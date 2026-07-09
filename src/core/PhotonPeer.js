const EventEmitter = require('events');
const logger = require('../utils/logger');
const enet = require('../protocol/enet');
const gp = require('../protocol/gpbinary');
const {
    ENET_COMMANDS,
    MESSAGE_TYPES,
    INTERNAL_OPERATIONS,
    PHOTON_PEER_STATE,
    DEFAULT_PEER_CONFIG
} = require('../protocol/constants');

const CONTROL_CHANNEL = 0xFF;

/**
 * A connected Photon client: one ENet (reliable UDP) session.
 *
 * Owns the per-connection protocol state — reliable sequence numbers,
 * pending ACKs, retransmission queue, fragment reassembly — and exposes the
 * high-level API (sendOperationResponse / sendEvent) used by the operation
 * handler, rooms and plugins.
 */
class PhotonPeer extends EventEmitter {
    /**
     * @param {PhotonServer} server - Owning server (provides the UDP socket)
     * @param {number} peerId - Server-assigned peer id
     * @param {Object} rinfo - {address, port} of the client
     * @param {Object} connect - Parsed CONNECT info {challenge, mtu, channelCount, payload}
     * @param {Object} [options={}] - Peer configuration
     */
    constructor(server, peerId, rinfo, connect, options = {}) {
        super();

        this._server = server;
        this._peerId = peerId;
        this._address = rinfo.address;
        this._port = rinfo.port;
        this._config = { ...DEFAULT_PEER_CONFIG, ...options };

        this._enet = {
            challenge: connect.challenge,
            mtu: Math.max(576, connect.mtu || 1200),
            channelCount: connect.channelCount || 2,
            connectPayload: connect.payload,
            channels: new Map(),          // channelId -> {outSeq, inSeq, pending}
            unreliableOutSeq: 0,
            unreliableInSeq: 0,
            sentReliable: new Map(),      // "ch:seq" -> {buffer, retries, nextResend}
            outgoing: [],                 // command buffers awaiting flush
            fragments: new Map()          // startSeq -> {chunks, received, totalLength, count}
        };

        this._state = {
            status: PHOTON_PEER_STATE.CONNECTING,
            isActive: true,
            connectedAt: Date.now(),
            lastActivity: Date.now(),
            lastPingTime: Date.now(),
            joinTime: null,
            isMasterClient: false,
            customProperties: {},
            stats: {
                messagesSent: 0, messagesReceived: 0,
                bytesReceived: 0, bytesSent: 0,
                reliableCommandsSent: 0, unreliableCommandsSent: 0,
                eventsSent: 0, eventsReceived: 0,
                operationsSent: 0, operationsReceived: 0,
                pingsSent: 0, pongsReceived: 0,
                errors: 0, reconnects: 0
            }
        };

        this._auth = {
            isAuthenticated: false,
            playerName: '',
            userId: '',
            authData: null,
            authenticatedAt: null,
            hasValidPassword: true,
            secret: null,
            onGameServer: false
        };

        this._room = null;
        this.actorNr = 0;
        this.actorProperties = new Map();
        this.clientInfo = null; // filled from the Init message

        logger.debug('PhotonPeer created', {
            peerId,
            remote: `${this._address}:${this._port}`,
            challenge: this._enet.challenge,
            mtu: this._enet.mtu
        });
    }

    // ------------------------------------------------------------------
    // Properties
    // ------------------------------------------------------------------

    get peerId() { return this._peerId; }
    get address() { return this._address; }
    get port() { return this._port; }
    get challenge() { return this._enet.challenge; }
    get sessionKey() { return `${this._address}:${this._port}`; }
    get playerName() { return this._auth.playerName; }
    get userId() { return this._auth.userId; }
    get secret() { return this._auth.secret; }
    get onGameServer() { return this._auth.onGameServer; }
    get customProperties() { return { ...this._state.customProperties }; }
    get state() { return this._state.status; }
    get isMasterClient() { return this._state.isMasterClient; }
    get room() { return this._room; }
    get joinTime() { return this._state.joinTime; }
    get connectionTime() { return Date.now() - this._state.connectedAt; }
    get timeSinceLastActivity() { return Date.now() - this._state.lastActivity; }
    get hasValidPassword() { return this._auth.hasValidPassword; }

    isConnected() {
        return this._state.isActive &&
            this._state.status !== PHOTON_PEER_STATE.DISCONNECTED;
    }

    isAuthenticated() { return this._auth.isAuthenticated; }
    updateActivity() { this._state.lastActivity = Date.now(); }
    updateLastPingTime() { this._state.lastPingTime = Date.now(); }

    shouldSendPing(now = Date.now()) {
        return (now - this._state.lastPingTime) > this._config.pingInterval;
    }

    isTimedOut(now = Date.now()) {
        return (now - this._state.lastActivity) > this._config.timeout;
    }

    setState(newState) {
        if (this._state.status !== newState) {
            const old = this._state.status;
            this._state.status = newState;
            this.emit('stateChanged', newState, old, this);
        }
    }

    updateStats(metric, value = 1) {
        if (Object.prototype.hasOwnProperty.call(this._state.stats, metric)) {
            this._state.stats[metric] += value;
        }
    }

    // ------------------------------------------------------------------
    // ENet receive path
    // ------------------------------------------------------------------

    _channel(id) {
        let ch = this._enet.channels.get(id);
        if (!ch) {
            ch = { outSeq: 0, inSeq: 0, pending: new Map() };
            this._enet.channels.set(id, ch);
        }
        return ch;
    }

    /**
     * Begin the ENet handshake: ACK the CONNECT and send VERIFY_CONNECT.
     * @param {Object} connectCommand - The parsed CONNECT command
     * @param {number} packetSentTime - sentTime of the packet that carried it
     */
    beginHandshake(connectCommand, packetSentTime) {
        const control = this._channel(CONTROL_CHANNEL);
        control.inSeq = Math.max(control.inSeq, connectCommand.reliableSequenceNumber);

        this._queueCommand(enet.buildAck(
            CONTROL_CHANNEL, connectCommand.reliableSequenceNumber, packetSentTime
        ));

        const seq = ++control.outSeq;
        const verify = enet.buildVerifyConnect(seq, this._peerId, this._enet.connectPayload);
        this._queueReliable(CONTROL_CHANNEL, seq, verify);
        this._flush();

        logger.info('ENet handshake started', {
            peerId: this._peerId,
            remote: this.sessionKey,
            challenge: this._enet.challenge
        });
    }

    /**
     * Process an incoming, already-parsed packet for this session.
     * @param {Object} packet - Result of enet.parsePacket
     */
    handlePacket(packet) {
        this.updateActivity();
        this.updateStats('messagesReceived', 1);

        for (const command of packet.commands) {
            try {
                this._handleCommand(command, packet);
            } catch (error) {
                this.updateStats('errors', 1);
                logger.error('Error handling ENet command', {
                    peerId: this._peerId,
                    commandType: command.type,
                    error: error.message
                });
            }
        }

        this._flush();
    }

    _handleCommand(command, packet) {
        switch (command.type) {
            case ENET_COMMANDS.ACKNOWLEDGE:
                this._handleAck(command);
                break;

            case ENET_COMMANDS.CONNECT:
                // Retransmitted CONNECT: our ACK/VERIFY was lost, resend both
                this._queueCommand(enet.buildAck(
                    command.channelId, command.reliableSequenceNumber, packet.sentTime
                ));
                for (const entry of this._enet.sentReliable.values()) {
                    if (entry.buffer.readUInt8(0) === ENET_COMMANDS.VERIFY_CONNECT) {
                        this._queueCommand(entry.buffer);
                    }
                }
                break;

            case ENET_COMMANDS.DISCONNECT:
                logger.info('Client requested disconnect', { peerId: this._peerId });
                this._state.isActive = false;
                this.setState(PHOTON_PEER_STATE.DISCONNECTED);
                this.emit('disconnected', this, 'Client requested disconnect');
                break;

            case ENET_COMMANDS.PING:
                this._ackAndOrder(command, packet, () => { /* keep-alive only */ });
                break;

            case ENET_COMMANDS.FETCH_SERVER_TIMESTAMP: {
                if (command.flags & enet.FLAG_RELIABLE) {
                    this._queueCommand(enet.buildAck(
                        command.channelId, command.reliableSequenceNumber, packet.sentTime
                    ));
                }
                const control = this._channel(CONTROL_CHANNEL);
                const seq = ++control.outSeq;
                const stamp = enet.buildServerTimestamp(seq, Date.now() & 0x7FFFFFFF);
                this._queueReliable(CONTROL_CHANNEL, seq, stamp);
                break;
            }

            case ENET_COMMANDS.SEND_RELIABLE:
                this._ackAndOrder(command, packet, (cmd) => this._handleMessage(cmd.payload));
                break;

            case ENET_COMMANDS.SEND_FRAGMENT:
                this._ackAndOrder(command, packet, (cmd) => this._handleFragment(cmd));
                break;

            case ENET_COMMANDS.SEND_UNRELIABLE:
                if (command.unreliableSequenceNumber > this._enet.unreliableInSeq) {
                    this._enet.unreliableInSeq = command.unreliableSequenceNumber;
                    this._handleMessage(command.payload);
                }
                break;

            default:
                // ACK unrecognized reliable commands so the client does not
                // retransmit them indefinitely.
                if (command.flags & enet.FLAG_RELIABLE) {
                    this._queueCommand(enet.buildAck(
                        command.channelId, command.reliableSequenceNumber, packet.sentTime
                    ));
                }
                logger.warn('Unknown ENet command type', {
                    peerId: this._peerId,
                    commandType: command.type
                });
        }
    }

    _handleAck(command) {
        const key = `${command.channelId}:${command.receivedReliableSequenceNumber}`;
        // ACK channel matches the channel of the acked command
        if (this._enet.sentReliable.delete(key)) {
            this.updateStats('pongsReceived', 0); // no-op placeholder for RTT tracking
        }
    }

    /**
     * ACK a reliable command and dispatch it (and any buffered successors)
     * in sequence order, dropping duplicates.
     */
    _ackAndOrder(command, packet, dispatch) {
        if (command.flags & enet.FLAG_RELIABLE) {
            this._queueCommand(enet.buildAck(
                command.channelId, command.reliableSequenceNumber, packet.sentTime
            ));
        }

        const ch = this._channel(command.channelId);
        const seq = command.reliableSequenceNumber;

        if (seq <= ch.inSeq || ch.pending.has(seq)) {
            return; // duplicate
        }

        ch.pending.set(seq, { command, dispatch });

        while (ch.pending.has(ch.inSeq + 1)) {
            const next = ch.pending.get(ch.inSeq + 1);
            ch.pending.delete(ch.inSeq + 1);
            ch.inSeq++;
            next.dispatch(next.command);
        }
    }

    _handleFragment(command) {
        let frag = this._enet.fragments.get(command.startSequenceNumber);
        if (!frag) {
            frag = {
                chunks: new Array(command.fragmentCount),
                received: 0,
                count: command.fragmentCount,
                totalLength: command.totalLength
            };
            this._enet.fragments.set(command.startSequenceNumber, frag);
        }

        if (!frag.chunks[command.fragmentNumber]) {
            frag.chunks[command.fragmentNumber] = {
                offset: command.fragmentOffset,
                data: command.payload
            };
            frag.received++;
        }

        if (frag.received === frag.count) {
            this._enet.fragments.delete(command.startSequenceNumber);
            const full = Buffer.alloc(frag.totalLength);
            for (const chunk of frag.chunks) {
                chunk.data.copy(full, chunk.offset);
            }
            this._handleMessage(full);
        }
    }

    // ------------------------------------------------------------------
    // Message layer
    // ------------------------------------------------------------------

    _handleMessage(payload) {
        if (payload.length === 0) return;

        let message;
        try {
            message = gp.parseMessage(payload);
        } catch (error) {
            this.updateStats('errors', 1);
            logger.error('Failed to parse Photon message', {
                peerId: this._peerId,
                error: error.message,
                head: payload.slice(0, 16).toString('hex')
            });
            return;
        }

        if (message.encrypted) {
            logger.error('Received encrypted message but encryption is not implemented', {
                peerId: this._peerId,
                messageType: message.messageType
            });
            return;
        }

        switch (message.messageType) {
            case MESSAGE_TYPES.INIT:
                this.clientInfo = {
                    protocolVersion: message.protocolVersion,
                    clientSdkId: message.clientSdkId,
                    clientVersion: message.clientVersion,
                    applicationId: message.applicationId
                };
                logger.info('Client init received', { peerId: this._peerId, ...this.clientInfo });
                this.sendMessage(gp.buildInitResponse());
                this.setState(PHOTON_PEER_STATE.CONNECTED);
                this.emit('connected', this);
                break;

            case MESSAGE_TYPES.INTERNAL_OPERATION_REQUEST:
                this._handleInternalOperation(message);
                break;

            case MESSAGE_TYPES.OPERATION_REQUEST:
                this.updateStats('operationsReceived', 1);
                this.emit('operation', message, this);
                break;

            default:
                logger.warn('Unhandled message type', {
                    peerId: this._peerId,
                    messageType: message.messageType
                });
        }
    }

    _handleInternalOperation(message) {
        switch (message.operationCode) {
            case INTERNAL_OPERATIONS.PING: {
                const clientTime = message.parameters[1] | 0;
                const serverTime = Date.now() & 0x7FFFFFFF;
                this.sendMessage(gp.buildOperationResponse(
                    INTERNAL_OPERATIONS.PING, 0,
                    { 1: gp.T.int(clientTime), 2: gp.T.int(serverTime) },
                    null, true
                ));
                this.updateStats('pongsReceived', 1);
                break;
            }

            case INTERNAL_OPERATIONS.INIT_ENCRYPTION:
                logger.error('Client requested encryption (InitEncryption) — not implemented. ' +
                    'The client will likely disconnect.', { peerId: this._peerId });
                this.sendMessage(gp.buildOperationResponse(
                    INTERNAL_OPERATIONS.INIT_ENCRYPTION, -1, {},
                    'Encryption not supported by this server', true
                ));
                break;

            default:
                logger.warn('Unknown internal operation', {
                    peerId: this._peerId,
                    operationCode: message.operationCode
                });
        }
    }

    // ------------------------------------------------------------------
    // ENet send path
    // ------------------------------------------------------------------

    _queueCommand(buffer) {
        this._enet.outgoing.push(buffer);
    }

    _queueReliable(channelId, seq, buffer) {
        this._enet.sentReliable.set(`${channelId}:${seq}`, {
            buffer,
            retries: 0,
            nextResend: Date.now() + this._config.retransmitInterval
        });
        this._enet.outgoing.push(buffer);
        this.updateStats('reliableCommandsSent', 1);
    }

    /**
     * Send a message payload to the client, fragmenting when needed.
     * @param {Buffer} payload - Message buffer (0xF3 ...)
     * @param {Object} [opts] - {channelId=0, reliable=true}
     * @returns {boolean} queued successfully
     */
    sendMessage(payload, opts = {}) {
        if (!this.isConnected()) return false;

        const channelId = opts.channelId ?? 0;
        const reliable = opts.reliable !== false;
        const ch = this._channel(channelId);
        const mtu = this._enet.mtu;
        const maxSingle = mtu - enet.PACKET_HEADER_SIZE - enet.COMMAND_HEADER_SIZE;

        if (!reliable && payload.length <= maxSingle - 4) {
            const seq = ++this._enet.unreliableOutSeq;
            this._queueCommand(enet.buildUnreliable(channelId, ch.outSeq, seq, payload));
            this.updateStats('unreliableCommandsSent', 1);
        } else if (payload.length <= maxSingle) {
            const seq = ++ch.outSeq;
            this._queueReliable(channelId, seq, enet.buildReliable(channelId, seq, payload));
        } else {
            const chunkSize = mtu - enet.PACKET_HEADER_SIZE - enet.FRAGMENT_HEADER_SIZE;
            const count = Math.ceil(payload.length / chunkSize);
            const startSeq = ch.outSeq + 1;
            for (let i = 0; i < count; i++) {
                const offset = i * chunkSize;
                const chunk = payload.slice(offset, offset + chunkSize);
                const seq = ++ch.outSeq;
                this._queueReliable(channelId, seq, enet.buildFragment(
                    channelId, seq, startSeq, count, i, payload.length, offset, chunk
                ));
            }
        }

        this._flush();
        return true;
    }

    /** Flush queued commands as one or more MTU-sized packets. */
    _flush() {
        const queue = this._enet.outgoing;
        if (queue.length === 0) return;
        this._enet.outgoing = [];

        const header = {
            peerId: this._peerId,
            sentTime: Date.now() & 0x7FFFFFFF,
            challenge: this._enet.challenge
        };

        let batch = [];
        let size = enet.PACKET_HEADER_SIZE;

        const send = () => {
            if (batch.length === 0) return;
            const packet = enet.buildPacket(header, batch);
            this._server._sendDatagram(packet, this._address, this._port);
            this.updateStats('messagesSent', 1);
            this.updateStats('bytesSent', packet.length);
            batch = [];
            size = enet.PACKET_HEADER_SIZE;
        };

        for (const cmd of queue) {
            if (batch.length >= 255 || size + cmd.length > this._enet.mtu) {
                send();
            }
            batch.push(cmd);
            size += cmd.length;
        }
        send();
    }

    /**
     * Periodic service: retransmit unacknowledged reliable commands.
     * @param {number} now - Current timestamp
     * @returns {boolean} false if the peer exceeded its retransmit budget
     */
    service(now = Date.now()) {
        for (const [key, entry] of this._enet.sentReliable) {
            if (now < entry.nextResend) continue;

            entry.retries++;
            if (entry.retries > this._config.maxRetransmits) {
                logger.warn('Reliable command retransmit limit reached', {
                    peerId: this._peerId,
                    command: key,
                    retries: entry.retries
                });
                return false;
            }

            entry.nextResend = now + Math.min(
                this._config.retransmitInterval * Math.pow(2, entry.retries), 3000
            );
            this._queueCommand(entry.buffer);
        }

        this._flush();
        return true;
    }

    // ------------------------------------------------------------------
    // High-level API (operation handler / rooms / plugins)
    // ------------------------------------------------------------------

    /**
     * Send an operation response.
     * @param {number} opCode
     * @param {number} [returnCode=0]
     * @param {Object|Map} [parameters={}] - byte-code keyed parameters
     * @param {string} [debugMessage] - optional debug string
     */
    sendOperationResponse(opCode, returnCode = 0, parameters = {}, debugMessage = null) {
        const ok = this.sendMessage(
            gp.buildOperationResponse(opCode, returnCode, parameters, debugMessage)
        );
        if (ok) this.updateStats('operationsSent', 1);
        return ok;
    }

    /**
     * Send an event. Parameters should be byte-code keyed; objects with
     * non-numeric keys (e.g. from plugins) are wrapped as custom event data.
     * @param {number} eventCode
     * @param {Object|Map} [parameters={}]
     */
    sendEvent(eventCode, parameters = {}) {
        let params = parameters;
        if (!(parameters instanceof Map)) {
            const keys = Object.keys(parameters);
            if (keys.some(k => !/^\d+$/.test(k))) {
                params = {
                    245: gp.T.hashtable(parameters), // Data
                    254: gp.T.int(0)                 // ActorNr 0 = server
                };
            }
        }

        const ok = this.sendMessage(gp.buildEvent(eventCode, params));
        if (ok) this.updateStats('eventsSent', 1);
        return ok;
    }

    /** Send an ENet-level ping (keep-alive). */
    sendPing() {
        if (!this.isConnected()) return false;
        const control = this._channel(CONTROL_CHANNEL);
        const seq = ++control.outSeq;
        this._queueReliable(CONTROL_CHANNEL, seq, enet.buildPing(seq));
        this._flush();
        this.updateLastPingTime();
        this.updateStats('pingsSent', 1);
        return true;
    }

    /** Send an ENet DISCONNECT command. */
    sendDisconnect() {
        const control = this._channel(CONTROL_CHANNEL);
        this._queueCommand(enet.buildDisconnect(++control.outSeq));
        this._flush();
        this.setState(PHOTON_PEER_STATE.DISCONNECTING);
        return true;
    }

    // ------------------------------------------------------------------
    // Authentication / room membership
    // ------------------------------------------------------------------

    /**
     * Mark peer as authenticated. Response sending is the operation
     * handler's responsibility.
     */
    authenticate(nickname, userId = null, authData = null, secret = null) {
        this._auth.playerName = nickname || '';
        this._auth.userId = userId || `user_${this._peerId}`;
        this._auth.authData = authData;
        this._auth.isAuthenticated = true;
        this._auth.authenticatedAt = Date.now();
        if (secret) {
            this._auth.secret = secret;
            this._auth.onGameServer = true;
        }
        this.emit('authenticated', this);
        return true;
    }

    setNickname(nickname) {
        if (typeof nickname === 'string') {
            this._auth.playerName = nickname;
        }
    }

    validatePassword() { return true; }

    setCustomProperties(properties, broadcast = false) {
        if (!properties || typeof properties !== 'object') return false;
        Object.assign(this._state.customProperties, properties);
        this.emit('propertiesChanged', properties, this);
        return true;
    }

    setRoom(room) {
        const oldRoom = this._room;
        this._room = room;
        if (room) {
            this._state.joinTime = Date.now();
        } else {
            this._state.joinTime = null;
            this._state.isMasterClient = false;
            this.actorNr = 0;
        }
        this.emit('roomChanged', room, oldRoom, this);
    }

    leaveRoom(reason = 'Left room') {
        if (!this._room) return false;
        const room = this._room;
        room.removePeer(this);
        this.emit('leftRoom', room, reason, this);
        return room.isEmpty();
    }

    setMasterClient(isMaster = true) {
        if (this._state.isMasterClient !== isMaster) {
            this._state.isMasterClient = isMaster;
            this.emit('masterClientChanged', isMaster, this);
        }
    }

    // ------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------

    async disconnect(reason = 'Disconnected') {
        if (!this._state.isActive) return;
        logger.info('Disconnecting peer', { peerId: this._peerId, reason });

        this._state.isActive = false;
        if (this._room) this.leaveRoom(reason);
        try { this.sendDisconnect(); } catch (e) { /* best effort */ }
        this.setState(PHOTON_PEER_STATE.DISCONNECTED);
        this.emit('disconnected', this, reason);
    }

    async forceDisconnect() {
        return this.disconnect('Force disconnect');
    }

    cleanup() {
        this._enet.sentReliable.clear();
        this._enet.outgoing = [];
        this._enet.fragments.clear();
        this._enet.channels.clear();
        this._room = null;
        this.removeAllListeners();
    }

    // ------------------------------------------------------------------
    // Stats / monitoring
    // ------------------------------------------------------------------

    getStats() {
        return {
            peerId: this._peerId,
            playerName: this._auth.playerName,
            userId: this._auth.userId,
            actorNr: this.actorNr,
            remote: this.sessionKey,
            state: this._state.status,
            isActive: this._state.isActive,
            isAuthenticated: this._auth.isAuthenticated,
            isMasterClient: this._state.isMasterClient,
            onGameServer: this._auth.onGameServer,
            room: this._room ? this._room.name : null,
            connectedAt: this._state.connectedAt,
            connectionTime: this.connectionTime,
            timeSinceLastActivity: this.timeSinceLastActivity,
            pendingReliable: this._enet.sentReliable.size,
            ...this._state.stats
        };
    }

    getHealthStatus() {
        return {
            status: this.isConnected() ? 'healthy' : 'disconnected',
            issues: [],
            pendingReliable: this._enet.sentReliable.size
        };
    }

    getConnectionSummary() {
        return this.getStats();
    }

    toJSON() {
        return {
            peerId: this._peerId,
            playerName: this._auth.playerName,
            userId: this._auth.userId,
            actorNr: this.actorNr,
            customProperties: this.customProperties,
            state: this._state.status,
            isActive: this._state.isActive,
            isAuthenticated: this._auth.isAuthenticated,
            isMasterClient: this._state.isMasterClient,
            room: this._room ? this._room.name : null,
            connectionTime: this.connectionTime,
            stats: this._state.stats
        };
    }

    toString() {
        const room = this._room ? `:${this._room.name}` : '';
        return `PhotonPeer[${this._peerId}:${this._auth.playerName}:${this._state.status}${room}]`;
    }
}

module.exports = PhotonPeer;
