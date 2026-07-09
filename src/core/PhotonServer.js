const dgram = require('dgram');
const os = require('os');
const EventEmitter = require('events');
const PhotonPeer = require('./PhotonPeer');
const PhotonRoom = require('./PhotonRoom');
const OperationHandler = require('../handlers/OperationHandler');
const enet = require('../protocol/enet');
const logger = require('../utils/logger');
const {
    ENET_COMMANDS,
    DEFAULT_SERVER_CONFIG
} = require('../protocol/constants');

/**
 * Photon Server — reliable-UDP (ENet) implementation of the Photon
 * LoadBalancing protocol, matching what PUN / Realtime clients speak
 * on UDP port 5055.
 */
class PhotonServer extends EventEmitter {
    /**
     * @param {Object} options - Server configuration
     * @param {number} [options.port=5055] - UDP port
     * @param {string} [options.host='0.0.0.0'] - Bind address
     * @param {string} [options.publicAddress] - ip[:port] advertised to clients
     *        as the game server address (defaults to the first external IPv4)
     * @param {number} [options.maxConnections=1000]
     * @param {number} [options.pingInterval=30000]
     * @param {number} [options.connectionTimeout=60000]
     * @param {number} [options.cleanupInterval=60000]
     * @param {number} [options.emptyRoomTtl=300000]
     */
    constructor(options = {}) {
        super();

        this._config = this._validateAndMergeConfig(options);
        this._state = this._initializeServerState();
        this._intervals = new Map();
        this._shutdownInProgress = false;

        this._operationHandler = new OperationHandler(this);

        logger.info('PhotonServer instance created', {
            port: this._config.port,
            host: this._config.host,
            transport: 'udp/enet'
        });
    }

    _validateAndMergeConfig(options) {
        const config = { ...DEFAULT_SERVER_CONFIG, ...options };

        if (config.port < 1 || config.port > 65535) {
            throw new Error(`Invalid port: ${config.port}. Must be between 1-65535`);
        }
        if (config.maxConnections < 1) {
            throw new Error(`Invalid maxConnections: ${config.maxConnections}. Must be positive`);
        }
        if (config.pingInterval < 1000) {
            throw new Error(`Invalid pingInterval: ${config.pingInterval}. Must be at least 1000ms`);
        }

        return config;
    }

    _initializeServerState() {
        return {
            socket: null,
            peers: new Map(),      // peerId -> peer
            sessions: new Map(),   // "address:port" -> peer
            rooms: new Map(),
            nextPeerId: 1,
            isRunning: false,
            startTime: null,
            stats: {
                totalConnections: 0,
                totalDisconnections: 0,
                totalRoomsCreated: 0,
                totalMessages: 0,
                totalErrors: 0,
                peakConnections: 0,
                peakRooms: 0,
                bytesReceived: 0,
                bytesSent: 0
            }
        };
    }

    // ------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------

    async start() {
        if (this._state.isRunning) {
            throw new Error('Server is already running');
        }
        if (this._shutdownInProgress) {
            throw new Error('Server shutdown is in progress');
        }

        try {
            await this._startUdpServer();
            this._startBackgroundTasks();

            logger.info('PhotonServer started', {
                host: this._config.host,
                port: this._config.port,
                publicAddress: this.getPublicAddress(),
                maxConnections: this._config.maxConnections
            });

            this.emit('started', this.getServerInfo());
        } catch (error) {
            logger.error('Failed to start PhotonServer', { error: error.message });
            await this._cleanup();
            throw error;
        }
    }

    _startUdpServer() {
        return new Promise((resolve, reject) => {
            const socket = dgram.createSocket('udp4');
            this._state.socket = socket;

            socket.on('error', (error) => {
                logger.error('UDP socket error', { error: error.message });
                this._state.stats.totalErrors++;
                this.emit('serverError', error);
                if (!this._state.isRunning) reject(error);
            });

            socket.on('message', (msg, rinfo) => {
                try {
                    this._handleDatagram(msg, rinfo);
                } catch (error) {
                    this._state.stats.totalErrors++;
                    logger.error('Error handling datagram', {
                        remote: `${rinfo.address}:${rinfo.port}`,
                        error: error.message
                    });
                }
            });

            socket.on('close', () => {
                logger.info('UDP socket closed');
                this.emit('serverClosed');
            });

            socket.bind(this._config.port, this._config.host, () => {
                this._state.isRunning = true;
                this._state.startTime = Date.now();
                resolve();
            });
        });
    }

    /** Address advertised to clients as the game server (ip:port). */
    getPublicAddress() {
        let addr = this._config.publicAddress || process.env.PHOTON_PUBLIC_ADDRESS;

        if (!addr) {
            if (this._config.host && this._config.host !== '0.0.0.0') {
                addr = this._config.host;
            } else {
                // First non-internal IPv4
                for (const ifaces of Object.values(os.networkInterfaces())) {
                    for (const iface of ifaces || []) {
                        if (iface.family === 'IPv4' && !iface.internal) {
                            addr = iface.address;
                            break;
                        }
                    }
                    if (addr) break;
                }
                addr = addr || '127.0.0.1';
            }
        }

        return addr.includes(':') ? addr : `${addr}:${this._config.port}`;
    }

    // ------------------------------------------------------------------
    // Datagram handling
    // ------------------------------------------------------------------

    _handleDatagram(msg, rinfo) {
        this._state.stats.totalMessages++;
        this._state.stats.bytesReceived += msg.length;

        const packet = enet.parsePacket(msg);
        if (!packet) {
            logger.warn('Malformed ENet packet dropped', {
                remote: `${rinfo.address}:${rinfo.port}`,
                length: msg.length
            });
            return;
        }

        const sessionKey = `${rinfo.address}:${rinfo.port}`;
        let peer = this._state.sessions.get(sessionKey);

        const connectCommand = packet.commands.find(c => c.type === ENET_COMMANDS.CONNECT);

        // New session (or client restarted with a new challenge)
        if (connectCommand && (!peer || peer.challenge !== packet.challenge)) {
            if (peer) {
                this._handlePeerDisconnection(peer, 'Superseded by new connection');
            }
            peer = this._acceptConnection(rinfo, packet, connectCommand);
            if (!peer) return;

            // Process any other commands that came in the same packet
            const rest = packet.commands.filter(c => c !== connectCommand);
            if (rest.length > 0) {
                peer.handlePacket({ ...packet, commands: rest });
            }
            return;
        }

        if (!peer) {
            // Unknown session without a CONNECT — client from a previous
            // server run; nothing to do but ignore it.
            logger.debug('Datagram from unknown session dropped', { remote: sessionKey });
            return;
        }

        if (packet.challenge !== peer.challenge) {
            logger.debug('Challenge mismatch, dropping packet', { remote: sessionKey });
            return;
        }

        peer.updateStats('bytesReceived', msg.length);
        peer.handlePacket(packet);
    }

    _acceptConnection(rinfo, packet, connectCommand) {
        if (!this._canAcceptConnection()) {
            logger.warn('Connection rejected: server at capacity', {
                currentConnections: this._state.peers.size,
                maxConnections: this._config.maxConnections,
                remote: `${rinfo.address}:${rinfo.port}`
            });
            return null;
        }

        const connectInfo = enet.parseConnectPayload(connectCommand.payload);
        const peerId = this._state.nextPeerId++;

        const peer = new PhotonPeer(this, peerId, rinfo, {
            challenge: packet.challenge,
            mtu: connectInfo.mtu,
            channelCount: connectInfo.channelCount,
            payload: connectCommand.payload
        }, {
            timeout: this._config.connectionTimeout,
            pingInterval: this._config.pingInterval
        });

        this._state.sessions.set(peer.sessionKey, peer);
        this._state.peers.set(peerId, peer);
        this._state.stats.totalConnections++;
        this._state.stats.peakConnections = Math.max(
            this._state.stats.peakConnections,
            this._state.peers.size
        );

        peer.on('connected', (p) => this.emit('peerConnected', p));
        peer.on('operation', (message, p) => {
            this._operationHandler.handleOperation(p, message).catch((error) => {
                logger.error('Unhandled operation error', {
                    peerId: p.peerId,
                    error: error.message
                });
            });
        });
        peer.on('disconnected', (p, reason) => this._handlePeerDisconnection(p, reason));

        peer.beginHandshake(connectCommand, packet.sentTime);

        logger.info('New UDP connection accepted', {
            peerId,
            remote: peer.sessionKey,
            mtu: connectInfo.mtu,
            channels: connectInfo.channelCount,
            totalConnections: this._state.peers.size
        });

        return peer;
    }

    _canAcceptConnection() {
        return this._state.isRunning &&
            this._state.peers.size < this._config.maxConnections &&
            !this._shutdownInProgress;
    }

    /** Raw datagram send used by peers. */
    _sendDatagram(buffer, address, port) {
        if (!this._state.socket) return;
        this._state.stats.bytesSent += buffer.length;
        this._state.socket.send(buffer, port, address, (error) => {
            if (error) {
                this._state.stats.totalErrors++;
                logger.error('UDP send error', {
                    remote: `${address}:${port}`,
                    error: error.message
                });
            }
        });
    }

    // ------------------------------------------------------------------
    // Peer disconnection
    // ------------------------------------------------------------------

    _handlePeerDisconnection(peer, reason = 'Unknown') {
        if (!this._state.peers.has(peer.peerId)) {
            return; // already handled
        }

        try {
            if (peer.room) {
                const roomName = peer.room.name;
                peer.room.removePeer(peer);
                const room = this._state.rooms.get(roomName);
                if (room && room.isEmpty()) {
                    this._scheduleRoomCleanup(roomName);
                }
            }

            this._state.sessions.delete(peer.sessionKey);
            this._state.peers.delete(peer.peerId);
            this._state.stats.totalDisconnections++;

            logger.info('Peer disconnected', {
                peerId: peer.peerId,
                reason,
                totalConnections: this._state.peers.size
            });

            this.emit('peerDisconnected', peer, reason);
            peer.cleanup();
        } catch (error) {
            logger.error('Error during peer disconnection', {
                peerId: peer.peerId,
                error: error.message
            });
        }
    }

    _scheduleRoomCleanup(roomName) {
        process.nextTick(() => {
            const room = this._state.rooms.get(roomName);
            if (room && room.isEmpty()) {
                this.removeRoom(roomName);
            }
        });
    }

    // ------------------------------------------------------------------
    // Background tasks
    // ------------------------------------------------------------------

    _startBackgroundTasks() {
        // ENet service: retransmissions
        this._intervals.set('service', setInterval(() => {
            this._performServiceCycle();
        }, 100));

        this._intervals.set('ping', setInterval(() => {
            this._performPingCycle();
        }, Math.max(1000, Math.floor(this._config.pingInterval / 3))));

        this._intervals.set('cleanup', setInterval(() => {
            this._performCleanupCycle();
        }, this._config.cleanupInterval));

        logger.debug('Background tasks started');
    }

    _stopBackgroundTasks() {
        for (const [name, intervalId] of this._intervals) {
            clearInterval(intervalId);
            logger.debug(`Stopped background task: ${name}`);
        }
        this._intervals.clear();
    }

    _performServiceCycle() {
        const now = Date.now();
        for (const peer of this._state.peers.values()) {
            try {
                if (!peer.service(now)) {
                    this._handlePeerDisconnection(peer, 'Retransmission limit exceeded');
                }
            } catch (error) {
                logger.error('Error in service cycle', {
                    peerId: peer.peerId,
                    error: error.message
                });
            }
        }
    }

    _performPingCycle() {
        const now = Date.now();
        const timedOut = [];

        for (const peer of this._state.peers.values()) {
            try {
                if (peer.isConnected() && peer.shouldSendPing(now)) {
                    peer.sendPing();
                }
                if (peer.isTimedOut(now)) {
                    timedOut.push(peer);
                }
            } catch (error) {
                logger.error('Error in ping cycle', {
                    peerId: peer.peerId,
                    error: error.message
                });
            }
        }

        for (const peer of timedOut) {
            logger.info('Disconnecting inactive peer', { peerId: peer.peerId });
            this._handlePeerDisconnection(peer, 'Inactivity timeout');
        }
    }

    _performCleanupCycle() {
        const now = Date.now();
        const emptyRooms = [];

        for (const [name, room] of this._state.rooms) {
            if (room.isEmpty() && room.shouldCleanup(now)) {
                emptyRooms.push(name);
            }
        }

        for (const roomName of emptyRooms) {
            this.removeRoom(roomName);
        }

        if (emptyRooms.length > 0) {
            logger.info('Cleaned up empty rooms', { count: emptyRooms.length });
        }
    }

    // ------------------------------------------------------------------
    // Shutdown
    // ------------------------------------------------------------------

    async stop(timeout = 10000) {
        if (!this._state.isRunning) return;
        if (this._shutdownInProgress) {
            logger.warn('Shutdown already in progress');
            return;
        }

        this._shutdownInProgress = true;
        logger.info('Beginning server shutdown', {
            connectedPeers: this._state.peers.size,
            activeRooms: this._state.rooms.size
        });

        try {
            this._stopBackgroundTasks();

            for (const peer of [...this._state.peers.values()]) {
                try {
                    await peer.disconnect('Server shutting down');
                } catch (e) { /* best effort */ }
            }

            await this._cleanup();

            await new Promise((resolve) => {
                if (!this._state.socket) return resolve();
                this._state.socket.close(() => resolve());
            });

            this._state.socket = null;
            this._state.isRunning = false;

            logger.info('Server shutdown completed');
            this.emit('stopped');
        } catch (error) {
            logger.error('Error during server shutdown', { error: error.message });
            throw error;
        } finally {
            this._shutdownInProgress = false;
        }
    }

    async _cleanup() {
        for (const room of this._state.rooms.values()) {
            try {
                room.destroy();
            } catch (error) {
                logger.error('Error destroying room', { error: error.message });
            }
        }
        this._state.rooms.clear();
        this._state.peers.clear();
        this._state.sessions.clear();
        logger.debug('Server cleanup completed');
    }

    // ------------------------------------------------------------------
    // Public API — rooms
    // ------------------------------------------------------------------

    createRoom(name, options = {}) {
        if (!name || typeof name !== 'string') {
            throw new Error('Room name must be a non-empty string');
        }
        if (this._state.rooms.has(name)) {
            throw new Error(`Room '${name}' already exists`);
        }

        const room = new PhotonRoom(name, {
            ...options,
            emptyRoomTtl: options.emptyRoomTtl || this._config.emptyRoomTtl
        });

        this._state.rooms.set(name, room);
        this._state.stats.totalRoomsCreated++;
        this._state.stats.peakRooms = Math.max(
            this._state.stats.peakRooms,
            this._state.rooms.size
        );

        logger.info('Room created', { roomName: name });
        this.emit('roomCreated', room);
        return room;
    }

    removeRoom(name) {
        const room = this._state.rooms.get(name);
        if (!room) return false;

        if (!room.isEmpty()) {
            logger.warn('Attempting to remove non-empty room', {
                roomName: name,
                peerCount: room.getPeerCount()
            });
            return false;
        }

        try {
            room.destroy();
            this._state.rooms.delete(name);
            logger.info('Room removed', { roomName: name });
            this.emit('roomRemoved', room);
            return true;
        } catch (error) {
            logger.error('Error removing room', { roomName: name, error: error.message });
            return false;
        }
    }

    getRoom(name) { return this._state.rooms.get(name); }
    getRooms() { return Array.from(this._state.rooms.values()); }
    getVisibleRooms() { return this.getRooms().filter(room => room.isVisible); }

    // ------------------------------------------------------------------
    // Public API — peers
    // ------------------------------------------------------------------

    getPeer(peerId) { return this._state.peers.get(peerId); }
    getPeers() { return Array.from(this._state.peers.values()); }
    getConnectedPeers() { return this.getPeers().filter(peer => peer.isConnected()); }

    disconnectPeer(peerId, reason = 'Disconnected by server') {
        const peer = this._state.peers.get(peerId);
        if (!peer) return false;
        peer.disconnect(reason);
        return true;
    }

    broadcast(eventCode, data = {}, excludePeerId = null) {
        if (typeof eventCode !== 'number') {
            throw new Error('Event code must be a number');
        }

        let sentCount = 0;
        for (const peer of this._state.peers.values()) {
            if (!peer.isConnected() || peer.peerId === excludePeerId) continue;
            try {
                peer.sendEvent(eventCode, data);
                sentCount++;
            } catch (error) {
                logger.warn('Broadcast error', { peerId: peer.peerId, error: error.message });
            }
        }

        logger.debug('Broadcast sent', { eventCode, sentCount });
    }

    broadcastToRoom(roomName, eventCode, data = {}, excludePeerId = null) {
        const room = this.getRoom(roomName);
        if (!room) {
            logger.warn('Attempted broadcast to non-existent room', { roomName });
            return false;
        }
        room.broadcastEvent(eventCode, data, excludePeerId);
        return true;
    }

    // ------------------------------------------------------------------
    // Stats / monitoring (same shape as before)
    // ------------------------------------------------------------------

    getStats() {
        return {
            ...this._state.stats,
            currentConnections: this._state.peers.size,
            currentRooms: this._state.rooms.size,
            uptime: this._state.startTime ? Date.now() - this._state.startTime : 0,
            isRunning: this._state.isRunning,
            config: {
                port: this._config.port,
                host: this._config.host,
                maxConnections: this._config.maxConnections,
                pingInterval: this._config.pingInterval,
                connectionTimeout: this._config.connectionTimeout
            },
            memory: process.memoryUsage(),
            timestamp: Date.now()
        };
    }

    getServerInfo() {
        return {
            version: (() => {
                try { return require('../../package.json').version; }
                catch (error) { return '1.0.0'; }
            })(),
            host: this._config.host,
            port: this._config.port,
            protocol: 'udp/enet',
            publicAddress: this.getPublicAddress(),
            isRunning: this._state.isRunning,
            startTime: this._state.startTime,
            uptime: this._state.startTime ? Date.now() - this._state.startTime : 0
        };
    }

    getRoomStats() {
        return this.getRooms().map(room => ({ name: room.name, ...room.getStats() }));
    }

    getPeerStats() {
        return this.getPeers().map(peer => peer.getStats());
    }

    getHealthStatus() {
        const stats = this.getStats();
        const health = {
            status: 'healthy',
            uptime: stats.uptime,
            connections: `${stats.currentConnections}/${this._config.maxConnections}`,
            rooms: stats.currentRooms,
            errors: stats.totalErrors,
            timestamp: Date.now()
        };

        if (!this._state.isRunning) {
            health.status = 'down';
        } else if (stats.totalErrors > 100 || stats.currentConnections >= this._config.maxConnections * 0.95) {
            health.status = 'degraded';
        } else if (stats.totalErrors > 10 || stats.currentConnections >= this._config.maxConnections * 0.8) {
            health.status = 'warning';
        }

        return health;
    }

    async performMaintenance() {
        this._performCleanupCycle();
        this._performPingCycle();
        if (global.gc) global.gc();
    }

    exportState() {
        return {
            stats: this.getStats(),
            rooms: this.getRoomStats(),
            peers: this.getPeerStats(),
            config: this._config
        };
    }

    toJSON() {
        return {
            serverInfo: this.getServerInfo(),
            stats: this.getStats(),
            health: this.getHealthStatus(),
            rooms: this.getRooms().map(room => room.toJSON()),
            peers: this.getPeers().map(peer => peer.toJSON())
        };
    }

    isHealthy() {
        return this._state.isRunning &&
            !this._shutdownInProgress &&
            this._state.peers.size < this._config.maxConnections;
    }

    getCapacity() {
        const connections = this._state.peers.size;
        const maxConnections = this._config.maxConnections;
        return {
            connections: {
                current: connections,
                max: maxConnections,
                utilization: connections / maxConnections,
                available: maxConnections - connections
            },
            rooms: { current: this._state.rooms.size },
            memory: process.memoryUsage()
        };
    }

    updateConfig(config) {
        const allowedUpdates = ['pingInterval', 'connectionTimeout', 'cleanupInterval'];
        let updated = false;

        for (const [key, value] of Object.entries(config)) {
            if (allowedUpdates.includes(key) && typeof value === 'number' && value > 0) {
                this._config[key] = value;
                updated = true;
            }
        }

        if (updated) {
            this._stopBackgroundTasks();
            this._startBackgroundTasks();
        }

        return updated;
    }

    getMetrics() {
        const stats = this.getStats();
        const capacity = this.getCapacity();
        return {
            'photon.connections.current': stats.currentConnections,
            'photon.connections.total': stats.totalConnections,
            'photon.connections.peak': stats.peakConnections,
            'photon.connections.utilization': capacity.connections.utilization,
            'photon.rooms.current': stats.currentRooms,
            'photon.rooms.total': stats.totalRoomsCreated,
            'photon.rooms.peak': stats.peakRooms,
            'photon.messages.total': stats.totalMessages,
            'photon.bytes.received': stats.bytesReceived,
            'photon.bytes.sent': stats.bytesSent,
            'photon.errors.total': stats.totalErrors,
            'photon.uptime': stats.uptime,
            'photon.memory.rss': stats.memory.rss,
            'photon.memory.heapUsed': stats.memory.heapUsed,
            'photon.memory.heapTotal': stats.memory.heapTotal
        };
    }

    on(event, listener) {
        const wrappedListener = (...args) => {
            try {
                listener(...args);
            } catch (error) {
                logger.error('Event listener error', { event, error: error.message });
                this._state.stats.totalErrors++;
            }
        };
        super.on(event, wrappedListener);
        return this;
    }
}

module.exports = PhotonServer;
