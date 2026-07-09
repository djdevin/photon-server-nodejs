const { ENET_COMMANDS } = require('./constants');

/**
 * Photon ENet (reliable UDP) packet codec.
 *
 * Packet layout (big endian):
 *   uint16 peerId
 *   uint8  crcEnabled/flags
 *   uint8  commandCount
 *   int32  sentTime
 *   int32  challenge
 *   commands...
 *
 * Command layout:
 *   uint8  commandType
 *   uint8  channelId       (0xFF = control channel)
 *   uint8  commandFlags    (0x01 = reliable, needs ACK)
 *   uint8  reserved
 *   int32  size            (total command size incl. this 12-byte header)
 *   int32  reliableSequenceNumber
 *   payload...
 */

const PACKET_HEADER_SIZE = 12;
const COMMAND_HEADER_SIZE = 12;
const FRAGMENT_HEADER_SIZE = COMMAND_HEADER_SIZE + 20;
const UNRELIABLE_HEADER_SIZE = COMMAND_HEADER_SIZE + 4;

const FLAG_RELIABLE = 0x01;
const FLAG_UNSEQUENCED = 0x02;

/**
 * Parse a raw UDP datagram into a packet structure.
 * @param {Buffer} buf - Raw datagram
 * @returns {Object|null} Parsed packet or null if malformed
 */
function parsePacket(buf) {
    if (buf.length < PACKET_HEADER_SIZE) {
        return null;
    }

    const packet = {
        peerId: buf.readUInt16BE(0),
        crcEnabled: buf.readUInt8(2),
        commandCount: buf.readUInt8(3),
        sentTime: buf.readInt32BE(4),
        challenge: buf.readInt32BE(8),
        commands: []
    };

    let offset = PACKET_HEADER_SIZE;

    for (let i = 0; i < packet.commandCount; i++) {
        if (offset + COMMAND_HEADER_SIZE > buf.length) {
            return null;
        }

        const command = {
            type: buf.readUInt8(offset),
            channelId: buf.readUInt8(offset + 1),
            flags: buf.readUInt8(offset + 2),
            reserved: buf.readUInt8(offset + 3),
            size: buf.readInt32BE(offset + 4),
            reliableSequenceNumber: buf.readInt32BE(offset + 8)
        };

        if (command.size < COMMAND_HEADER_SIZE || offset + command.size > buf.length) {
            return null;
        }

        const body = buf.slice(offset + COMMAND_HEADER_SIZE, offset + command.size);

        switch (command.type) {
            case ENET_COMMANDS.ACKNOWLEDGE:
                if (body.length < 8) return null;
                command.receivedReliableSequenceNumber = body.readInt32BE(0);
                command.receivedSentTime = body.readInt32BE(4);
                break;

            case ENET_COMMANDS.SEND_UNRELIABLE:
                if (body.length < 4) return null;
                command.unreliableSequenceNumber = body.readInt32BE(0);
                command.payload = body.slice(4);
                break;

            case ENET_COMMANDS.SEND_FRAGMENT:
                if (body.length < 20) return null;
                command.startSequenceNumber = body.readInt32BE(0);
                command.fragmentCount = body.readInt32BE(4);
                command.fragmentNumber = body.readInt32BE(8);
                command.totalLength = body.readInt32BE(12);
                command.fragmentOffset = body.readInt32BE(16);
                command.payload = body.slice(20);
                break;

            default:
                command.payload = body;
        }

        packet.commands.push(command);
        offset += command.size;
    }

    return packet;
}

/**
 * Build a raw datagram from a packet header and pre-serialized commands.
 * @param {Object} header - {peerId, sentTime, challenge, crcEnabled}
 * @param {Buffer[]} commands - Serialized command buffers
 * @returns {Buffer} Datagram ready to send
 */
function buildPacket(header, commands) {
    const head = Buffer.allocUnsafe(PACKET_HEADER_SIZE);
    head.writeUInt16BE(header.peerId & 0xFFFF, 0);
    head.writeUInt8(header.crcEnabled || 0, 2);
    head.writeUInt8(commands.length & 0xFF, 3);
    head.writeInt32BE(header.sentTime | 0, 4);
    head.writeInt32BE(header.challenge | 0, 8);
    return Buffer.concat([head, ...commands]);
}

function _commandHeader(type, channelId, flags, size, reliableSequenceNumber) {
    const buf = Buffer.allocUnsafe(size);
    buf.writeUInt8(type, 0);
    buf.writeUInt8(channelId & 0xFF, 1);
    buf.writeUInt8(flags, 2);
    buf.writeUInt8(4, 3); // reserved byte, mirrors what Photon clients send
    buf.writeInt32BE(size, 4);
    buf.writeInt32BE(reliableSequenceNumber | 0, 8);
    return buf;
}

/**
 * Build an ACKNOWLEDGE command for a received reliable command.
 */
function buildAck(channelId, receivedReliableSequenceNumber, receivedSentTime) {
    const buf = _commandHeader(ENET_COMMANDS.ACKNOWLEDGE, channelId, 0, COMMAND_HEADER_SIZE + 8, 0);
    buf.writeInt32BE(receivedReliableSequenceNumber | 0, 12);
    buf.writeInt32BE(receivedSentTime | 0, 16);
    return buf;
}

/**
 * Build a VERIFY_CONNECT command answering a client CONNECT.
 * Payload: assigned peer id (uint16) followed by the mirrored connect payload.
 */
function buildVerifyConnect(sequenceNumber, assignedPeerId, connectPayload) {
    const payload = Buffer.alloc(32);
    if (connectPayload && connectPayload.length >= 32) {
        connectPayload.copy(payload, 0, 0, 32);
    }
    payload.writeUInt16BE(assignedPeerId & 0xFFFF, 0);

    const buf = _commandHeader(
        ENET_COMMANDS.VERIFY_CONNECT, 0xFF, FLAG_RELIABLE,
        COMMAND_HEADER_SIZE + payload.length, sequenceNumber
    );
    payload.copy(buf, COMMAND_HEADER_SIZE);
    return buf;
}

/**
 * Build a SEND_RELIABLE command carrying a message payload.
 */
function buildReliable(channelId, sequenceNumber, payload) {
    const buf = _commandHeader(
        ENET_COMMANDS.SEND_RELIABLE, channelId, FLAG_RELIABLE,
        COMMAND_HEADER_SIZE + payload.length, sequenceNumber
    );
    payload.copy(buf, COMMAND_HEADER_SIZE);
    return buf;
}

/**
 * Build a SEND_UNRELIABLE command carrying a message payload.
 */
function buildUnreliable(channelId, reliableSequenceNumber, unreliableSequenceNumber, payload) {
    const buf = _commandHeader(
        ENET_COMMANDS.SEND_UNRELIABLE, channelId, 0,
        UNRELIABLE_HEADER_SIZE + payload.length, reliableSequenceNumber
    );
    buf.writeInt32BE(unreliableSequenceNumber | 0, 12);
    payload.copy(buf, UNRELIABLE_HEADER_SIZE);
    return buf;
}

/**
 * Build one SEND_FRAGMENT command of a fragmented reliable message.
 */
function buildFragment(channelId, sequenceNumber, startSequenceNumber,
    fragmentCount, fragmentNumber, totalLength, fragmentOffset, chunk) {
    const buf = _commandHeader(
        ENET_COMMANDS.SEND_FRAGMENT, channelId, FLAG_RELIABLE,
        FRAGMENT_HEADER_SIZE + chunk.length, sequenceNumber
    );
    buf.writeInt32BE(startSequenceNumber | 0, 12);
    buf.writeInt32BE(fragmentCount | 0, 16);
    buf.writeInt32BE(fragmentNumber | 0, 20);
    buf.writeInt32BE(totalLength | 0, 24);
    buf.writeInt32BE(fragmentOffset | 0, 28);
    chunk.copy(buf, FRAGMENT_HEADER_SIZE);
    return buf;
}

/**
 * Build a PING command (reliable, control channel).
 */
function buildPing(sequenceNumber) {
    return _commandHeader(ENET_COMMANDS.PING, 0xFF, FLAG_RELIABLE, COMMAND_HEADER_SIZE, sequenceNumber);
}

/**
 * Build a FETCH_SERVER_TIMESTAMP reply carrying a 4-byte server time.
 */
function buildServerTimestamp(sequenceNumber, serverTime) {
    const buf = _commandHeader(
        ENET_COMMANDS.FETCH_SERVER_TIMESTAMP, 0xFF, FLAG_RELIABLE,
        COMMAND_HEADER_SIZE + 4, sequenceNumber
    );
    buf.writeInt32BE(serverTime | 0, COMMAND_HEADER_SIZE);
    return buf;
}

/**
 * Build a DISCONNECT command.
 */
function buildDisconnect(sequenceNumber) {
    return _commandHeader(ENET_COMMANDS.DISCONNECT, 0xFF, FLAG_UNSEQUENCED, COMMAND_HEADER_SIZE, sequenceNumber);
}

/**
 * Parse the client CONNECT payload (32 bytes of transport parameters).
 */
function parseConnectPayload(payload) {
    if (!payload || payload.length < 32) {
        return { mtu: 1200, channelCount: 2, raw: payload || Buffer.alloc(0) };
    }
    return {
        mtu: payload.readUInt16BE(2) || 1200,
        windowSize: payload.readInt32BE(4),
        channelCount: payload.readInt32BE(8) || 2,
        raw: payload
    };
}

module.exports = {
    PACKET_HEADER_SIZE,
    COMMAND_HEADER_SIZE,
    FRAGMENT_HEADER_SIZE,
    UNRELIABLE_HEADER_SIZE,
    FLAG_RELIABLE,
    FLAG_UNSEQUENCED,
    parsePacket,
    buildPacket,
    buildAck,
    buildVerifyConnect,
    buildReliable,
    buildUnreliable,
    buildFragment,
    buildPing,
    buildServerTimestamp,
    buildDisconnect,
    parseConnectPayload
};
