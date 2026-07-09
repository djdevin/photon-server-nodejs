/**
 * End-to-end smoke test: drives the server over real UDP with a minimal
 * ENet/GpBinary client, replicating what a PUN client does:
 *
 *   connect -> verify-connect -> init -> authenticate (master)
 *   -> create game (redirect) -> reconnect -> authenticate (game server)
 *   -> create game (join) -> raise cached event
 *   -> second client joins and must receive the join event + cached event
 */

const dgram = require('dgram');
const { PhotonServer } = require('../src');
const enet = require('../src/protocol/enet');
const gp = require('../src/protocol/gpbinary');
const { T, raw } = gp;

const PORT = 15055;
const HOST = '127.0.0.1';

// Connect payload captured from the real client (MTU 1200, 2 channels)
const CONNECT_PAYLOAD = Buffer.from(
    '000004b000008000000000020000000000000000000013880000000200000002', 'hex');

// Init message captured from the real client (protocol 1.6, "LoadBalancing")
const INIT_MESSAGE = Buffer.concat([
    Buffer.from([0xF3, 0x00, 0x01, 0x06, 0x1E, 0x41, 0x05, 0x05, 0x00]),
    Buffer.from('LoadBalancing'.padEnd(32, '\0'), 'latin1')
]);

class TestClient {
    constructor(name) {
        this.name = name;
        this.socket = dgram.createSocket('udp4');
        this.challenge = Math.floor(Math.random() * 0x7FFFFFFF);
        this.peerId = 0xFFFF;
        this.channels = new Map();
        this.fragments = new Map();
        this.messages = [];
        this.waiters = [];

        this.socket.on('message', (msg) => this._onDatagram(msg));
    }

    _channel(id) {
        let ch = this.channels.get(id);
        if (!ch) {
            ch = { outSeq: 0, inSeq: 0 };
            this.channels.set(id, ch);
        }
        return ch;
    }

    _send(commands) {
        const packet = enet.buildPacket({
            peerId: this.peerId,
            sentTime: Date.now() & 0x7FFFFFFF,
            challenge: this.challenge
        }, commands);
        this.socket.send(packet, PORT, HOST);
    }

    _onDatagram(msg) {
        const packet = enet.parsePacket(msg);
        if (!packet) return;

        const acks = [];
        for (const cmd of packet.commands) {
            if (cmd.flags & enet.FLAG_RELIABLE) {
                acks.push(enet.buildAck(cmd.channelId, cmd.reliableSequenceNumber, packet.sentTime));
            }

            if (cmd.type === 3) { // VERIFY_CONNECT
                this.peerId = cmd.payload.readUInt16BE(0);
                this._notify({ kind: 'verify', peerId: this.peerId });
            } else if (cmd.type === 6 || cmd.type === 7) {
                const payload = cmd.payload;
                if (payload.length >= 2 && payload[0] === 0xF3) {
                    const message = gp.parseMessage(payload);
                    this._notify({ kind: 'message', message });
                }
            } else if (cmd.type === 8) { // SEND_FRAGMENT
                let frag = this.fragments.get(cmd.startSequenceNumber);
                if (!frag) {
                    frag = { chunks: [], received: 0 };
                    this.fragments.set(cmd.startSequenceNumber, frag);
                }
                frag.chunks[cmd.fragmentNumber] = { offset: cmd.fragmentOffset, data: cmd.payload };
                frag.received++;
                if (frag.received === cmd.fragmentCount) {
                    this.fragments.delete(cmd.startSequenceNumber);
                    const full = Buffer.alloc(cmd.totalLength);
                    for (const chunk of frag.chunks) chunk.data.copy(full, chunk.offset);
                    if (full[0] === 0xF3) {
                        this._notify({ kind: 'message', message: gp.parseMessage(full) });
                    }
                }
            }
        }
        if (acks.length > 0) this._send(acks);
    }

    _notify(item) {
        // Deliver to the first matching waiter; only queue unclaimed items
        for (const waiter of [...this.waiters]) {
            if (waiter.match(item)) {
                this.waiters.splice(this.waiters.indexOf(waiter), 1);
                clearTimeout(waiter.timer);
                waiter.resolve(item);
                return;
            }
        }
        this.messages.push(item);
    }

    wait(desc, match, timeoutMs = 3000) {
        const existing = this.messages.find(match);
        if (existing) {
            this.messages.splice(this.messages.indexOf(existing), 1);
            return Promise.resolve(existing);
        }
        return new Promise((resolve, reject) => {
            const waiter = { match, resolve };
            waiter.timer = setTimeout(() => {
                this.waiters.splice(this.waiters.indexOf(waiter), 1);
                reject(new Error(`[${this.name}] timeout waiting for: ${desc}`));
            }, timeoutMs);
            this.waiters.push(waiter);
        });
    }

    connect() {
        const cmd = Buffer.alloc(44);
        cmd.writeUInt8(2, 0);         // CONNECT
        cmd.writeUInt8(0xFF, 1);      // control channel
        cmd.writeUInt8(1, 2);         // reliable
        cmd.writeUInt8(4, 3);
        cmd.writeInt32BE(44, 4);
        cmd.writeInt32BE(1, 8);       // seq 1
        CONNECT_PAYLOAD.copy(cmd, 12);
        this._channel(0xFF).outSeq = 1;
        this._send([cmd]);
        return this.wait('verify-connect', (m) => m.kind === 'verify');
    }

    sendReliable(payload, channelId = 0) {
        const ch = this._channel(channelId);
        const maxSingle = 1200 - enet.PACKET_HEADER_SIZE - enet.COMMAND_HEADER_SIZE;

        if (payload.length <= maxSingle) {
            const seq = ++ch.outSeq;
            this._send([enet.buildReliable(channelId, seq, payload)]);
            return;
        }

        // Client-side fragmentation (mirrors what a real ENet client does)
        const chunkSize = 1200 - enet.PACKET_HEADER_SIZE - enet.FRAGMENT_HEADER_SIZE;
        const count = Math.ceil(payload.length / chunkSize);
        const startSeq = ch.outSeq + 1;
        for (let i = 0; i < count; i++) {
            const offset = i * chunkSize;
            const chunk = payload.slice(offset, offset + chunkSize);
            const seq = ++ch.outSeq;
            this._send([enet.buildFragment(
                channelId, seq, startSeq, count, i, payload.length, offset, chunk
            )]);
        }
    }

    sendOperation(opCode, params, internal = false) {
        const w = new gp.Writer();
        w.u8(0xF3);
        w.u8(internal ? 6 : 2);
        w.u8(opCode);
        const entries = Object.entries(params);
        w.i16(entries.length);
        for (const [code, value] of entries) {
            w.u8(Number(code));
            w.value(value);
        }
        this.sendReliable(w.buffer());
    }

    waitForResponse(opCode, timeoutMs = 3000) {
        return this.wait(`op response ${opCode}`, (m) =>
            m.kind === 'message' &&
            (m.message.messageType === 3 || m.message.messageType === 7) &&
            m.message.operationCode === opCode, timeoutMs
        ).then(m => m.message);
    }

    waitForEvent(eventCode, timeoutMs = 3000) {
        return this.wait(`event ${eventCode}`, (m) =>
            m.kind === 'message' &&
            m.message.messageType === 4 &&
            m.message.eventCode === eventCode, timeoutMs
        ).then(m => m.message);
    }

    close() {
        try { this.socket.close(); } catch (e) { /* ignore */ }
    }
}

function assert(cond, what) {
    if (!cond) throw new Error(`ASSERT FAILED: ${what}`);
    console.log(`  ok: ${what}`);
}

async function fullClientFlow(name, roomName, { expectJoinOfOther } = {}) {
    // ---- master phase ----
    let client = new TestClient(`${name}-master`);
    await client.connect();
    console.log(`[${name}] verified, peerId=${client.peerId}`);

    client.sendReliable(INIT_MESSAGE);
    await client.wait('init response', (m) =>
        m.kind === 'message' && m.message.messageType === 1);
    console.log(`[${name}] init response received`);

    client.sendOperation(230, { 220: T.string('test-app-1.0'), 225: T.string(name) });
    let auth = await client.waitForResponse(230);
    assert(auth.returnCode === 0, `${name} master auth ok`);
    const secret = raw(auth.parameters[221]);
    assert(typeof secret === 'string' && secret.length > 0, `${name} got secret`);

    client.sendOperation(226, { 255: T.string(roomName), 215: T.byte(1) });
    const redirect = await client.waitForResponse(226);
    assert(redirect.returnCode === 0, `${name} join redirect ok`);
    const address = raw(redirect.parameters[230]);
    assert(address === `${HOST}:${PORT}`, `${name} redirect address is ${address}`);
    const gsSecret = raw(redirect.parameters[221]);
    client.close();

    // ---- game server phase (reconnect like a real client) ----
    client = new TestClient(`${name}-game`);
    await client.connect();
    client.sendReliable(INIT_MESSAGE);
    await client.wait('init response', (m) =>
        m.kind === 'message' && m.message.messageType === 1);

    client.sendOperation(230, {
        220: T.string('test-app-1.0'),
        225: T.string(name),
        221: T.string(gsSecret)
    });
    auth = await client.waitForResponse(230);
    assert(auth.returnCode === 0, `${name} game-server auth ok`);

    const nickProps = new Map([[255, `${name}-nick`]]);
    client.sendOperation(226, {
        255: T.string(roomName),
        215: T.byte(1),
        249: T.hashtable(nickProps),
        250: true
    });
    const join = await client.waitForResponse(226);
    assert(join.returnCode === 0, `${name} joined room`);
    const actorNr = raw(join.parameters[254]);
    assert(typeof actorNr === 'number' && actorNr >= 1, `${name} actorNr=${actorNr}`);
    const actors = raw(join.parameters[252]);
    console.log(`[${name}] actors in room: ${JSON.stringify(actors)}`);

    const joinEvent = await client.waitForEvent(255);
    assert(raw(joinEvent.parameters[254]) === actorNr, `${name} received own join event`);

    return { client, actorNr };
}

async function main() {
    const server = new PhotonServer({
        port: PORT,
        host: HOST,
        publicAddress: `${HOST}:${PORT}`
    });
    await server.start();
    console.log('server started');

    try {
        // Client A: full connect + join flow
        const a = await fullClientFlow('alice', 'TestRoom');

        // A raises a cached event (like PUN instantiation)
        a.client.sendOperation(253, {
            244: T.byte(42),
            245: T.hashtable(new Map([['msg', 'hello'], [5, T.byte(7)]])),
            247: T.byte(4) // AddToRoomCache
        });
        console.log('[alice] raised cached event 42');

        // Client B joins the same room
        const b = await fullClientFlow('bob', 'TestRoom');
        assert(b.actorNr === a.actorNr + 1, 'bob got next actor number');

        // A must see B's join
        const joinOfB = await a.client.waitForEvent(255);
        assert(raw(joinOfB.parameters[254]) === b.actorNr, 'alice saw bob join');

        // B must receive the cached event
        const cached = await b.client.waitForEvent(42);
        assert(raw(cached.parameters[254]) === a.actorNr, 'bob got cached event from alice');
        const data = raw(cached.parameters[245]);
        assert(data instanceof Map && data.get('msg') === 'hello', 'cached event data intact');
        assert(raw(data.get(5)) === 7, 'cached event byte value intact');

        // B raises a live event that A receives
        b.client.sendOperation(253, { 244: T.byte(10), 245: T.string('ping!') });
        const live = await a.client.waitForEvent(10);
        assert(raw(live.parameters[245]) === 'ping!', 'alice got live event from bob');

        // B raises a large event (5KB) — exercises fragmentation both ways:
        // bob->server (reassembly) and server->alice (fragmenting)
        const bigData = Buffer.alloc(5000);
        for (let i = 0; i < bigData.length; i++) bigData[i] = i & 0xFF;
        b.client.sendOperation(253, { 244: T.byte(11), 245: T.byteArray(bigData) });
        const bigEvent = await a.client.waitForEvent(11);
        const received = raw(bigEvent.parameters[245]);
        assert(Buffer.isBuffer(received) && received.length === 5000, 'fragmented event size intact');
        assert(received.equals(bigData), 'fragmented event content intact');

        // Internal ping
        a.client.sendOperation(1, { 1: T.int(123456) }, true);
        const pong = await a.client.waitForResponse(1);
        assert(raw(pong.parameters[1]) === 123456, 'internal ping echoed client time');

        // Leave
        b.client.sendOperation(254, {});
        const leaveResp = await b.client.waitForResponse(254);
        assert(leaveResp.returnCode === 0, 'bob left room');
        const leaveEvent = await a.client.waitForEvent(254);
        assert(raw(leaveEvent.parameters[254]) === b.actorNr, 'alice saw bob leave');

        a.client.close();
        b.client.close();

        console.log('\nALL TESTS PASSED');
    } finally {
        await server.stop();
    }
}

main().then(
    () => process.exit(0),
    (error) => {
        console.error('\nTEST FAILED:', error.message);
        process.exit(1);
    }
);
