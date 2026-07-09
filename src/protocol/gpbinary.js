const {
    PHOTON_TYPES,
    MESSAGE_TYPES,
    MESSAGE_SIGNATURE
} = require('./constants');

/**
 * GpBinaryV16 codec — the serialization used by Photon protocol 1.6.
 *
 * Type fidelity matters: a value received as `byte` must be echoed back as
 * `byte`, or the C# client will fail casting it. The Reader therefore wraps
 * types that don't round-trip naturally through JS (byte, short, long, float,
 * double, typed arrays, custom data) in Typed markers which the Writer
 * serializes back exactly. Plain JS values are used where the mapping is
 * unambiguous: null, boolean, int32 (number), string, Buffer (byte[]),
 * Array (object[]), Map (hashtable).
 *
 * Use `raw(value)` to unwrap a possibly-Typed value, and the `T` helpers to
 * write explicit types, e.g. T.int(actorNr).
 */

class Typed {
    constructor(type, value) {
        this.type = type;
        this.value = value;
    }
}

const T = {
    null: () => new Typed('null', null),
    byte: (v) => new Typed('byte', v),
    bool: (v) => new Typed('bool', v),
    short: (v) => new Typed('short', v),
    int: (v) => new Typed('int', v),
    long: (v) => new Typed('long', v),
    float: (v) => new Typed('float', v),
    double: (v) => new Typed('double', v),
    string: (v) => new Typed('string', String(v)),
    byteArray: (v) => new Typed('byteArray', v),
    intArray: (v) => new Typed('intArray', v),
    stringArray: (v) => new Typed('stringArray', v),
    objectArray: (v) => new Typed('objectArray', v),
    hashtable: (v) => new Typed('hashtable', v),
    array: (elementType, items) => new Typed('array', { elementType, items }),
    dictionary: (keyType, valType, map) => new Typed('dictionary', { keyType, valType, map }),
    custom: (code, data) => new Typed('custom', { code, data })
};

/** Unwrap a possibly-Typed value to its plain JS value. */
function raw(v) {
    return v instanceof Typed ? v.value : v;
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

class Writer {
    constructor() {
        this._chunks = [];
        this._length = 0;
    }

    _push(buf) {
        this._chunks.push(buf);
        this._length += buf.length;
    }

    u8(v) { const b = Buffer.allocUnsafe(1); b.writeUInt8(v & 0xFF, 0); this._push(b); }
    i16(v) { const b = Buffer.allocUnsafe(2); b.writeInt16BE(v | 0, 0); this._push(b); }
    i32(v) { const b = Buffer.allocUnsafe(4); b.writeInt32BE(v | 0, 0); this._push(b); }
    i64(v) { const b = Buffer.allocUnsafe(8); b.writeBigInt64BE(BigInt(v), 0); this._push(b); }
    f32(v) { const b = Buffer.allocUnsafe(4); b.writeFloatBE(v, 0); this._push(b); }
    f64(v) { const b = Buffer.allocUnsafe(8); b.writeDoubleBE(v, 0); this._push(b); }
    raw(buf) { this._push(Buffer.from(buf)); }

    string(str) {
        const bytes = Buffer.from(String(str), 'utf8');
        this.i16(bytes.length);
        this._push(bytes);
    }

    /** Write a full typed value (type marker + body). */
    value(v) {
        const t = this._resolve(v);
        const marker = Writer.MARKERS[t.type];
        if (marker === undefined) {
            throw new Error(`GpBinary: cannot serialize type '${t.type}'`);
        }
        this.u8(marker);
        this._body(t.type, t.value);
    }

    /** Write a value body without its type marker (for typed arrays). */
    _body(type, value) {
        switch (type) {
            case 'null': break;
            case 'byte': this.u8(value); break;
            case 'bool': this.u8(value ? 1 : 0); break;
            case 'short': this.i16(value); break;
            case 'int': this.i32(value); break;
            case 'long': this.i64(value); break;
            case 'float': this.f32(value); break;
            case 'double': this.f64(value); break;
            case 'string': this.string(value); break;
            case 'byteArray':
                this.i32(value.length);
                this.raw(value);
                break;
            case 'intArray':
                this.i32(value.length);
                for (const n of value) this.i32(n);
                break;
            case 'stringArray':
                this.i16(value.length);
                for (const s of value) this.string(s);
                break;
            case 'objectArray':
                this.i16(value.length);
                for (const item of value) this.value(item);
                break;
            case 'array': {
                this.i16(value.items.length);
                this.u8(value.elementType);
                const bodyType = Writer.TYPE_BY_MARKER[value.elementType];
                for (const item of value.items) {
                    if (bodyType) {
                        this._body(bodyType, raw(item));
                    } else if (item instanceof Typed) {
                        this._body(item.type, item.value);
                    } else {
                        throw new Error(`GpBinary: cannot write array element of marker 0x${value.elementType.toString(16)}`);
                    }
                }
                break;
            }
            case 'hashtable': {
                const entries = value instanceof Map ? [...value.entries()] : Object.entries(value);
                this.i16(entries.length);
                for (const [key, val] of entries) {
                    this.value(this._autoKey(key));
                    this.value(val);
                }
                break;
            }
            case 'dictionary': {
                this.u8(value.keyType);
                this.u8(value.valType);
                const entries = value.map instanceof Map ? [...value.map.entries()] : Object.entries(value.map);
                this.i16(entries.length);
                const keyBody = Writer.TYPE_BY_MARKER[value.keyType];
                const valBody = Writer.TYPE_BY_MARKER[value.valType];
                for (const [key, val] of entries) {
                    if (keyBody) this._body(keyBody, raw(key)); else this.value(key);
                    if (valBody) this._body(valBody, raw(val)); else this.value(val);
                }
                break;
            }
            case 'custom':
                this.u8(value.code);
                this.i16(value.data.length);
                this.raw(value.data);
                break;
            default:
                throw new Error(`GpBinary: cannot serialize type '${type}'`);
        }
    }

    /**
     * Hashtable key convention: integer keys 0-255 become GpBinary bytes
     * (Photon's well-known property keys), everything else keeps its type.
     */
    _autoKey(key) {
        if (key instanceof Typed) return key;
        if (typeof key === 'number' && Number.isInteger(key) && key >= 0 && key <= 255) {
            return T.byte(key);
        }
        if (typeof key === 'string' && /^\d+$/.test(key) && Number(key) <= 255) {
            return T.byte(Number(key));
        }
        return key;
    }

    /** Map an untyped JS value onto a Typed wrapper. */
    _resolve(v) {
        if (v instanceof Typed) return v;
        if (v === null || v === undefined) return T.null();
        switch (typeof v) {
            case 'string': return T.string(v);
            case 'boolean': return T.bool(v);
            case 'number':
                if (!Number.isInteger(v)) return T.float(v);
                if (v >= -2147483648 && v <= 2147483647) return T.int(v);
                return T.long(v);
            case 'bigint': return T.long(v);
            case 'object':
                if (Buffer.isBuffer(v) || v instanceof Uint8Array) return T.byteArray(Buffer.from(v));
                if (Array.isArray(v)) return T.objectArray(v);
                return T.hashtable(v);
            default:
                throw new Error(`GpBinary: unsupported JS type '${typeof v}'`);
        }
    }

    buffer() {
        return Buffer.concat(this._chunks, this._length);
    }
}

Writer.MARKERS = {
    null: PHOTON_TYPES.NULL,
    byte: PHOTON_TYPES.BYTE,
    bool: PHOTON_TYPES.BOOLEAN,
    short: PHOTON_TYPES.SHORT,
    int: PHOTON_TYPES.INTEGER,
    long: PHOTON_TYPES.LONG,
    float: PHOTON_TYPES.FLOAT,
    double: PHOTON_TYPES.DOUBLE,
    string: PHOTON_TYPES.STRING,
    byteArray: PHOTON_TYPES.BYTE_ARRAY,
    intArray: PHOTON_TYPES.INT_ARRAY,
    stringArray: PHOTON_TYPES.STRING_ARRAY,
    objectArray: PHOTON_TYPES.OBJECT_ARRAY,
    array: PHOTON_TYPES.ARRAY,
    hashtable: PHOTON_TYPES.HASH_TABLE,
    dictionary: PHOTON_TYPES.DICTIONARY,
    custom: PHOTON_TYPES.CUSTOM_DATA
};

// marker -> body type name (scalars and simple types only)
Writer.TYPE_BY_MARKER = {
    [PHOTON_TYPES.BYTE]: 'byte',
    [PHOTON_TYPES.BOOLEAN]: 'bool',
    [PHOTON_TYPES.SHORT]: 'short',
    [PHOTON_TYPES.INTEGER]: 'int',
    [PHOTON_TYPES.LONG]: 'long',
    [PHOTON_TYPES.FLOAT]: 'float',
    [PHOTON_TYPES.DOUBLE]: 'double',
    [PHOTON_TYPES.STRING]: 'string',
    [PHOTON_TYPES.BYTE_ARRAY]: 'byteArray',
    [PHOTON_TYPES.INT_ARRAY]: 'intArray',
    [PHOTON_TYPES.STRING_ARRAY]: 'stringArray',
    [PHOTON_TYPES.OBJECT_ARRAY]: 'objectArray',
    [PHOTON_TYPES.HASH_TABLE]: 'hashtable',
    [PHOTON_TYPES.CUSTOM_DATA]: 'custom'
};

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

class Reader {
    constructor(buf, offset = 0) {
        this.buf = buf;
        this.offset = offset;
    }

    _need(n) {
        if (this.offset + n > this.buf.length) {
            throw new Error(`GpBinary: unexpected end of buffer at ${this.offset} (+${n}/${this.buf.length})`);
        }
    }

    u8() { this._need(1); return this.buf.readUInt8(this.offset++); }
    i16() { this._need(2); const v = this.buf.readInt16BE(this.offset); this.offset += 2; return v; }
    i32() { this._need(4); const v = this.buf.readInt32BE(this.offset); this.offset += 4; return v; }
    i64() { this._need(8); const v = this.buf.readBigInt64BE(this.offset); this.offset += 8; return v; }
    f32() { this._need(4); const v = this.buf.readFloatBE(this.offset); this.offset += 4; return v; }
    f64() { this._need(8); const v = this.buf.readDoubleBE(this.offset); this.offset += 8; return v; }

    bytes(n) {
        this._need(n);
        const v = this.buf.slice(this.offset, this.offset + n);
        this.offset += n;
        return v;
    }

    string() {
        return this.bytes(this.i16()).toString('utf8');
    }

    /** Read a full typed value; see module docs for the JS mapping. */
    value(fixedType = null) {
        const type = fixedType !== null ? fixedType : this.u8();
        switch (type) {
            case 0:
            case PHOTON_TYPES.NULL: return null;
            case PHOTON_TYPES.BYTE: return T.byte(this.u8());
            case PHOTON_TYPES.BOOLEAN: return this.u8() !== 0;
            case PHOTON_TYPES.SHORT: return T.short(this.i16());
            case PHOTON_TYPES.INTEGER: return this.i32();
            case PHOTON_TYPES.LONG: {
                const v = this.i64();
                return T.long(v >= Number.MIN_SAFE_INTEGER && v <= Number.MAX_SAFE_INTEGER ? Number(v) : v);
            }
            case PHOTON_TYPES.FLOAT: return T.float(this.f32());
            case PHOTON_TYPES.DOUBLE: return T.double(this.f64());
            case PHOTON_TYPES.STRING: return this.string();
            case PHOTON_TYPES.BYTE_ARRAY: return this.bytes(this.i32());
            case PHOTON_TYPES.INT_ARRAY: {
                const len = this.i32();
                const arr = new Array(len);
                for (let i = 0; i < len; i++) arr[i] = this.i32();
                return T.intArray(arr);
            }
            case PHOTON_TYPES.STRING_ARRAY: {
                const len = this.i16();
                const arr = new Array(len);
                for (let i = 0; i < len; i++) arr[i] = this.string();
                return T.stringArray(arr);
            }
            case PHOTON_TYPES.OBJECT_ARRAY: {
                const len = this.i16();
                const arr = new Array(len);
                for (let i = 0; i < len; i++) arr[i] = this.value();
                return arr;
            }
            case PHOTON_TYPES.ARRAY: {
                const len = this.i16();
                const elementType = this.u8();
                const items = new Array(len);
                for (let i = 0; i < len; i++) items[i] = this.value(elementType);
                return T.array(elementType, items);
            }
            case PHOTON_TYPES.HASH_TABLE: {
                const len = this.i16();
                const map = new Map();
                for (let i = 0; i < len; i++) {
                    const key = raw(this.value());
                    map.set(key, this.value());
                }
                return map;
            }
            case PHOTON_TYPES.DICTIONARY: {
                const keyType = this.u8();
                const valType = this.u8();
                const len = this.i16();
                const readKey = keyType === 0 || keyType === PHOTON_TYPES.NULL;
                const readVal = valType === 0 || valType === PHOTON_TYPES.NULL;
                const map = new Map();
                for (let i = 0; i < len; i++) {
                    const key = raw(this.value(readKey ? null : keyType));
                    const val = this.value(readVal ? null : valType);
                    map.set(key, val);
                }
                return T.dictionary(keyType, valType, map);
            }
            case PHOTON_TYPES.CUSTOM_DATA: {
                const code = this.u8();
                const len = this.i16();
                return T.custom(code, this.bytes(len));
            }
            default:
                throw new Error(`GpBinary: unknown type marker 0x${type.toString(16)} at offset ${this.offset - 1}`);
        }
    }

    /** Read a parameter dictionary: int16 count of (byte code, typed value). */
    parameters() {
        const count = this.i16();
        const params = {};
        for (let i = 0; i < count; i++) {
            const code = this.u8();
            params[code] = this.value();
        }
        return params;
    }
}

// ---------------------------------------------------------------------------
// Message layer (0xF3-prefixed messages inside transport payloads)
// ---------------------------------------------------------------------------

/**
 * Parse a message payload starting with 0xF3.
 */
function parseMessage(buf) {
    if (buf.length < 2 || buf.readUInt8(0) !== MESSAGE_SIGNATURE) {
        throw new Error(`Not a Photon message (starts with 0x${buf.readUInt8(0).toString(16)})`);
    }

    const typeByte = buf.readUInt8(1);
    const messageType = typeByte & 0x7F;
    const encrypted = (typeByte & 0x80) !== 0;
    const message = { messageType, encrypted };

    if (encrypted) {
        message.raw = buf.slice(2);
        return message;
    }

    const reader = new Reader(buf, 2);

    switch (messageType) {
        case MESSAGE_TYPES.INIT: {
            message.protocolVersion = `${reader.u8()}.${reader.u8()}`;
            message.clientSdkId = reader.u8();
            message.clientVersion = [reader.u8(), reader.u8(), reader.u8(), reader.u8()].join('.');
            const appIdBytes = reader.bytes(Math.min(32, buf.length - reader.offset));
            const zero = appIdBytes.indexOf(0);
            message.applicationId = appIdBytes.slice(0, zero === -1 ? appIdBytes.length : zero).toString('utf8');
            break;
        }

        case MESSAGE_TYPES.OPERATION_REQUEST:
        case MESSAGE_TYPES.INTERNAL_OPERATION_REQUEST:
            message.operationCode = reader.u8();
            message.parameters = reader.parameters();
            break;

        case MESSAGE_TYPES.OPERATION_RESPONSE:
        case MESSAGE_TYPES.INTERNAL_OPERATION_RESPONSE:
            message.operationCode = reader.u8();
            message.returnCode = reader.i16();
            message.debugMessage = raw(reader.value());
            message.parameters = reader.parameters();
            break;

        case MESSAGE_TYPES.EVENT:
            message.eventCode = reader.u8();
            message.parameters = reader.parameters();
            break;

        default:
            message.raw = buf.slice(2);
    }

    return message;
}

function _writeParameters(w, parameters) {
    const entries = parameters instanceof Map
        ? [...parameters.entries()]
        : Object.entries(parameters || {});
    const valid = entries.filter(([code]) => {
        const n = Number(code);
        return Number.isInteger(n) && n >= 0 && n <= 255;
    });
    w.i16(valid.length);
    for (const [code, value] of valid) {
        w.u8(Number(code));
        w.value(value);
    }
}

/** Build the init response message. The client only inspects the type byte. */
function buildInitResponse() {
    return Buffer.from([MESSAGE_SIGNATURE, MESSAGE_TYPES.INIT_RESPONSE]);
}

/**
 * Build an operation response message.
 */
function buildOperationResponse(opCode, returnCode = 0, parameters = {}, debugMessage = null, internal = false) {
    const w = new Writer();
    w.u8(MESSAGE_SIGNATURE);
    w.u8(internal ? MESSAGE_TYPES.INTERNAL_OPERATION_RESPONSE : MESSAGE_TYPES.OPERATION_RESPONSE);
    w.u8(opCode);
    w.i16(returnCode);
    w.value(debugMessage === null || debugMessage === undefined ? T.null() : T.string(debugMessage));
    _writeParameters(w, parameters);
    return w.buffer();
}

/**
 * Build an event message.
 */
function buildEvent(eventCode, parameters = {}) {
    const w = new Writer();
    w.u8(MESSAGE_SIGNATURE);
    w.u8(MESSAGE_TYPES.EVENT);
    w.u8(eventCode);
    _writeParameters(w, parameters);
    return w.buffer();
}

module.exports = {
    T,
    Typed,
    raw,
    Writer,
    Reader,
    parseMessage,
    buildInitResponse,
    buildOperationResponse,
    buildEvent
};
