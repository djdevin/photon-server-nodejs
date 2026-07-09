const crypto = require('crypto');

/**
 * Photon payload encryption.
 *
 * The client negotiates a shared key with an anonymous Diffie-Hellman
 * exchange (Photon uses the Oakley Group 1 / 768-bit MODP prime, generator 2),
 * derives an AES key from the agreed secret, and AES-encrypts message bodies.
 * Encrypted messages set bit 0x80 in their message-type byte.
 *
 * Byte order: Photon is a .NET codebase and serializes the DH integers
 * little-endian, while Node's crypto.DiffieHellman is big-endian. We therefore
 * reverse the client's public key on the way in and our public key on the way
 * out. The AES-key derivation and cipher framing are then discovered by trying
 * a small matrix of candidates against the client's first encrypted message
 * (validated as parseable GpBinary) and locking onto the winner.
 */

// RFC 2409 Oakley Group 1 (768-bit MODP prime)
const OAKLEY_PRIME_768 = Buffer.from([
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
    0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
    0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x3A, 0x36, 0x20,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
]);

const OAKLEY_GENERATOR = Buffer.from([0x02]);
const PRIME_LEN = OAKLEY_PRIME_768.length; // 96

// Set true if a capture proves Photon uses big-endian after all.
const CLIENT_LITTLE_ENDIAN = true;

const rev = (b) => Buffer.from(b).reverse();
const sha256 = (b) => crypto.createHash('sha256').update(b).digest();
const md5 = (b) => crypto.createHash('md5').update(b).digest();

function leftPad(buf, len) {
    if (buf.length >= len) return buf;
    return Buffer.concat([Buffer.alloc(len - buf.length), buf]);
}

function trimLeadingZeros(buf) {
    let i = 0;
    while (i < buf.length - 1 && buf[i] === 0) i++;
    return buf.slice(i);
}

class EncryptionContext {
    constructor() {
        this._dh = crypto.createDiffieHellman(OAKLEY_PRIME_768, OAKLEY_GENERATOR);
        this._dh.generateKeys();
        this._clientPublicKey = null;
        this._sharedSecret = null;
        this.established = false;

        this._key = null;
        this._algo = null;
        this._ivMode = null;
        this._schemeName = null;
    }

    /** Server public key in the byte order the client expects. */
    getServerPublicKey() {
        const raw = this._dh.getPublicKey(); // big-endian
        return CLIENT_LITTLE_ENDIAN ? rev(raw) : raw;
    }

    /**
     * Complete the exchange with the client's public key (as received).
     * @param {Buffer} clientPublicKey
     */
    deriveSharedKey(clientPublicKey) {
        this._clientPublicKey = clientPublicKey;
        const clientBE = CLIENT_LITTLE_ENDIAN ? rev(clientPublicKey) : clientPublicKey;
        this._sharedSecret = this._dh.computeSecret(clientBE); // big-endian
        this.established = true;
        return this._sharedSecret;
    }

    // Diagnostics used to solve the scheme offline if calibration fails.
    get sharedSecretHex() { return this._sharedSecret ? this._sharedSecret.toString('hex') : null; }
    get privateKeyHex() { return this._dh.getPrivateKey().toString('hex'); }
    get serverPublicKeyRawHex() { return this._dh.getPublicKey().toString('hex'); }
    get clientPublicKeyHex() { return this._clientPublicKey ? this._clientPublicKey.toString('hex') : null; }
    get schemeName() { return this._schemeName; }

    /** Candidate AES keys, covering both byte orders and common derivations. */
    _candidateKeys() {
        const s = this._sharedSecret;
        const forms = {
            be: s,
            le: rev(s),
            'be-pad96': leftPad(s, PRIME_LEN),
            'le-pad96': leftPad(rev(s), PRIME_LEN),
            'be-trim': trimLeadingZeros(s),
            'le-trim': trimLeadingZeros(rev(s))
        };
        const keys = [];
        for (const [name, form] of Object.entries(forms)) {
            keys.push([`sha256(${name})`, sha256(form)]);
            keys.push([`md5(${name})`, md5(form)]);
            if (form.length >= 32) keys.push([`${name}[0:32]`, form.slice(0, 32)]);
            if (form.length >= 16) keys.push([`${name}[0:16]`, form.slice(0, 16)]);
        }
        return keys.filter(([, k]) => k.length === 16 || k.length === 32);
    }

    _cipherVariants(keyLen) {
        if (keyLen === 32) {
            return [
                ['aes-256-cbc', 'zero'],
                ['aes-256-cbc', 'prepend'],
                ['aes-256-ecb', 'none']
            ];
        }
        return [
            ['aes-128-cbc', 'zero'],
            ['aes-128-cbc', 'prepend'],
            ['aes-128-ecb', 'none']
        ];
    }

    _runDecrypt(algo, key, ivMode, data) {
        let iv = null;
        let ciphertext = data;
        if (ivMode === 'zero') iv = Buffer.alloc(16);
        else if (ivMode === 'prepend') { iv = data.slice(0, 16); ciphertext = data.slice(16); }
        const decipher = crypto.createDecipheriv(algo, key, ivMode === 'none' ? null : iv);
        decipher.setAutoPadding(true);
        return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    }

    _runEncrypt(algo, key, ivMode, plaintext) {
        let iv = null;
        let prefix = Buffer.alloc(0);
        if (ivMode === 'zero') iv = Buffer.alloc(16);
        else if (ivMode === 'prepend') { iv = crypto.randomBytes(16); prefix = iv; }
        const cipher = crypto.createCipheriv(algo, key, ivMode === 'none' ? null : iv);
        cipher.setAutoPadding(true);
        return Buffer.concat([prefix, cipher.update(plaintext), cipher.final()]);
    }

    decrypt(data, validate = null) {
        if (!this._sharedSecret) throw new Error('Encryption key not established');

        if (this._key) {
            return this._runDecrypt(this._algo, this._key, this._ivMode, data);
        }

        let firstDecryptable = null;
        for (const [keyName, key] of this._candidateKeys()) {
            for (const [algo, ivMode] of this._cipherVariants(key.length)) {
                let plaintext;
                try {
                    plaintext = this._runDecrypt(algo, key, ivMode, data);
                } catch (e) {
                    continue;
                }
                const name = `${keyName}/${algo}/${ivMode}`;
                if (!validate || validate(plaintext)) {
                    this._lock(key, algo, ivMode, name);
                    return plaintext;
                }
                if (!firstDecryptable) firstDecryptable = { key, algo, ivMode, name, plaintext };
            }
        }

        if (firstDecryptable) {
            this._lock(firstDecryptable.key, firstDecryptable.algo,
                firstDecryptable.ivMode, firstDecryptable.name);
            return firstDecryptable.plaintext;
        }

        throw new Error('Unable to decrypt payload with any known key/cipher combination');
    }

    _lock(key, algo, ivMode, name) {
        this._key = key;
        this._algo = algo;
        this._ivMode = ivMode;
        this._schemeName = name;
    }

    encrypt(plaintext) {
        if (!this._sharedSecret) throw new Error('Encryption key not established');
        if (!this._key) {
            this._lock(sha256(this._sharedSecret), 'aes-256-cbc', 'zero',
                'sha256(be)/aes-256-cbc/zero');
        }
        return this._runEncrypt(this._algo, this._key, this._ivMode, plaintext);
    }
}

module.exports = {
    OAKLEY_PRIME_768,
    OAKLEY_GENERATOR,
    EncryptionContext
};
