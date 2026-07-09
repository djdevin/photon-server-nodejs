const crypto = require('crypto');

/**
 * Photon payload encryption.
 *
 * The client negotiates a shared key with an anonymous Diffie-Hellman
 * exchange (Photon uses the Oakley Group 1 / 768-bit MODP prime, generator 2),
 * derives an AES key from the agreed secret, and AES-encrypts message bodies.
 * Encrypted messages set bit 0x80 in their message-type byte.
 *
 * DH interop across .NET (Photon) and Node has two historically fiddly points
 * that different Photon builds handle differently:
 *   1. how the shared secret's bytes are represented before hashing
 *      (minimal big-endian vs. zero-padded to the prime length), and
 *   2. the AES mode / IV framing.
 * Rather than hard-code one choice, `decrypt()` tries a small matrix of
 * (key-derivation × cipher-mode) candidates on the first encrypted message,
 * validates each against a caller-supplied predicate (parseable GpBinary),
 * and locks onto the winning combination for the rest of the session — the
 * same combination is then used to encrypt outbound messages.
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

function leftPad(buf, len) {
    if (buf.length >= len) return buf;
    return Buffer.concat([Buffer.alloc(len - buf.length), buf]);
}

function trimLeadingZeros(buf) {
    let i = 0;
    while (i < buf.length - 1 && buf[i] === 0) i++;
    return buf.slice(i);
}

const sha256 = (b) => crypto.createHash('sha256').update(b).digest();
const md5 = (b) => crypto.createHash('md5').update(b).digest();

class EncryptionContext {
    constructor() {
        this._dh = crypto.createDiffieHellman(OAKLEY_PRIME_768, OAKLEY_GENERATOR);
        this._dh.generateKeys();
        this._sharedSecret = null;
        this.established = false;

        // Locked-in scheme once decryption succeeds
        this._key = null;
        this._algo = null;   // 'aes-256-cbc' | 'aes-256-ecb' | ...
        this._ivMode = null; // 'zero' | 'prepend' | 'none'
        this._schemeName = null;
    }

    getServerPublicKey() {
        return this._dh.getPublicKey();
    }

    deriveSharedKey(clientPublicKey) {
        this._sharedSecret = this._dh.computeSecret(clientPublicKey);
        this.established = true;
        return this._sharedSecret;
    }

    get sharedSecretHex() {
        return this._sharedSecret ? this._sharedSecret.toString('hex') : null;
    }

    get schemeName() {
        return this._schemeName;
    }

    /** Candidate AES keys derived from the shared secret, most-likely first. */
    _candidateKeys() {
        const s = this._sharedSecret;
        const trimmed = trimLeadingZeros(s);
        const padded = leftPad(s, PRIME_LEN);
        const keys = [
            ['sha256(secret)', sha256(s)],
            ['sha256(secret,padded96)', sha256(padded)],
            ['sha256(secret,trimmed)', sha256(trimmed)],
            ['secret[0:32]', s.slice(0, 32)],
            ['padded96[0:32]', padded.slice(0, 32)],
            ['md5(secret)', md5(s)],
            ['md5(secret,padded96)', md5(padded)],
        ];
        return keys.filter(([, k]) => k.length >= 16);
    }

    /** (algo, ivMode, keySlice) cipher variants to try per candidate key. */
    _cipherVariants() {
        return [
            ['aes-256-cbc', 'zero', 32],
            ['aes-256-cbc', 'prepend', 32],
            ['aes-256-ecb', 'none', 32],
            ['aes-128-cbc', 'zero', 16],
            ['aes-128-cbc', 'prepend', 16],
        ];
    }

    _runDecrypt(algo, key, ivMode, data) {
        let iv = null;
        let ciphertext = data;
        if (ivMode === 'zero') {
            iv = Buffer.alloc(algo.startsWith('aes-128') ? 16 : 16);
        } else if (ivMode === 'prepend') {
            iv = data.slice(0, 16);
            ciphertext = data.slice(16);
        }
        const decipher = crypto.createDecipheriv(algo, key, iv);
        decipher.setAutoPadding(true);
        return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    }

    _runEncrypt(algo, key, ivMode, plaintext) {
        let iv = null;
        let prefix = Buffer.alloc(0);
        if (ivMode === 'zero') {
            iv = Buffer.alloc(16);
        } else if (ivMode === 'prepend') {
            iv = crypto.randomBytes(16);
            prefix = iv;
        }
        const cipher = crypto.createCipheriv(algo, key, iv);
        cipher.setAutoPadding(true);
        return Buffer.concat([prefix, cipher.update(plaintext), cipher.final()]);
    }

    /**
     * Decrypt an encrypted message body.
     * @param {Buffer} data - ciphertext (message bytes after the type byte)
     * @param {Function} [validate] - predicate on candidate plaintext used to
     *        detect the correct scheme on first use
     * @returns {Buffer} plaintext
     */
    decrypt(data, validate = null) {
        if (!this._sharedSecret) throw new Error('Encryption key not established');

        if (this._key) {
            return this._runDecrypt(this._algo, this._key, this._ivMode, data);
        }

        let firstDecryptable = null;
        for (const [keyName, key] of this._candidateKeys()) {
            for (const [algo, ivMode, keyLen] of this._cipherVariants()) {
                const useKey = key.length === keyLen ? key : key.slice(0, keyLen);
                if (useKey.length !== keyLen) continue;
                let plaintext;
                try {
                    plaintext = this._runDecrypt(algo, useKey, ivMode, data);
                } catch (e) {
                    continue; // padding error — wrong combination
                }
                const name = `${keyName}/${algo}/${ivMode}`;
                if (!validate || validate(plaintext)) {
                    this._lock(useKey, algo, ivMode, name);
                    return plaintext;
                }
                if (!firstDecryptable) firstDecryptable = { useKey, algo, ivMode, name, plaintext };
            }
        }

        if (firstDecryptable) {
            this._lock(firstDecryptable.useKey, firstDecryptable.algo,
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
            // Not yet calibrated (no inbound encrypted message seen). Fall back
            // to the most likely scheme.
            this._lock(sha256(this._sharedSecret), 'aes-256-cbc', 'zero',
                'sha256(secret)/aes-256-cbc/zero');
        }
        return this._runEncrypt(this._algo, this._key, this._ivMode, plaintext);
    }
}

module.exports = {
    OAKLEY_PRIME_768,
    OAKLEY_GENERATOR,
    EncryptionContext
};
