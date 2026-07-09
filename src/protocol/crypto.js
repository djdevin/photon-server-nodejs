const crypto = require('crypto');

/**
 * Photon payload encryption.
 *
 * The client negotiates a shared key with an anonymous Diffie-Hellman
 * exchange (Photon uses the Oakley Group 1 / 768-bit MODP prime with
 * generator 2), hashes the agreed secret with SHA-256 to get a 256-bit AES
 * key, and then AES-encrypts message bodies. Encrypted messages set bit 0x80
 * in their message-type byte (see gpbinary.parseMessage).
 *
 * The exact AES framing (whether a per-message IV is prepended) is confirmed
 * empirically the first time the client sends an encrypted message —
 * `decrypt()` tries the known schemes and remembers whichever yields a
 * parseable payload.
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

class EncryptionContext {
    constructor() {
        this._dh = crypto.createDiffieHellman(OAKLEY_PRIME_768, OAKLEY_GENERATOR);
        this._dh.generateKeys();
        this._sharedKey = null;     // 32-byte AES key
        this._ivScheme = null;      // 'prepend' | 'zero' | null (undetermined)
        this.established = false;
    }

    /** Server's DH public key (big-endian bytes) to send back to the client. */
    getServerPublicKey() {
        return this._dh.getPublicKey();
    }

    /**
     * Complete the exchange with the client's public key.
     * @param {Buffer} clientPublicKey - big-endian bytes
     */
    deriveSharedKey(clientPublicKey) {
        const secret = this._dh.computeSecret(clientPublicKey);
        this._sharedKey = crypto.createHash('sha256').update(secret).digest();
        this.established = true;
        return this._sharedKey;
    }

    get sharedKeyHex() {
        return this._sharedKey ? this._sharedKey.toString('hex') : null;
    }

    // ---- AES ----

    _decryptCbc(ciphertext, iv) {
        const decipher = crypto.createDecipheriv('aes-256-cbc', this._sharedKey, iv);
        decipher.setAutoPadding(true);
        return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    }

    _encryptCbc(plaintext, iv) {
        const cipher = crypto.createCipheriv('aes-256-cbc', this._sharedKey, iv);
        cipher.setAutoPadding(true);
        return Buffer.concat([cipher.update(plaintext), cipher.final()]);
    }

    /**
     * Decrypt an encrypted message body.
     * @param {Buffer} data - ciphertext (message bytes after the type byte)
     * @param {Function} [validate] - optional predicate on the plaintext;
     *        used to auto-detect the IV scheme on first use
     * @returns {Buffer} plaintext
     */
    decrypt(data, validate = null) {
        if (!this._sharedKey) throw new Error('Encryption key not established');

        // Once the scheme is known, use it directly.
        if (this._ivScheme === 'zero') {
            return this._decryptCbc(data, Buffer.alloc(16));
        }
        if (this._ivScheme === 'prepend') {
            return this._decryptCbc(data.slice(16), data.slice(0, 16));
        }

        // Undetermined: try candidate schemes and keep the one that validates.
        const candidates = [
            ['zero', () => this._decryptCbc(data, Buffer.alloc(16))],
            ['prepend', () => this._decryptCbc(data.slice(16), data.slice(0, 16))]
        ];

        let firstSuccess = null;
        for (const [scheme, run] of candidates) {
            try {
                const plaintext = run();
                if (!validate || validate(plaintext)) {
                    this._ivScheme = scheme;
                    return plaintext;
                }
                if (!firstSuccess) firstSuccess = { scheme, plaintext };
            } catch (e) {
                // padding error — wrong scheme, keep trying
            }
        }

        if (firstSuccess) {
            // Decrypted without a padding error but validation failed; use it
            // and record the scheme so behaviour is stable.
            this._ivScheme = firstSuccess.scheme;
            return firstSuccess.plaintext;
        }

        throw new Error('Unable to decrypt payload with any known IV scheme');
    }

    /**
     * Encrypt a plaintext message body, matching the negotiated IV scheme.
     * @param {Buffer} plaintext
     * @returns {Buffer} ciphertext
     */
    encrypt(plaintext) {
        if (!this._sharedKey) throw new Error('Encryption key not established');
        const scheme = this._ivScheme || 'zero';
        if (scheme === 'prepend') {
            const iv = crypto.randomBytes(16);
            return Buffer.concat([iv, this._encryptCbc(plaintext, iv)]);
        }
        return this._encryptCbc(plaintext, Buffer.alloc(16));
    }
}

module.exports = {
    OAKLEY_PRIME_768,
    OAKLEY_GENERATOR,
    EncryptionContext
};
