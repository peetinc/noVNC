/* eslint-disable comma-spacing */

// AES-128 S-box
const SBOX = new Uint8Array([
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]);

// AES-128 Inverse S-box
const INV_SBOX = new Uint8Array([
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
]);

// Round constant
const RCON = new Uint8Array([
    0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,
]);

// Precomputed MixColumns lookup tables for encryption
const T0 = new Uint32Array(256);
const T1 = new Uint32Array(256);
const T2 = new Uint32Array(256);
const T3 = new Uint32Array(256);

// Precomputed InvMixColumns lookup tables for decryption
const IT0 = new Uint32Array(256);
const IT1 = new Uint32Array(256);
const IT2 = new Uint32Array(256);
const IT3 = new Uint32Array(256);

function xtime(a) { return ((a << 1) ^ (((a >>> 7) & 1) * 0x1b)) & 0xff; }

(function initTables() {
    for (let i = 0; i < 256; i++) {
        const s = SBOX[i];
        const s2 = xtime(s);
        const s3 = s2 ^ s;
        // Encryption: [2,1,1,3] column
        T0[i] = (s2 << 24) | (s << 16) | (s << 8) | s3;
        T1[i] = (s3 << 24) | (s2 << 16) | (s << 8) | s;
        T2[i] = (s << 24) | (s3 << 16) | (s2 << 8) | s;
        T3[i] = (s << 24) | (s << 16) | (s3 << 8) | s2;

        const si = INV_SBOX[i];
        const si2 = xtime(si);
        const si4 = xtime(si2);
        const si8 = xtime(si4);
        const si9 = si8 ^ si;
        const sib = si8 ^ si2 ^ si;
        const sid = si8 ^ si4 ^ si;
        const sie = si8 ^ si4 ^ si2;
        // Decryption: [14,9,13,11] column
        IT0[i] = (sie << 24) | (si9 << 16) | (sid << 8) | sib;
        IT1[i] = (sib << 24) | (sie << 16) | (si9 << 8) | sid;
        IT2[i] = (sid << 24) | (sib << 16) | (sie << 8) | si9;
        IT3[i] = (si9 << 24) | (sid << 16) | (sib << 8) | sie;
    }
})();

/* eslint-enable comma-spacing */

// Pure-JS AES-128 block cipher (synchronous)
class AES128 {
    constructor(keyBytes) {
        // Key expansion: 16 bytes -> 44 u32 round keys (11 round keys x 4 words)
        this._encKey = new Uint32Array(44);
        this._decKey = new Uint32Array(44);

        // Load key as 4 big-endian words
        const k = this._encKey;
        for (let i = 0; i < 4; i++) {
            k[i] = (keyBytes[4 * i] << 24) | (keyBytes[4 * i + 1] << 16) |
                   (keyBytes[4 * i + 2] << 8) | keyBytes[4 * i + 3];
        }

        // Expand
        for (let i = 4; i < 44; i++) {
            let t = k[i - 1];
            if (i % 4 === 0) {
                // RotWord + SubWord + Rcon
                t = (SBOX[(t >>> 16) & 0xff] << 24) |
                    (SBOX[(t >>> 8) & 0xff] << 16) |
                    (SBOX[t & 0xff] << 8) |
                    SBOX[(t >>> 24) & 0xff];
                t ^= (RCON[(i / 4) - 1] << 24);
            }
            k[i] = k[i - 4] ^ t;
        }

        // Decryption round keys = encryption round keys with InvMixColumns
        // (except first and last rounds)
        const dk = this._decKey;
        // First round key same
        for (let i = 0; i < 4; i++) dk[i] = k[i];
        // Middle rounds: apply InvMixColumns
        for (let i = 4; i < 40; i++) {
            const w = k[i];
            const b0 = (w >>> 24) & 0xff;
            const b1 = (w >>> 16) & 0xff;
            const b2 = (w >>> 8) & 0xff;
            const b3 = w & 0xff;
            dk[i] = IT0[SBOX[b0]] ^ IT1[SBOX[b1]] ^ IT2[SBOX[b2]] ^ IT3[SBOX[b3]];
        }
        // Last round key same
        for (let i = 40; i < 44; i++) dk[i] = k[i];
    }

    encryptBlock(block) {
        const out = new Uint8Array(16);
        const k = this._encKey;

        // Load input as 4 big-endian words, XOR with first round key
        let s0 = ((block[0] << 24) | (block[1] << 16) | (block[2] << 8) | block[3]) ^ k[0];
        let s1 = ((block[4] << 24) | (block[5] << 16) | (block[6] << 8) | block[7]) ^ k[1];
        let s2 = ((block[8] << 24) | (block[9] << 16) | (block[10] << 8) | block[11]) ^ k[2];
        let s3 = ((block[12] << 24) | (block[13] << 16) | (block[14] << 8) | block[15]) ^ k[3];

        let t0, t1, t2, t3;
        // Rounds 1..9 (T-table based)
        for (let r = 1; r < 10; r++) {
            const ki = r * 4;
            t0 = T0[(s0 >>> 24) & 0xff] ^ T1[(s1 >>> 16) & 0xff] ^ T2[(s2 >>> 8) & 0xff] ^ T3[s3 & 0xff] ^ k[ki];
            t1 = T0[(s1 >>> 24) & 0xff] ^ T1[(s2 >>> 16) & 0xff] ^ T2[(s3 >>> 8) & 0xff] ^ T3[s0 & 0xff] ^ k[ki + 1];
            t2 = T0[(s2 >>> 24) & 0xff] ^ T1[(s3 >>> 16) & 0xff] ^ T2[(s0 >>> 8) & 0xff] ^ T3[s1 & 0xff] ^ k[ki + 2];
            t3 = T0[(s3 >>> 24) & 0xff] ^ T1[(s0 >>> 16) & 0xff] ^ T2[(s1 >>> 8) & 0xff] ^ T3[s2 & 0xff] ^ k[ki + 3];
            s0 = t0; s1 = t1; s2 = t2; s3 = t3;
        }

        // Final round (SubBytes + ShiftRows + AddRoundKey, no MixColumns)
        t0 = ((SBOX[(s0 >>> 24) & 0xff] << 24) | (SBOX[(s1 >>> 16) & 0xff] << 16) |
              (SBOX[(s2 >>> 8) & 0xff] << 8) | SBOX[s3 & 0xff]) ^ k[40];
        t1 = ((SBOX[(s1 >>> 24) & 0xff] << 24) | (SBOX[(s2 >>> 16) & 0xff] << 16) |
              (SBOX[(s3 >>> 8) & 0xff] << 8) | SBOX[s0 & 0xff]) ^ k[41];
        t2 = ((SBOX[(s2 >>> 24) & 0xff] << 24) | (SBOX[(s3 >>> 16) & 0xff] << 16) |
              (SBOX[(s0 >>> 8) & 0xff] << 8) | SBOX[s1 & 0xff]) ^ k[42];
        t3 = ((SBOX[(s3 >>> 24) & 0xff] << 24) | (SBOX[(s0 >>> 16) & 0xff] << 16) |
              (SBOX[(s1 >>> 8) & 0xff] << 8) | SBOX[s2 & 0xff]) ^ k[43];

        // Store output as big-endian
        out[0] = (t0 >>> 24) & 0xff; out[1] = (t0 >>> 16) & 0xff;
        out[2] = (t0 >>> 8) & 0xff;  out[3] = t0 & 0xff;
        out[4] = (t1 >>> 24) & 0xff; out[5] = (t1 >>> 16) & 0xff;
        out[6] = (t1 >>> 8) & 0xff;  out[7] = t1 & 0xff;
        out[8] = (t2 >>> 24) & 0xff; out[9] = (t2 >>> 16) & 0xff;
        out[10] = (t2 >>> 8) & 0xff; out[11] = t2 & 0xff;
        out[12] = (t3 >>> 24) & 0xff; out[13] = (t3 >>> 16) & 0xff;
        out[14] = (t3 >>> 8) & 0xff; out[15] = t3 & 0xff;
        return out;
    }

    decryptBlock(block) {
        const out = new Uint8Array(16);
        const k = this._decKey;
        const ek = this._encKey;

        // Load input, XOR with last encryption round key
        let s0 = ((block[0] << 24) | (block[1] << 16) | (block[2] << 8) | block[3]) ^ ek[40];
        let s1 = ((block[4] << 24) | (block[5] << 16) | (block[6] << 8) | block[7]) ^ ek[41];
        let s2 = ((block[8] << 24) | (block[9] << 16) | (block[10] << 8) | block[11]) ^ ek[42];
        let s3 = ((block[12] << 24) | (block[13] << 16) | (block[14] << 8) | block[15]) ^ ek[43];

        let t0, t1, t2, t3;
        // Rounds 9..1 (InvShiftRows built into column indices)
        for (let r = 9; r > 0; r--) {
            const ki = r * 4;
            t0 = IT0[(s0 >>> 24) & 0xff] ^ IT1[(s3 >>> 16) & 0xff] ^ IT2[(s2 >>> 8) & 0xff] ^ IT3[s1 & 0xff] ^ k[ki];
            t1 = IT0[(s1 >>> 24) & 0xff] ^ IT1[(s0 >>> 16) & 0xff] ^ IT2[(s3 >>> 8) & 0xff] ^ IT3[s2 & 0xff] ^ k[ki + 1];
            t2 = IT0[(s2 >>> 24) & 0xff] ^ IT1[(s1 >>> 16) & 0xff] ^ IT2[(s0 >>> 8) & 0xff] ^ IT3[s3 & 0xff] ^ k[ki + 2];
            t3 = IT0[(s3 >>> 24) & 0xff] ^ IT1[(s2 >>> 16) & 0xff] ^ IT2[(s1 >>> 8) & 0xff] ^ IT3[s0 & 0xff] ^ k[ki + 3];
            s0 = t0; s1 = t1; s2 = t2; s3 = t3;
        }

        // Final round (InvSubBytes + InvShiftRows + AddRoundKey, no InvMixColumns)
        t0 = ((INV_SBOX[(s0 >>> 24) & 0xff] << 24) | (INV_SBOX[(s3 >>> 16) & 0xff] << 16) |
              (INV_SBOX[(s2 >>> 8) & 0xff] << 8) | INV_SBOX[s1 & 0xff]) ^ ek[0];
        t1 = ((INV_SBOX[(s1 >>> 24) & 0xff] << 24) | (INV_SBOX[(s0 >>> 16) & 0xff] << 16) |
              (INV_SBOX[(s3 >>> 8) & 0xff] << 8) | INV_SBOX[s2 & 0xff]) ^ ek[1];
        t2 = ((INV_SBOX[(s2 >>> 24) & 0xff] << 24) | (INV_SBOX[(s1 >>> 16) & 0xff] << 16) |
              (INV_SBOX[(s0 >>> 8) & 0xff] << 8) | INV_SBOX[s3 & 0xff]) ^ ek[2];
        t3 = ((INV_SBOX[(s3 >>> 24) & 0xff] << 24) | (INV_SBOX[(s2 >>> 16) & 0xff] << 16) |
              (INV_SBOX[(s1 >>> 8) & 0xff] << 8) | INV_SBOX[s0 & 0xff]) ^ ek[3];

        out[0] = (t0 >>> 24) & 0xff; out[1] = (t0 >>> 16) & 0xff;
        out[2] = (t0 >>> 8) & 0xff;  out[3] = t0 & 0xff;
        out[4] = (t1 >>> 24) & 0xff; out[5] = (t1 >>> 16) & 0xff;
        out[6] = (t1 >>> 8) & 0xff;  out[7] = t1 & 0xff;
        out[8] = (t2 >>> 24) & 0xff; out[9] = (t2 >>> 16) & 0xff;
        out[10] = (t2 >>> 8) & 0xff; out[11] = t2 & 0xff;
        out[12] = (t3 >>> 24) & 0xff; out[13] = (t3 >>> 16) & 0xff;
        out[14] = (t3 >>> 8) & 0xff; out[15] = t3 & 0xff;
        return out;
    }
}

// FIPS 197 Appendix B self-test
(function selfTest() {
    /* eslint-disable comma-spacing */
    const key = new Uint8Array([0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                                0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c]);
    const pt  = new Uint8Array([0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,
                                0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34]);
    const ct  = new Uint8Array([0x39,0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,
                                0xdc,0x11,0x85,0x97,0x19,0x6a,0x0b,0x32]);
    /* eslint-enable comma-spacing */
    const aes = new AES128(key);
    const enc = aes.encryptBlock(pt);
    const dec = aes.decryptBlock(ct);
    let ok = true;
    for (let i = 0; i < 16; i++) {
        if (enc[i] !== ct[i] || dec[i] !== pt[i]) { ok = false; break; }
    }
    if (!ok) {
        /* eslint-disable no-console */
        console.error("AES-128 SELF-TEST FAILED!",
                      "enc=", Array.from(enc).map(b => b.toString(16).padStart(2, '0')).join(''),
                      "expected=", Array.from(ct).map(b => b.toString(16).padStart(2, '0')).join(''),
                      "dec=", Array.from(dec).map(b => b.toString(16).padStart(2, '0')).join(''),
                      "expected=", Array.from(pt).map(b => b.toString(16).padStart(2, '0')).join(''));
        /* eslint-enable no-console */
    }
})();

// Synchronous AES-128-ECB wrapper
export class AES128ECB {
    constructor() {
        this._cipher = null;
    }

    get algorithm() {
        return { name: "AES-128-ECB" };
    }

    static importKey(key, _algorithm, _extractable, _keyUsages) {
        const cipher = new AES128ECB;
        cipher._importKey(key);
        return cipher;
    }

    _importKey(key) {
        this._cipher = new AES128(key);
    }

    encrypt(_algorithm, plaintext) {
        const x = new Uint8Array(plaintext);
        if (x.length % 16 !== 0 || this._cipher === null) {
            return null;
        }
        const n = x.length / 16;
        for (let i = 0; i < n; i++) {
            x.set(this._cipher.encryptBlock(x.slice(i * 16, i * 16 + 16)), i * 16);
        }
        return x;
    }

    decrypt(_algorithm, ciphertext) {
        const x = new Uint8Array(ciphertext);
        if (x.length % 16 !== 0 || this._cipher === null) {
            return null;
        }
        const n = x.length / 16;
        for (let i = 0; i < n; i++) {
            x.set(this._cipher.decryptBlock(x.slice(i * 16, i * 16 + 16)), i * 16);
        }
        return x;
    }
}

export class AESECBCipher {
    constructor() {
        this._key = null;
    }

    get algorithm() {
        return { name: "AES-ECB" };
    }

    static async importKey(key, _algorithm, extractable, keyUsages) {
        const cipher = new AESECBCipher;
        await cipher._importKey(key, extractable, keyUsages);
        return cipher;
    }

    async _importKey(key, extractable, keyUsages) {
        this._key = await window.crypto.subtle.importKey(
            "raw", key, {name: "AES-CBC"}, extractable, keyUsages);
    }

    async encrypt(_algorithm, plaintext) {
        const x = new Uint8Array(plaintext);
        if (x.length % 16 !== 0 || this._key === null) {
            return null;
        }
        const n = x.length / 16;
        for (let i = 0; i < n; i++) {
            const y = new Uint8Array(await window.crypto.subtle.encrypt({
                name: "AES-CBC",
                iv: new Uint8Array(16),
            }, this._key, x.slice(i * 16, i * 16 + 16))).slice(0, 16);
            x.set(y, i * 16);
        }
        return x;
    }
}

export class AESEAXCipher {
    constructor() {
        this._rawKey = null;
        this._ctrKey = null;
        this._cbcKey = null;
        this._zeroBlock = new Uint8Array(16);
        this._prefixBlock0 = this._zeroBlock;
        this._prefixBlock1 = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        this._prefixBlock2 = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    }

    get algorithm() {
        return { name: "AES-EAX" };
    }

    async _encryptBlock(block) {
        const encrypted = await window.crypto.subtle.encrypt({
            name: "AES-CBC",
            iv: this._zeroBlock,
        }, this._cbcKey, block);
        return new Uint8Array(encrypted).slice(0, 16);
    }

    async _initCMAC() {
        const k1 = await this._encryptBlock(this._zeroBlock);
        const k2 = new Uint8Array(16);
        const v = k1[0] >>> 6;
        for (let i = 0; i < 15; i++) {
            k2[i] = (k1[i + 1] >> 6) | (k1[i] << 2);
            k1[i] = (k1[i + 1] >> 7) | (k1[i] << 1);
        }
        const lut = [0x0, 0x87, 0x0e, 0x89];
        k2[14] ^= v >>> 1;
        k2[15] = (k1[15] << 2) ^ lut[v];
        k1[15] = (k1[15] << 1) ^ lut[v >> 1];
        this._k1 = k1;
        this._k2 = k2;
    }

    async _encryptCTR(data, counter) {
        const encrypted = await window.crypto.subtle.encrypt({
            name: "AES-CTR",
            counter: counter,
            length: 128
        }, this._ctrKey, data);
        return new Uint8Array(encrypted);
    }

    async _decryptCTR(data, counter) {
        const decrypted = await window.crypto.subtle.decrypt({
            name: "AES-CTR",
            counter: counter,
            length: 128
        }, this._ctrKey, data);
        return new Uint8Array(decrypted);
    }

    async _computeCMAC(data, prefixBlock) {
        if (prefixBlock.length !== 16) {
            return null;
        }
        const n = Math.floor(data.length / 16);
        const m = Math.ceil(data.length / 16);
        const r = data.length - n * 16;
        const cbcData = new Uint8Array((m + 1) * 16);
        cbcData.set(prefixBlock);
        cbcData.set(data, 16);
        if (r === 0) {
            for (let i = 0; i < 16; i++) {
                cbcData[n * 16 + i] ^= this._k1[i];
            }
        } else {
            cbcData[(n + 1) * 16 + r] = 0x80;
            for (let i = 0; i < 16; i++) {
                cbcData[(n + 1) * 16 + i] ^= this._k2[i];
            }
        }
        let cbcEncrypted = await window.crypto.subtle.encrypt({
            name: "AES-CBC",
            iv: this._zeroBlock,
        }, this._cbcKey, cbcData);

        cbcEncrypted = new Uint8Array(cbcEncrypted);
        const mac = cbcEncrypted.slice(cbcEncrypted.length - 32, cbcEncrypted.length - 16);
        return mac;
    }

    static async importKey(key, _algorithm, _extractable, _keyUsages) {
        const cipher = new AESEAXCipher;
        await cipher._importKey(key);
        return cipher;
    }

    async _importKey(key) {
        this._rawKey = key;
        this._ctrKey = await window.crypto.subtle.importKey(
            "raw", key, {name: "AES-CTR"}, false, ["encrypt", "decrypt"]);
        this._cbcKey = await window.crypto.subtle.importKey(
            "raw", key, {name: "AES-CBC"}, false, ["encrypt"]);
        await this._initCMAC();
    }

    async encrypt(algorithm, message) {
        const ad = algorithm.additionalData;
        const nonce = algorithm.iv;
        const nCMAC = await this._computeCMAC(nonce, this._prefixBlock0);
        const encrypted = await this._encryptCTR(message, nCMAC);
        const adCMAC = await this._computeCMAC(ad, this._prefixBlock1);
        const mac = await this._computeCMAC(encrypted, this._prefixBlock2);
        for (let i = 0; i < 16; i++) {
            mac[i] ^= nCMAC[i] ^ adCMAC[i];
        }
        const res = new Uint8Array(16 + encrypted.length);
        res.set(encrypted);
        res.set(mac, encrypted.length);
        return res;
    }

    async decrypt(algorithm, data) {
        const encrypted = data.slice(0, data.length - 16);
        const ad = algorithm.additionalData;
        const nonce = algorithm.iv;
        const mac = data.slice(data.length - 16);
        const nCMAC = await this._computeCMAC(nonce, this._prefixBlock0);
        const adCMAC = await this._computeCMAC(ad, this._prefixBlock1);
        const computedMac = await this._computeCMAC(encrypted, this._prefixBlock2);
        for (let i = 0; i < 16; i++) {
            computedMac[i] ^= nCMAC[i] ^ adCMAC[i];
        }
        if (computedMac.length !== mac.length) {
            return null;
        }
        for (let i = 0; i < mac.length; i++) {
            if (computedMac[i] !== mac[i]) {
                return null;
            }
        }
        const res = await this._decryptCTR(encrypted, nCMAC);
        return res;
    }
}
