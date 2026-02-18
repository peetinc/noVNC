/*
 * noVNC: HTML5 VNC client
 * Copyright (C) 2024 The noVNC authors
 * Licensed under MPL 2.0 (see LICENSE.txt)
 *
 * See README.md for usage and integration instructions.
 *
 * Synchronous SHA-1 implementation.
 */

export function SHA1(data) {
    // Pre-processing: add padding
    const msgLen = data.length;
    const bitLen = msgLen * 8;

    // Message + 1 byte (0x80) + padding + 8 bytes (length)
    // Total must be multiple of 64
    const padLen = 64 - ((msgLen + 9) % 64);
    const totalLen = msgLen + 1 + (padLen === 64 ? 0 : padLen) + 8;

    const msg = new Uint8Array(totalLen);
    msg.set(data);
    msg[msgLen] = 0x80;

    // Append bit length as big-endian 64-bit integer
    // (JavaScript bitwise ops are 32-bit, bitLen fits in 53-bit safe integer)
    const hiLen = Math.floor(bitLen / 0x100000000);
    const loLen = bitLen >>> 0;
    const dv = new DataView(msg.buffer);
    dv.setUint32(totalLen - 8, hiLen, false);
    dv.setUint32(totalLen - 4, loLen, false);

    // Initialize hash values
    let h0 = 0x67452301;
    let h1 = 0xEFCDAB89;
    let h2 = 0x98BADCFE;
    let h3 = 0x10325476;
    let h4 = 0xC3D2E1F0;

    const w = new Uint32Array(80);

    // Process each 512-bit (64-byte) block
    for (let offset = 0; offset < totalLen; offset += 64) {
        // Load 16 big-endian words
        for (let i = 0; i < 16; i++) {
            w[i] = dv.getUint32(offset + i * 4, false);
        }

        // Extend to 80 words
        for (let i = 16; i < 80; i++) {
            const t = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
            w[i] = (t << 1) | (t >>> 31);
        }

        let a = h0, b = h1, c = h2, d = h3, e = h4;

        for (let i = 0; i < 80; i++) {
            let f, k;
            if (i < 20) {
                f = (b & c) | (~b & d);
                k = 0x5A827999;
            } else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }

            const temp = (((a << 5) | (a >>> 27)) + f + e + k + w[i]) >>> 0;
            e = d;
            d = c;
            c = ((b << 30) | (b >>> 2)) >>> 0;
            b = a;
            a = temp;
        }

        h0 = (h0 + a) >>> 0;
        h1 = (h1 + b) >>> 0;
        h2 = (h2 + c) >>> 0;
        h3 = (h3 + d) >>> 0;
        h4 = (h4 + e) >>> 0;
    }

    // Output 20 bytes big-endian
    const result = new Uint8Array(20);
    const rv = new DataView(result.buffer);
    rv.setUint32(0, h0, false);
    rv.setUint32(4, h1, false);
    rv.setUint32(8, h2, false);
    rv.setUint32(12, h3, false);
    rv.setUint32(16, h4, false);
    return result;
}
