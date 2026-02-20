/*
 * noVNC: HTML5 VNC client
 * Copyright (C) 2024 The noVNC authors
 * Licensed under MPL 2.0 (see LICENSE.txt)
 *
 * See README.md for usage and integration instructions.
 *
 * ARD ArdGray16 (encoding 1001) decoder.
 * 4-bit grayscale (16 levels), zlib compressed.
 */

import ArdZlibDecoder from "./ardzlib.js";

export default class ArdGray16Decoder extends ArdZlibDecoder {
    get _encodingName() { return "ArdGray16"; }

    _inflateSize(width, height) {
        return Math.ceil(width / 2) * height;
    }

    _convertPixels(gray4, width, height) {
        const rowBytes = Math.ceil(width / 2);
        const pixels = new Uint8Array(width * height * 4);
        let pIdx = 0;
        for (let row = 0; row < height; row++) {
            const rowOff = row * rowBytes;
            for (let col = 0; col < width; col++) {
                const byteVal = gray4[rowOff + (col >> 1)];
                const nibble = (col & 1) === 0 ? (byteVal >> 4) : (byteVal & 0x0f);
                const v = nibble * 17;  // scale 0-15 to 0-255
                pixels[pIdx++] = v;
                pixels[pIdx++] = v;
                pixels[pIdx++] = v;
                pixels[pIdx++] = 255;
            }
        }
        return pixels;
    }
}
