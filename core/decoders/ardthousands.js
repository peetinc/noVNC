/*
 * noVNC: HTML5 VNC client
 * Copyright (C) 2024 The noVNC authors
 * Licensed under MPL 2.0 (see LICENSE.txt)
 *
 * See README.md for usage and integration instructions.
 *
 * ARD ArdThousands (encoding 1002) decoder.
 * 16-bit RGB555, zlib compressed.
 */

import ArdZlibDecoder from "./ardzlib.js";

export default class ArdThousandsDecoder extends ArdZlibDecoder {
    get _encodingName() { return "ArdThousands"; }

    _inflateSize(width, height) {
        return width * height * 2;
    }

    _convertPixels(rgb555, width, height) {
        const pixels = new Uint8Array(width * height * 4);
        let pIdx = 0;
        for (let i = 0; i < width * height; i++) {
            const word = (rgb555[i * 2] << 8) | rgb555[i * 2 + 1];
            const r = (word >> 10) & 0x1f;
            const g = (word >> 5) & 0x1f;
            const b = word & 0x1f;
            // Scale 5-bit (0-31) to 8-bit (0-255)
            pixels[pIdx++] = (r << 3) | (r >> 2);
            pixels[pIdx++] = (g << 3) | (g >> 2);
            pixels[pIdx++] = (b << 3) | (b >> 2);
            pixels[pIdx++] = 255;
        }
        return pixels;
    }
}
