/*
 * noVNC: HTML5 VNC client
 * Copyright (C) 2024 The noVNC authors
 * Licensed under MPL 2.0 (see LICENSE.txt)
 *
 * See README.md for usage and integration instructions.
 *
 * ARD ArdHalftone (encoding 1000) decoder.
 * 1-bit monochrome (halftone dithered), zlib compressed.
 */

import ArdZlibDecoder from "./ardzlib.js";

export default class ArdHalftoneDecoder extends ArdZlibDecoder {
    get _encodingName() { return "ArdHalftone"; }

    _inflateSize(width, height) {
        return Math.ceil(width / 8) * height;
    }

    _convertPixels(mono, width, height) {
        const rowBytes = Math.ceil(width / 8);
        const pixels = new Uint8Array(width * height * 4);
        let pIdx = 0;
        for (let row = 0; row < height; row++) {
            const rowOff = row * rowBytes;
            for (let col = 0; col < width; col++) {
                const bit = (mono[rowOff + (col >> 3)] >> (7 - (col & 7))) & 1;
                const v = bit ? 255 : 0;
                pixels[pIdx++] = v;
                pixels[pIdx++] = v;
                pixels[pIdx++] = v;
                pixels[pIdx++] = 255;
            }
        }
        return pixels;
    }
}
