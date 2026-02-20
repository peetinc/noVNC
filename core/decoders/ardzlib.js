/*
 * noVNC: HTML5 VNC client
 * Copyright (C) 2024 The noVNC authors
 * Licensed under MPL 2.0 (see LICENSE.txt)
 *
 * See README.md for usage and integration instructions.
 *
 * Base class for ARD zlib-compressed decoders (encodings 1000-1002).
 * Handles the common framing: [u32 compressedLength][zlib data].
 * Subclasses implement _inflateSize() and _convertPixels().
 */

import Inflator from "../inflator.js";

export default class ArdZlibDecoder {
    constructor() {
        this._zlib = new Inflator();
        this._length = 0;
    }

    decodeRect(x, y, width, height, sock, display, _depth) {
        if ((width === 0) || (height === 0)) {
            return true;
        }

        if (this._length === 0) {
            if (sock.rQwait(this._encodingName, 4)) {
                return false;
            }
            this._length = sock.rQshift32();
        }

        if (sock.rQwait(this._encodingName, this._length)) {
            return false;
        }

        let data = new Uint8Array(sock.rQshiftBytes(this._length, false));
        this._length = 0;

        this._zlib.setInput(data);
        const inflated = this._zlib.inflate(this._inflateSize(width, height));
        this._zlib.setInput(null);

        const pixels = this._convertPixels(inflated, width, height);
        display.blitImage(x, y, width, height, pixels, 0);

        return true;
    }
}
