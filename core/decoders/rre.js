/*
 * noVNC: HTML5 VNC client
 * Copyright (C) 2019 The noVNC authors
 * Licensed under MPL 2.0 (see LICENSE.txt)
 *
 * See README.md for usage and integration instructions.
 *
 */

export default class RREDecoder {
    constructor() {
        this._subrects = 0;
        this.swapRedBlue = false;
    }

    _readColor(bytes) {
        if (this.swapRedBlue) {
            const tmp = bytes[0];
            bytes[0] = bytes[2];
            bytes[2] = tmp;
        }
        return bytes;
    }

    decodeRect(x, y, width, height, sock, display, depth) {
        if (this._subrects === 0) {
            if (sock.rQwait("RRE", 4 + 4)) {
                return false;
            }

            this._subrects = sock.rQshift32();

            let color = this._readColor(sock.rQshiftBytes(4));  // Background
            display.fillRect(x, y, width, height, color);
        }

        while (this._subrects > 0) {
            if (sock.rQwait("RRE", 4 + 8)) {
                return false;
            }

            let color = this._readColor(sock.rQshiftBytes(4));
            let sx = sock.rQshift16();
            let sy = sock.rQshift16();
            let swidth = sock.rQshift16();
            let sheight = sock.rQshift16();
            display.fillRect(x + sx, y + sy, swidth, sheight, color);

            this._subrects--;
        }

        return true;
    }
}
