/*
 * noVNC: HTML5 VNC client
 * Copyright (C) 2020 The noVNC authors
 * Licensed under MPL 2.0 (see LICENSE.txt)
 *
 * See README.md for usage and integration instructions.
 *
 */

import { toUnsigned32bit, toSigned32bit } from './util/int.js';
import * as Log from './util/logging.js';
import { encodeUTF8, decodeUTF8 } from './util/strings.js';
import { dragThreshold, supportsWebCodecsH264Decode } from './util/browser.js';
import { clientToElement } from './util/element.js';
import { setCapture } from './util/events.js';
import EventTargetMixin from './util/eventtarget.js';
import Display from "./display.js";
import AsyncClipboard from "./clipboard.js";
import Inflator from "./inflator.js";
import Deflator from "./deflator.js";
import Keyboard from "./input/keyboard.js";
import GestureHandler from "./input/gesturehandler.js";
import Cursor from "./util/cursor.js";
import Websock from "./websock.js";
import KeyTable from "./input/keysym.js";
import XtScancode from "./input/xtscancodes.js";
import { encodings } from "./encodings.js";
import RSAAESAuthenticationState from "./ra2.js";
import legacyCrypto from "./crypto/crypto.js";
import { RSACipher } from "./crypto/rsa.js";
import { AES128ECB, AES128CBC } from "./crypto/aes.js";
import { SHA1 } from "./crypto/sha1.js";

import RawDecoder from "./decoders/raw.js";
import CopyRectDecoder from "./decoders/copyrect.js";
import RREDecoder from "./decoders/rre.js";
import HextileDecoder from "./decoders/hextile.js";
import ZlibDecoder from './decoders/zlib.js';
import TightDecoder from "./decoders/tight.js";
import TightPNGDecoder from "./decoders/tightpng.js";
import ZRLEDecoder from "./decoders/zrle.js";
import JPEGDecoder from "./decoders/jpeg.js";
import H264Decoder from "./decoders/h264.js";
import ArdHalftoneDecoder from "./decoders/ardhalftone.js";
import ArdGray16Decoder from "./decoders/ardgray16.js";
import ArdThousandsDecoder from "./decoders/ardthousands.js";

// How many seconds to wait for a disconnect to finish
const DISCONNECT_TIMEOUT = 3;
const DEFAULT_BACKGROUND = 'rgb(40, 40, 40)';

// Minimum wait (ms) between two mouse moves
const MOUSE_MOVE_DELAY = 17;

// Wheel thresholds
const WHEEL_STEP = 50; // Pixels needed for one step
const WHEEL_LINE_HEIGHT = 19; // Assumed pixels for one line step

// Gesture thresholds
const GESTURE_ZOOMSENS = 75;
const GESTURE_SCRLSENS = 50;
const DOUBLE_TAP_TIMEOUT = 1000;
const DOUBLE_TAP_THRESHOLD = 50;

// Security types
const securityTypeNone              = 1;
const securityTypeVNCAuth           = 2;
const securityTypeRA2ne             = 6;
const securityTypeTight             = 16;
const securityTypeVeNCrypt          = 19;
const securityTypeXVP               = 22;
const securityTypeARD               = 30;
const securityTypeRSATunnel         = 33;
const securityTypeMSLogonII         = 113;

// Special Tight security types
const securityTypeUnixLogon         = 129;

// VeNCrypt security types
const securityTypePlain             = 256;

// Extended clipboard pseudo-encoding formats
const extendedClipboardFormatText   = 1;
/*eslint-disable no-unused-vars */
const extendedClipboardFormatRtf    = 1 << 1;
const extendedClipboardFormatHtml   = 1 << 2;
const extendedClipboardFormatDib    = 1 << 3;
const extendedClipboardFormatFiles  = 1 << 4;
/*eslint-enable */

// Extended clipboard pseudo-encoding actions
const extendedClipboardActionCaps    = 1 << 24;
const extendedClipboardActionRequest = 1 << 25;
const extendedClipboardActionPeek    = 1 << 26;
const extendedClipboardActionNotify  = 1 << 27;
const extendedClipboardActionProvide = 1 << 28;

export default class RFB extends EventTargetMixin {
    constructor(target, urlOrChannel, options) {
        if (!target) {
            throw new Error("Must specify target");
        }
        if (!urlOrChannel) {
            throw new Error("Must specify URL, WebSocket or RTCDataChannel");
        }

        // We rely on modern APIs which might not be available in an
        // insecure context
        if (!window.isSecureContext) {
            Log.Error("noVNC requires a secure context (TLS). Expect crashes!");
        }

        super();

        this._target = target;

        if (typeof urlOrChannel === "string") {
            this._url = urlOrChannel;
        } else {
            this._url = null;
            this._rawChannel = urlOrChannel;
        }

        // Connection details
        options = options || {};
        this._rfbCredentials = options.credentials || {};
        this._shared = 'shared' in options ? !!options.shared : true;
        this._repeaterID = options.repeaterID || '';
        this._wsProtocols = options.wsProtocols || [];

        // Internal state
        this._rfbConnectionState = '';
        this._rfbInitState = '';
        this._rfbAuthScheme = -1;
        this._rfbCleanDisconnect = true;
        this._rfbRSAAESAuthenticationState = null;

        // Server capabilities
        this._rfbVersion = 0;
        this._rfbMaxVersion = 3.8;
        this._rfbTightVNC = false;
        this._rfbAppleARD = false;
        this._ardDHKey = null;
        this._ardECBCipher = null;
        this._ardSessionKey = null;
        this._ardSessionIV = null;
        this._ardPendingEncryption = false;
        this._ardEncryptionEnabled = false;
        this._ardRSATunnelStage = 0;
        this._ardRSAServerKey = null;
        this._ardQualityPreset = 'thousands';
        this._ardClipboardSessionId = 0;
        this._ardControlMode = 1;               // 0=Observe, 1=Control, 2=Exclusive
        this._ardCurtainActive = false;         // whether curtain is currently engaged
        this._ardCurtainMessage = '';           // default curtain message (empty = server default)
        this._ardConsoleActive = false;         // true = user at active session; false = lock/login screen
        this._ardUsername = '';                 // logged-in username, empty = login window
        this._ardUserAvatarPng = null;          // cached avatar PNG (BGRA, may be null)
        this._ardClipboardSyncEnabled = true;  // mirrors init AutoPasteboard(1)
        this._ardClipboardManualRequest = false; // one-shot: honour reply even when sync off
        this._ardLastClipboardSent = null;
        this._ardLastClipboardRecv = null;
        this._ardCursorCache = {};       // cursor image cache (id → {rgba, hotx, hoty, w, h})
        this._ardCursorUrlCache = {};    // cursor CSS URL cache (id → css string)
        this._ardCursorZlib = new Inflator();  // zlib for cursor data (reset per image)
        this._ardActiveCursor = null;    // {type:'system'|'custom', id}
        this._ardGotCursor = false;      // track if cursor data received in first FBU
        this._ardDisplays = [];            // per-display geometry from DisplayInfo/DisplayInfo2
        this._ardCombineAllDisplays = 1;   // 1=All displays (combined view)
        this._ardSelectedDisplayId = 0;    // 0=no specific display (All)
        this._ardCombinedFbWidth = 0;      // combined desktop width (from DisplayInfo2 header)
        this._ardCombinedFbHeight = 0;     // combined desktop height (from DisplayInfo2 header)
        this._ardFirstDisplayInfo = true;  // first DisplayInfo2 needs double-tap
        this._ardPhase3Pending = false;    // waiting for echo DI2 before FBUpdateRequest
        this._ardLastClipboardReqTime = 0;
        this._ardLastFbuTime = 0;          // ms timestamp of last completed FBU
        this._ardTickleCount = 0;          // Tickles received since last FBU
        this._ardPrevCombinedW = 0;
        this._ardPrevCombinedH = 0;
        this._ardPrevDisplayCount = 0;
        this._ardSessionSelectNeeded = false;  // Session Select required before FBUs
        this._ardSessionSelectConsoleUser = ''; // User currently at console
        this._rfbVeNCryptState = 0;
        this._rfbXvpVer = 0;

        this._fbWidth = 0;
        this._fbHeight = 0;

        this._fbName = "";

        this._capabilities = { power: false };

        this._supportsFence = false;

        this._supportsContinuousUpdates = false;
        this._enabledContinuousUpdates = false;

        this._supportsSetDesktopSize = false;
        this._screenID = 0;
        this._screenFlags = 0;
        this._pendingRemoteResize = false;
        this._lastResize = 0;

        this._qemuExtKeyEventSupported = false;

        this._extendedPointerEventSupported = false;

        this._clipboardText = null;
        this._clipboardServerCapabilitiesActions = {};
        this._clipboardServerCapabilitiesFormats = {};

        // Internal objects
        this._sock = null;              // Websock object
        this._display = null;           // Display object
        this._flushing = false;         // Display flushing state
        this._asyncClipboard = null;    // Async clipboard object
        this._keyboard = null;          // Keyboard input handler object
        this._gestures = null;          // Gesture input handler object
        this._resizeObserver = null;    // Resize observer object

        // Timers
        this._disconnTimer = null;      // disconnection timer
        this._resizeTimeout = null;     // resize rate limiting
        this._mouseMoveTimer = null;
        this._authTimer = null;         // auth response timeout

        // Decoder states
        this._decoders = {};

        this._FBU = {
            rects: 0,
            x: 0,
            y: 0,
            width: 0,
            height: 0,
            encoding: null,
        };

        // Mouse state
        this._mousePos = {};
        this._mouseButtonMask = 0;
        this._mouseLastMoveTime = 0;
        this._viewportDragging = false;
        this._viewportDragPos = {};
        this._viewportHasMoved = false;
        this._accumulatedWheelDeltaX = 0;
        this._accumulatedWheelDeltaY = 0;

        // Gesture state
        this._gestureLastTapTime = null;
        this._gestureFirstDoubleTapEv = null;
        this._gestureLastMagnitudeX = 0;
        this._gestureLastMagnitudeY = 0;

        // Bound event handlers
        this._eventHandlers = {
            focusCanvas: this._focusCanvas.bind(this),
            handleResize: this._handleResize.bind(this),
            handleMouse: this._handleMouse.bind(this),
            handleWheel: this._handleWheel.bind(this),
            handleGesture: this._handleGesture.bind(this),
            handleRSAAESCredentialsRequired: this._handleRSAAESCredentialsRequired.bind(this),
            handleRSAAESServerVerification: this._handleRSAAESServerVerification.bind(this),
        };

        // main setup
        Log.Debug(">> RFB.constructor");

        // Create DOM elements
        this._screen = document.createElement('div');
        this._screen.style.display = 'flex';
        this._screen.style.width = '100%';
        this._screen.style.height = '100%';
        this._screen.style.overflow = 'auto';
        this._screen.style.background = DEFAULT_BACKGROUND;
        this._canvas = document.createElement('canvas');
        this._canvas.style.margin = 'auto';
        // Some browsers add an outline on focus
        this._canvas.style.outline = 'none';
        this._canvas.width = 0;
        this._canvas.height = 0;
        this._canvas.tabIndex = -1;
        this._screen.appendChild(this._canvas);

        // Cursor
        this._cursor = new Cursor();

        // XXX: TightVNC 2.8.11 sends no cursor at all until Windows changes
        // it. Result: no cursor at all until a window border or an edit field
        // is hit blindly. But there are also VNC servers that draw the cursor
        // in the framebuffer and don't send the empty local cursor. There is
        // no way to satisfy both sides.
        //
        // The spec is unclear on this "initial cursor" issue. Many other
        // viewers (TigerVNC, RealVNC, Remmina) display an arrow as the
        // initial cursor instead.
        this._cursorImage = RFB.cursors.none;

        // populate decoder array with objects
        this._decoders[encodings.encodingRaw] = new RawDecoder();
        this._decoders[encodings.encodingCopyRect] = new CopyRectDecoder();
        this._decoders[encodings.encodingRRE] = new RREDecoder();
        this._decoders[encodings.encodingHextile] = new HextileDecoder();
        this._decoders[encodings.encodingZlib] = new ZlibDecoder();
        this._decoders[encodings.encodingTight] = new TightDecoder();
        this._decoders[encodings.encodingTightPNG] = new TightPNGDecoder();
        this._decoders[encodings.encodingZRLE] = new ZRLEDecoder();
        this._decoders[encodings.encodingJPEG] = new JPEGDecoder();
        this._decoders[encodings.encodingH264] = new H264Decoder();
        this._decoders[encodings.encodingArdHalftone] = new ArdHalftoneDecoder();
        this._decoders[encodings.encodingArdGray16] = new ArdGray16Decoder();
        this._decoders[encodings.encodingArdThousands] = new ArdThousandsDecoder();

        // NB: nothing that needs explicit teardown should be done
        // before this point, since this can throw an exception
        try {
            this._display = new Display(this._canvas);
        } catch (exc) {
            Log.Error("Display exception: " + exc);
            throw exc;
        }

        this._asyncClipboard = new AsyncClipboard(this._canvas);
        this._asyncClipboard.onpaste = this.clipboardPasteFrom.bind(this);

        this._keyboard = new Keyboard(this._canvas);
        this._keyboard.onkeyevent = this._handleKeyEvent.bind(this);
        this._remoteCapsLock = null; // Null indicates unknown or irrelevant
        this._remoteNumLock = null;

        this._gestures = new GestureHandler();

        this._sock = new Websock();
        this._sock.on('open', this._socketOpen.bind(this));
        this._sock.on('close', this._socketClose.bind(this));
        this._sock.on('message', this._handleMessage.bind(this));
        this._sock.on('error', this._socketError.bind(this));

        this._expectedClientWidth = null;
        this._expectedClientHeight = null;
        this._resizeObserver = new ResizeObserver(this._eventHandlers.handleResize);

        // All prepared, kick off the connection
        this._updateConnectionState('connecting');

        Log.Debug("<< RFB.constructor");

        // ===== PROPERTIES =====

        this.dragViewport = false;
        this.focusOnClick = true;

        this._viewOnly = false;
        this._clipViewport = false;
        this._clippingViewport = false;
        this._scaleViewport = false;
        this._resizeSession = false;

        this._showDotCursor = false;

        this._qualityLevel = 6;
        this._compressionLevel = 2;
    }

    // ===== PROPERTIES =====

    get viewOnly() { return this._viewOnly; }
    set viewOnly(viewOnly) {
        this._viewOnly = viewOnly;

        if (this._rfbConnectionState === "connecting" ||
            this._rfbConnectionState === "connected") {
            if (viewOnly) {
                this._keyboard.ungrab();
                this._asyncClipboard.ungrab();
            } else {
                this._keyboard.grab();
                this._asyncClipboard.grab();
            }
        }
    }

    // ARD control mode: 0=Observe (view-only), 1=Control (shared), 2=Exclusive.
    // Observe suppresses all input from this client; the local user retains control.
    // Exclusive blocks the local user's input; the remote screen remains visible.
    // Control allows both viewer and local user to interact simultaneously.
    // Setting this on a connected ARD session sends SetMode immediately.
    get ardControlMode() { return this._ardControlMode; }
    set ardControlMode(mode) {
        if (mode !== 0 && mode !== 1 && mode !== 2) {
            throw new Error("ardControlMode must be 0 (Observe), 1 (Control), or 2 (Exclusive)");
        }
        this._ardControlMode = mode;
        // Observe suppresses viewer input — drive viewOnly so keyboard/clipboard
        // grabs and all existing _viewOnly guards are handled automatically.
        this.viewOnly = (mode === 0);
        if (this._rfbConnectionState === 'connected' && this._rfbAppleARD) {
            this._sendArdSetMode(mode);
            this._sock.flush();
            Log.Info("ARD: control mode → " + ['Observe', 'Control', 'Exclusive'][mode]);
        }
    }

    // Whether the curtain (screen blank) is currently active on the remote Mac.
    get ardCurtainActive() { return this._ardCurtainActive; }

    // Default message shown on the curtained screen when ardCurtainLock() is
    // called without an explicit message argument.  The ARD convention is:
    //   "curtain\r\rScreen locked by <username>"
    // where \r\r separates the title from the body.  An empty string causes
    // the server to display its own default curtain screen.
    get ardCurtainMessage() { return this._ardCurtainMessage; }
    set ardCurtainMessage(msg) { this._ardCurtainMessage = String(msg); }

    // Username of the currently logged-in user on the remote Mac.
    // Empty string means the login window is shown (no user at console).
    get ardUsername() { return this._ardUsername; }

    // True when a user is actively at the console (desktop unlocked).
    // False when the remote Mac is at the login window or lock screen.
    // Derived from DI2 global flags bit 3 (0x08): set = locked/login window.
    get ardConsoleActive() { return this._ardConsoleActive; }

    // Engage curtain mode: blanks the remote Mac's physical displays.
    // message (optional): text to display on the curtained screen.  Falls
    // back to ardCurtainMessage, then to an empty string (server default).
    ardCurtainLock(message) {
        if (this._rfbConnectionState !== 'connected' || !this._rfbAppleARD) return;
        const text = (message !== undefined) ? String(message) : this._ardCurtainMessage;
        // Protocol requires "curtain\r\r" prefix before the display message.
        // An empty message sends no text (server shows its default curtain screen).
        const payload = text ? ('curtain\r\r' + text) : '';
        this._ardCurtainActive = true;
        this._sendArdSessionVisibility(false, payload);
        this._sock.flush();
        Log.Info("ARD: curtain engaged" + (text ? ' ("' + text.substring(0, 40) + '")' : ''));
        this.dispatchEvent(new CustomEvent('ardcurtainchange',
            { detail: { active: true } }));
    }

    // Disengage curtain mode: restores the remote Mac's physical displays.
    ardCurtainUnlock() {
        if (this._rfbConnectionState !== 'connected' || !this._rfbAppleARD) return;
        this._ardCurtainActive = false;
        this._sendArdSessionVisibility(true, '');
        this._sock.flush();
        Log.Info("ARD: curtain disengaged");
        this.dispatchEvent(new CustomEvent('ardcurtainchange',
            { detail: { active: false } }));
    }

    get capabilities() { return this._capabilities; }

    get clippingViewport() { return this._clippingViewport; }
    _setClippingViewport(on) {
        if (on === this._clippingViewport) {
            return;
        }
        this._clippingViewport = on;
        this.dispatchEvent(new CustomEvent("clippingviewport",
                                           { detail: this._clippingViewport }));
    }

    get touchButton() { return 0; }
    set touchButton(button) { Log.Warn("Using old API!"); }

    get clipViewport() { return this._clipViewport; }
    set clipViewport(viewport) {
        this._clipViewport = viewport;
        this._updateClip();
    }

    get scaleViewport() { return this._scaleViewport; }
    set scaleViewport(scale) {
        this._scaleViewport = scale;
        // Scaling trumps clipping, so we may need to adjust
        // clipping when enabling or disabling scaling
        if (scale && this._clipViewport) {
            this._updateClip();
        }
        this._updateScale();
        if (!scale && this._clipViewport) {
            this._updateClip();
        }
    }

    get resizeSession() { return this._resizeSession; }
    set resizeSession(resize) {
        this._resizeSession = resize;
        if (resize) {
            this._requestRemoteResize();
        }
    }

    get showDotCursor() { return this._showDotCursor; }
    set showDotCursor(show) {
        this._showDotCursor = show;
        this._refreshCursor();
    }

    get background() { return this._screen.style.background; }
    set background(cssValue) { this._screen.style.background = cssValue; }

    get qualityLevel() {
        return this._qualityLevel;
    }
    set qualityLevel(qualityLevel) {
        if (!Number.isInteger(qualityLevel) || qualityLevel < 0 || qualityLevel > 9) {
            Log.Error("qualityLevel must be an integer between 0 and 9");
            return;
        }

        if (this._qualityLevel === qualityLevel) {
            return;
        }

        this._qualityLevel = qualityLevel;

        if (this._rfbConnectionState === 'connected') {
            this._sendEncodings();
        }
    }

    get qualityPreset() { return this._ardQualityPreset; }
    set qualityPreset(preset) {
        const validPresets = ['halftone', 'gray', 'thousands', 'millions'];
        if (!validPresets.includes(preset)) {
            Log.Error("qualityPreset must be one of: " + validPresets.join(', '));
            return;
        }
        if (this._ardQualityPreset === preset) {
            return;
        }
        this._ardQualityPreset = preset;
        if (this._rfbConnectionState === 'connected' && this._rfbAppleARD) {
            this._sendEncodings();
            this._sendArdSetDisplay();
            this._requestArdFullUpdate(this._fbWidth, this._fbHeight);
        }
    }

    get compressionLevel() {
        return this._compressionLevel;
    }
    set compressionLevel(compressionLevel) {
        if (!Number.isInteger(compressionLevel) || compressionLevel < 0 || compressionLevel > 9) {
            Log.Error("compressionLevel must be an integer between 0 and 9");
            return;
        }

        if (this._compressionLevel === compressionLevel) {
            return;
        }

        this._compressionLevel = compressionLevel;

        if (this._rfbConnectionState === 'connected') {
            this._sendEncodings();
        }
    }

    // ===== PUBLIC METHODS =====

    disconnect() {
        this._updateConnectionState('disconnecting');
        this._sock.off('error');
        this._sock.off('message');
        this._sock.off('open');
        if (this._rfbRSAAESAuthenticationState !== null) {
            this._rfbRSAAESAuthenticationState.disconnect();
        }
    }

    approveServer() {
        if (this._rfbRSAAESAuthenticationState !== null) {
            this._rfbRSAAESAuthenticationState.approveServer();
        }
    }

    sendCredentials(creds) {
        this._rfbCredentials = creds;
        this._resumeAuthentication();
    }

    get isAppleARD() { return this._rfbAppleARD; }
    get ardCombineAllDisplays() { return this._ardCombineAllDisplays; }
    get ardSelectedDisplayId() { return this._ardSelectedDisplayId; }

    sendCtrlAltDel() {
        if (this._rfbConnectionState !== 'connected' || this._viewOnly) { return; }
        Log.Info("Sending Ctrl-Alt-Del");

        this.sendKey(KeyTable.XK_Control_L, "ControlLeft", true);
        this.sendKey(KeyTable.XK_Alt_L, "AltLeft", true);
        this.sendKey(KeyTable.XK_Delete, "Delete", true);
        this.sendKey(KeyTable.XK_Delete, "Delete", false);
        this.sendKey(KeyTable.XK_Alt_L, "AltLeft", false);
        this.sendKey(KeyTable.XK_Control_L, "ControlLeft", false);
    }

    machineShutdown() {
        this._xvpOp(1, 2);
    }

    machineReboot() {
        this._xvpOp(1, 3);
    }

    machineReset() {
        this._xvpOp(1, 4);
    }

    // Send a key press. If 'down' is not specified then send a down key
    // followed by an up key.
    sendKey(keysym, code, down) {
        if (this._rfbConnectionState !== 'connected' || this._viewOnly) { return; }

        if (down === undefined) {
            this.sendKey(keysym, code, true);
            this.sendKey(keysym, code, false);
            return;
        }

        // ARD servers expect keystrokes wrapped in AES-128-ECB encryption
        // (only before stream encryption is active)
        if (this._rfbAppleARD && this._ardDHKey && !this._ardEncryptionEnabled) {
            const cipher = this._getArdECBCipher();
            const payload = this._buildEncryptedKeyPayload(keysym || 0, down);
            const encrypted = cipher.encrypt({ name: "AES-128-ECB" }, payload);
            Log.Debug("Sending encrypted key event (" + (down ? "down" : "up") + "): keysym " + (keysym || 0));
            RFB.messages.encryptedEvent(this._sock, 0, encrypted);
            return;
        }

        const scancode = XtScancode[code];

        if (this._qemuExtKeyEventSupported && scancode) {
            // 0 is NoSymbol
            keysym = keysym || 0;

            Log.Info("Sending key (" + (down ? "down" : "up") + "): keysym " + keysym + ", scancode " + scancode);

            RFB.messages.QEMUExtendedKeyEvent(this._sock, keysym, down, scancode);
        } else {
            if (!keysym) {
                return;
            }
            Log.Info("Sending keysym (" + (down ? "down" : "up") + "): " + keysym);
            RFB.messages.keyEvent(this._sock, keysym, down ? 1 : 0);
        }
    }

    focus(options) {
        this._canvas.focus(options);
    }

    blur() {
        this._canvas.blur();
    }

    // Force-send clipboard text, bypassing both the dedup check and the
    // auto-sync gate.  Used for explicit user-initiated sends so the content
    // always reaches the remote even if auto-sync is disabled or the text
    // equals what was last sent.
    forceClipboardPaste(text) {
        if (this._rfbConnectionState !== 'connected' || this._viewOnly) { return; }
        this._ardLastClipboardSent = null;
        if (this._rfbAppleARD) {
            this._sendArdClipboard(text);
            return;
        }
        this.clipboardPasteFrom(text);
    }

    clipboardPasteFrom(text) {
        if (this._rfbConnectionState !== 'connected' || this._viewOnly) { return; }
        if (this._rfbAppleARD && !this._ardClipboardSyncEnabled) { return; }
        if (text === this._ardLastClipboardSent) { return; }
        this._ardLastClipboardSent = text;

        if (this._rfbAppleARD) {
            this._sendArdClipboard(text);
            return;
        }

        if (this._clipboardServerCapabilitiesFormats[extendedClipboardFormatText] &&
            this._clipboardServerCapabilitiesActions[extendedClipboardActionNotify]) {

            this._clipboardText = text;
            RFB.messages.extendedClipboardNotify(this._sock, [extendedClipboardFormatText]);
        } else {
            let length, i;
            let data;

            length = 0;
            // eslint-disable-next-line no-unused-vars
            for (let codePoint of text) {
                length++;
            }

            data = new Uint8Array(length);

            i = 0;
            for (let codePoint of text) {
                let code = codePoint.codePointAt(0);

                /* Only ISO 8859-1 is supported */
                if (code > 0xff) {
                    code = 0x3f; // '?'
                }

                data[i++] = code;
            }

            RFB.messages.clientCutText(this._sock, data);
        }
    }

    // Enable or disable automatic clipboard sync (ARD AutoPasteboard).
    // When enabled the server notifies us on remote clipboard changes and
    // we forward local clipboard changes to the remote.
    enableClipboardSync(enabled) {
        if (this._rfbConnectionState !== 'connected' || !this._rfbAppleARD) {
            Log.Warn("ARD: enableClipboardSync(" + enabled + ") skipped" +
                     " state=" + this._rfbConnectionState +
                     " ard=" + this._rfbAppleARD);
            return;
        }
        Log.Info("ARD: clipboard sync " + (enabled ? "ON" : "OFF"));
        this._sendArdAutoPasteboard(enabled ? 1 : 0);
        this._sock.flush();
    }

    // Request the current contents of the remote clipboard (ARD pull).
    // The server will respond with a clipboard event if data is available.
    // Sets a one-shot flag so the reply is honoured even if auto-sync is off.
    requestRemoteClipboard() {
        if (this._rfbConnectionState !== 'connected' || !this._rfbAppleARD) return;
        this._ardClipboardManualRequest = true;
        RFB.messages.ardClipboardRequest(this._sock, this._ardClipboardSessionId);
        this._sock.flush();
    }

    // Switch to a specific display or combined view.
    // combineAll: 1=all displays combined, 0=single display
    // displayId: display ID when combineAll=0
    selectDisplay(combineAll, displayId) {
        if (this._rfbConnectionState !== 'connected' || !this._rfbAppleARD) {
            Log.Debug("ARD selectDisplay(" + combineAll + ", " + displayId +
                      ") skipped -- state=" + this._rfbConnectionState);
            return;
        }

        this._ardCombineAllDisplays = combineAll;
        this._ardSelectedDisplayId = displayId;

        Log.Info("ARD selectDisplay(" +
                 (combineAll ? "All" : "id=" + displayId) + ")");
        this._sendArdSetDisplay();
        if (!combineAll) {
            this._sendArdSetDisplay();  // native ARD client sends twice for single display
        }
        RFB.messages.pixelFormat(this._sock, this._fbDepth, true);
        this._sendArdSetServerScaling(1.0);
        this._sock.flush();
        // Phase 2/3 in _handleArdDisplayInfo2 will send FBUpdateRequest
        // once the server confirms the new layout via DisplayInfo2.
    }

    requestFullUpdate() {
        if (this._rfbConnectionState !== 'connected') return;
        if (this._rfbAppleARD) {
            this._requestArdFullUpdate(this._fbWidth, this._fbHeight);
        } else {
            RFB.messages.fbUpdateRequest(this._sock, false, 0, 0,
                                         this._fbWidth, this._fbHeight);
        }
        this._sock.flush();
    }

    getImageData() {
        return this._display.getImageData();
    }

    toDataURL(type, encoderOptions) {
        return this._display.toDataURL(type, encoderOptions);
    }

    toBlob(callback, type, quality) {
        return this._display.toBlob(callback, type, quality);
    }

    // ===== PRIVATE METHODS =====

    _connect() {
        Log.Debug(">> RFB.connect");

        if (this._url) {
            Log.Info(`connecting to ${this._url}`);
            this._sock.open(this._url, this._wsProtocols);
        } else {
            Log.Info(`attaching ${this._rawChannel} to Websock`);
            this._sock.attach(this._rawChannel);

            if (this._sock.readyState === 'closed') {
                throw Error("Cannot use already closed WebSocket/RTCDataChannel");
            }

            if (this._sock.readyState === 'open') {
                // FIXME: _socketOpen() can in theory call _fail(), which
                //        isn't allowed this early, but I'm not sure that can
                //        happen without a bug messing up our state variables
                this._socketOpen();
            }
        }

        // Make our elements part of the page
        this._target.appendChild(this._screen);

        this._gestures.attach(this._canvas);

        this._cursor.attach(this._canvas);
        this._refreshCursor();

        // Monitor size changes of the screen element
        this._resizeObserver.observe(this._screen);

        // Always grab focus on some kind of click event
        this._canvas.addEventListener("mousedown", this._eventHandlers.focusCanvas);
        this._canvas.addEventListener("touchstart", this._eventHandlers.focusCanvas);

        // Mouse events
        this._canvas.addEventListener('mousedown', this._eventHandlers.handleMouse);
        this._canvas.addEventListener('mouseup', this._eventHandlers.handleMouse);
        this._canvas.addEventListener('mousemove', this._eventHandlers.handleMouse);
        // Prevent middle-click pasting (see handler for why we bind to document)
        this._canvas.addEventListener('click', this._eventHandlers.handleMouse);
        // preventDefault() on mousedown doesn't stop this event for some
        // reason so we have to explicitly block it
        this._canvas.addEventListener('contextmenu', this._eventHandlers.handleMouse);

        // Wheel events
        this._canvas.addEventListener("wheel", this._eventHandlers.handleWheel);

        // Gesture events
        this._canvas.addEventListener("gesturestart", this._eventHandlers.handleGesture);
        this._canvas.addEventListener("gesturemove", this._eventHandlers.handleGesture);
        this._canvas.addEventListener("gestureend", this._eventHandlers.handleGesture);

        Log.Debug("<< RFB.connect");
    }

    _disconnect() {
        Log.Debug(">> RFB.disconnect");
        this._cursor.detach();
        this._canvas.removeEventListener("gesturestart", this._eventHandlers.handleGesture);
        this._canvas.removeEventListener("gesturemove", this._eventHandlers.handleGesture);
        this._canvas.removeEventListener("gestureend", this._eventHandlers.handleGesture);
        this._canvas.removeEventListener("wheel", this._eventHandlers.handleWheel);
        this._canvas.removeEventListener('mousedown', this._eventHandlers.handleMouse);
        this._canvas.removeEventListener('mouseup', this._eventHandlers.handleMouse);
        this._canvas.removeEventListener('mousemove', this._eventHandlers.handleMouse);
        this._canvas.removeEventListener('click', this._eventHandlers.handleMouse);
        this._canvas.removeEventListener('contextmenu', this._eventHandlers.handleMouse);
        this._canvas.removeEventListener("mousedown", this._eventHandlers.focusCanvas);
        this._canvas.removeEventListener("touchstart", this._eventHandlers.focusCanvas);
        this._resizeObserver.disconnect();
        this._keyboard.ungrab();
        this._gestures.detach();
        this._sock.close();
        try {
            this._target.removeChild(this._screen);
        } catch (e) {
            if (e.name === 'NotFoundError') {
                // Some cases where the initial connection fails
                // can disconnect before the _screen is created
            } else {
                throw e;
            }
        }
        clearTimeout(this._resizeTimeout);
        clearTimeout(this._mouseMoveTimer);
        clearTimeout(this._authTimer);
        this._authTimer = null;
        Log.Debug("<< RFB.disconnect");
    }

    _socketOpen() {
        if ((this._rfbConnectionState === 'connecting') &&
            (this._rfbInitState === '')) {
            this._rfbInitState = 'ProtocolVersion';
            Log.Debug("Starting VNC handshake");
        } else {
            this._fail("Unexpected server connection while " +
                       this._rfbConnectionState);
        }
    }

    _socketClose(e) {
        Log.Debug("WebSocket on-close event");
        let msg = "";
        if (e.code) {
            msg = "(code: " + e.code;
            if (e.reason) {
                msg += ", reason: " + e.reason;
            }
            msg += ")";
        }
        switch (this._rfbConnectionState) {
            case 'connecting':
                this._fail("Connection closed " + msg);
                break;
            case 'connected':
                // Handle disconnects that were initiated server-side
                this._updateConnectionState('disconnecting');
                this._updateConnectionState('disconnected');
                break;
            case 'disconnecting':
                // Normal disconnection path
                this._updateConnectionState('disconnected');
                break;
            case 'disconnected':
                this._fail("Unexpected server disconnect " +
                           "when already disconnected " + msg);
                break;
            default:
                this._fail("Unexpected server disconnect before connecting " +
                           msg);
                break;
        }
        this._sock.off('close');
        // Delete reference to raw channel to allow cleanup.
        this._rawChannel = null;
    }

    _socketError(e) {
        Log.Warn("WebSocket on-error event");
    }

    _focusCanvas(event) {
        if (!this.focusOnClick) {
            return;
        }

        this.focus({ preventScroll: true });
    }

    _setDesktopName(name) {
        this._fbName = name;
        this.dispatchEvent(new CustomEvent(
            "desktopname",
            { detail: { name: this._fbName } }));
    }

    _saveExpectedClientSize() {
        this._expectedClientWidth = this._screen.clientWidth;
        this._expectedClientHeight = this._screen.clientHeight;
    }

    _currentClientSize() {
        return [this._screen.clientWidth, this._screen.clientHeight];
    }

    _clientHasExpectedSize() {
        const [currentWidth, currentHeight] = this._currentClientSize();
        return currentWidth == this._expectedClientWidth &&
            currentHeight == this._expectedClientHeight;
    }

    // Handle browser window resizes
    _handleResize() {
        // Don't change anything if the client size is already as expected
        if (this._clientHasExpectedSize()) {
            return;
        }
        // If the window resized then our screen element might have
        // as well. Update the viewport dimensions.
        window.requestAnimationFrame(() => {
            this._updateClip();
            this._updateScale();
            this._saveExpectedClientSize();
        });

        // Request changing the resolution of the remote display to
        // the size of the local browser viewport.
        this._requestRemoteResize();
    }

    // Update state of clipping in Display object, and make sure the
    // configured viewport matches the current screen size
    _updateClip() {
        const curClip = this._display.clipViewport;
        let newClip = this._clipViewport;

        if (this._scaleViewport) {
            // Disable viewport clipping if we are scaling
            newClip = false;
        }

        if (curClip !== newClip) {
            this._display.clipViewport = newClip;
        }

        if (newClip) {
            // When clipping is enabled, the screen is limited to
            // the size of the container.
            const size = this._screenSize();
            this._display.viewportChangeSize(size.w, size.h);
            this._fixScrollbars();
            this._setClippingViewport(size.w < this._display.width ||
                                      size.h < this._display.height);
        } else {
            this._setClippingViewport(false);
        }

        // When changing clipping we might show or hide scrollbars.
        // This causes the expected client dimensions to change.
        if (curClip !== newClip) {
            this._saveExpectedClientSize();
        }
    }

    _updateScale() {
        if (!this._scaleViewport) {
            this._display.scale = 1.0;
        } else {
            const size = this._screenSize();
            this._display.autoscale(size.w, size.h);
        }
        this._fixScrollbars();
    }

    // Requests a change of remote desktop size. This message is an extension
    // and may only be sent if we have received an ExtendedDesktopSize message
    _requestRemoteResize() {
        if (!this._resizeSession) {
            return;
        }
        if (this._viewOnly) {
            return;
        }
        if (!this._supportsSetDesktopSize) {
            return;
        }

        // Rate limit to one pending resize at a time
        if (this._pendingRemoteResize) {
            return;
        }

        // And no more than once every 100ms
        if ((Date.now() - this._lastResize) < 100) {
            clearTimeout(this._resizeTimeout);
            this._resizeTimeout = setTimeout(this._requestRemoteResize.bind(this),
                                             100 - (Date.now() - this._lastResize));
            return;
        }
        this._resizeTimeout = null;

        const size = this._screenSize();

        // Do we actually change anything?
        if (size.w === this._fbWidth && size.h === this._fbHeight) {
            return;
        }

        this._pendingRemoteResize = true;
        this._lastResize = Date.now();
        RFB.messages.setDesktopSize(this._sock,
                                    Math.floor(size.w), Math.floor(size.h),
                                    this._screenID, this._screenFlags);

        Log.Debug('Requested new desktop size: ' +
                   size.w + 'x' + size.h);
    }

    // Gets the the size of the available screen
    _screenSize() {
        let r = this._screen.getBoundingClientRect();
        return { w: r.width, h: r.height };
    }

    _fixScrollbars() {
        // This is a hack because Safari on macOS screws up the calculation
        // for when scrollbars are needed. We get scrollbars when making the
        // browser smaller, despite remote resize being enabled. So to fix it
        // we temporarily toggle them off and on.
        const orig = this._screen.style.overflow;
        this._screen.style.overflow = 'hidden';
        // Force Safari to recalculate the layout by asking for
        // an element's dimensions
        this._screen.getBoundingClientRect();
        this._screen.style.overflow = orig;
    }

    /*
     * Connection states:
     *   connecting
     *   connected
     *   disconnecting
     *   disconnected - permanent state
     */
    _updateConnectionState(state) {
        const oldstate = this._rfbConnectionState;

        if (state === oldstate) {
            Log.Debug("Already in state '" + state + "', ignoring");
            return;
        }

        // The 'disconnected' state is permanent for each RFB object
        if (oldstate === 'disconnected') {
            Log.Error("Tried changing state of a disconnected RFB object");
            return;
        }

        // Ensure proper transitions before doing anything
        switch (state) {
            case 'connected':
                if (oldstate !== 'connecting') {
                    Log.Error("Bad transition to connected state, " +
                               "previous connection state: " + oldstate);
                    return;
                }
                break;

            case 'disconnected':
                if (oldstate !== 'disconnecting') {
                    Log.Error("Bad transition to disconnected state, " +
                               "previous connection state: " + oldstate);
                    return;
                }
                break;

            case 'connecting':
                if (oldstate !== '') {
                    Log.Error("Bad transition to connecting state, " +
                               "previous connection state: " + oldstate);
                    return;
                }
                break;

            case 'disconnecting':
                if (oldstate !== 'connected' && oldstate !== 'connecting') {
                    Log.Error("Bad transition to disconnecting state, " +
                               "previous connection state: " + oldstate);
                    return;
                }
                break;

            default:
                Log.Error("Unknown connection state: " + state);
                return;
        }

        // State change actions

        this._rfbConnectionState = state;

        Log.Debug("New state '" + state + "', was '" + oldstate + "'.");

        if (this._disconnTimer && state !== 'disconnecting') {
            Log.Debug("Clearing disconnect timer");
            clearTimeout(this._disconnTimer);
            this._disconnTimer = null;

            // make sure we don't get a double event
            this._sock.off('close');
        }

        switch (state) {
            case 'connecting':
                this._connect();
                break;

            case 'connected':
                this.dispatchEvent(new CustomEvent("connect", { detail: {} }));
                if (this._rfbAppleARD) {
                    this._ardLastFbuTime = 0;
                    this._ardTickleCount = 0;
                    this._ardFreezeWatchdog = setInterval(() => {
                        if (!this._ardLastFbuTime) return; // still in init
                        const age = Date.now() - this._ardLastFbuTime;
                        if (age > 5000) {
                            Log.Warn("ARD: no FBU for " + Math.round(age / 1000) +
                                     "s (Tickles since last FBU: " +
                                     this._ardTickleCount + ")");
                        }
                    }, 5000);
                }
                break;

            case 'disconnecting':
                if (this._ardFreezeWatchdog) {
                    clearInterval(this._ardFreezeWatchdog);
                    this._ardFreezeWatchdog = null;
                }
                // Reset ARD mode/curtain/user state so reconnects start clean
                this._ardControlMode = 1;
                this._ardCurtainActive = false;
                this._ardConsoleActive = false;
                this._ardUsername = '';
                this._ardUserAvatarPng = null;
                this._disconnect();

                this._disconnTimer = setTimeout(() => {
                    Log.Error("Disconnection timed out.");
                    this._updateConnectionState('disconnected');
                }, DISCONNECT_TIMEOUT * 1000);
                break;

            case 'disconnected':
                this.dispatchEvent(new CustomEvent(
                    "disconnect", { detail:
                                    { clean: this._rfbCleanDisconnect } }));
                break;
        }
    }

    /* Print errors and disconnect
     *
     * The parameter 'details' is used for information that
     * should be logged but not sent to the user interface.
     */
    _fail(details) {
        switch (this._rfbConnectionState) {
            case 'disconnecting':
                Log.Error("Failed when disconnecting: " + details);
                break;
            case 'connected':
                Log.Error("Failed while connected: " + details);
                break;
            case 'connecting':
                Log.Error("Failed when connecting: " + details);
                break;
            default:
                Log.Error("RFB failure: " + details);
                break;
        }
        this._rfbCleanDisconnect = false; //This is sent to the UI

        // Transition to disconnected without waiting for socket to close
        this._updateConnectionState('disconnecting');
        this._updateConnectionState('disconnected');

        return false;
    }

    _setCapability(cap, val) {
        this._capabilities[cap] = val;
        this.dispatchEvent(new CustomEvent("capabilities",
                                           { detail: { capabilities: this._capabilities } }));
    }

    _handleMessage() {
        if (this._sock.rQwait("message", 1)) {
            Log.Warn("handleMessage called on an empty receive queue");
            return;
        }

        switch (this._rfbConnectionState) {
            case 'disconnected':
                Log.Error("Got data while disconnected");
                break;
            case 'connected':
                while (true) {
                    if (this._flushing) {
                        break;
                    }
                    if (!this._normalMsg()) {
                        break;
                    }
                    if (this._sock.rQwait("message", 1)) {
                        break;
                    }
                }
                break;
            case 'connecting':
                while (this._rfbConnectionState === 'connecting') {
                    if (!this._initMsg()) {
                        break;
                    }
                }
                break;
            default:
                Log.Error("Got data while in an invalid state");
                break;
        }
    }

    _handleKeyEvent(keysym, code, down, numlock, capslock) {
        // If remote state of capslock is known, and it doesn't match the local led state of
        // the keyboard, we send a capslock keypress first to bring it into sync.
        // If we just pressed CapsLock, or we toggled it remotely due to it being out of sync
        // we clear the remote state so that we don't send duplicate or spurious fixes,
        // since it may take some time to receive the new remote CapsLock state.
        if (code == 'CapsLock' && down) {
            this._remoteCapsLock = null;
        }
        if (this._remoteCapsLock !== null && capslock !== null && this._remoteCapsLock !== capslock && down) {
            Log.Debug("Fixing remote caps lock");

            this.sendKey(KeyTable.XK_Caps_Lock, 'CapsLock', true);
            this.sendKey(KeyTable.XK_Caps_Lock, 'CapsLock', false);
            // We clear the remote capsLock state when we do this to prevent issues with doing this twice
            // before we receive an update of the the remote state.
            this._remoteCapsLock = null;
        }

        // Logic for numlock is exactly the same.
        if (code == 'NumLock' && down) {
            this._remoteNumLock = null;
        }
        if (this._remoteNumLock !== null && numlock !== null && this._remoteNumLock !== numlock && down) {
            Log.Debug("Fixing remote num lock");
            this.sendKey(KeyTable.XK_Num_Lock, 'NumLock', true);
            this.sendKey(KeyTable.XK_Num_Lock, 'NumLock', false);
            this._remoteNumLock = null;
        }
        this.sendKey(keysym, code, down);
    }

    static _convertButtonMask(buttons) {
        /* The bits in MouseEvent.buttons property correspond
         * to the following mouse buttons:
         *     0: Left
         *     1: Right
         *     2: Middle
         *     3: Back
         *     4: Forward
         *
         * These bits needs to be converted to what they are defined as
         * in the RFB protocol.
         */

        const buttonMaskMap = {
            0: 1 << 0, // Left
            1: 1 << 2, // Right
            2: 1 << 1, // Middle
            3: 1 << 7, // Back
            4: 1 << 8, // Forward
        };

        let bmask = 0;
        for (let i = 0; i < 5; i++) {
            if (buttons & (1 << i)) {
                bmask |= buttonMaskMap[i];
            }
        }
        return bmask;
    }

    _handleMouse(ev) {
        /*
         * We don't check connection status or viewOnly here as the
         * mouse events might be used to control the viewport
         */

        if (ev.type === 'click') {
            /*
             * Note: This is only needed for the 'click' event as it fails
             *       to fire properly for the target element so we have
             *       to listen on the document element instead.
             */
            if (ev.target !== this._canvas) {
                return;
            }
        }

        // FIXME: if we're in view-only and not dragging,
        //        should we stop events?
        ev.stopPropagation();
        ev.preventDefault();

        if ((ev.type === 'click') || (ev.type === 'contextmenu')) {
            return;
        }

        let pos = clientToElement(ev.clientX, ev.clientY,
                                  this._canvas);

        let bmask = RFB._convertButtonMask(ev.buttons);

        let down = ev.type == 'mousedown';
        switch (ev.type) {
            case 'mousedown':
            case 'mouseup':
                if (this.dragViewport) {
                    if (down && !this._viewportDragging) {
                        this._viewportDragging = true;
                        this._viewportDragPos = {'x': pos.x, 'y': pos.y};
                        this._viewportHasMoved = false;

                        this._flushMouseMoveTimer(pos.x, pos.y);

                        // Skip sending mouse events, instead save the current
                        // mouse mask so we can send it later.
                        this._mouseButtonMask = bmask;
                        break;
                    } else {
                        this._viewportDragging = false;

                        // If we actually performed a drag then we are done
                        // here and should not send any mouse events
                        if (this._viewportHasMoved) {
                            this._mouseButtonMask = bmask;
                            break;
                        }
                        // Otherwise we treat this as a mouse click event.
                        // Send the previously saved button mask, followed
                        // by the current button mask at the end of this
                        // function.
                        this._sendMouse(pos.x, pos.y,  this._mouseButtonMask);
                    }
                }
                if (down) {
                    setCapture(this._canvas);
                }
                this._handleMouseButton(pos.x, pos.y, bmask);
                break;
            case 'mousemove':
                if (this._viewportDragging) {
                    const deltaX = this._viewportDragPos.x - pos.x;
                    const deltaY = this._viewportDragPos.y - pos.y;

                    if (this._viewportHasMoved || (Math.abs(deltaX) > dragThreshold ||
                                                   Math.abs(deltaY) > dragThreshold)) {
                        this._viewportHasMoved = true;

                        this._viewportDragPos = {'x': pos.x, 'y': pos.y};
                        this._display.viewportChangePos(deltaX, deltaY);
                    }

                    // Skip sending mouse events
                    break;
                }
                this._handleMouseMove(pos.x, pos.y);
                break;
        }
    }

    _handleMouseButton(x, y, bmask) {
        // Flush waiting move event first
        this._flushMouseMoveTimer(x, y);

        this._mouseButtonMask = bmask;
        this._sendMouse(x, y, this._mouseButtonMask);
    }

    _handleMouseMove(x, y) {
        this._mousePos = { 'x': x, 'y': y };

        // Limit many mouse move events to one every MOUSE_MOVE_DELAY ms
        if (this._mouseMoveTimer == null) {

            const timeSinceLastMove = Date.now() - this._mouseLastMoveTime;
            if (timeSinceLastMove > MOUSE_MOVE_DELAY) {
                this._sendMouse(x, y, this._mouseButtonMask);
                this._mouseLastMoveTime = Date.now();
            } else {
                // Too soon since the latest move, wait the remaining time
                this._mouseMoveTimer = setTimeout(() => {
                    this._handleDelayedMouseMove();
                }, MOUSE_MOVE_DELAY - timeSinceLastMove);
            }
        }
    }

    _handleDelayedMouseMove() {
        this._mouseMoveTimer = null;
        this._sendMouse(this._mousePos.x, this._mousePos.y,
                        this._mouseButtonMask);
        this._mouseLastMoveTime = Date.now();
    }

    _sendMouse(x, y, mask) {
        if (this._rfbConnectionState !== 'connected') { return; }
        if (this._viewOnly) { return; } // View only, skip mouse events

        // Highest bit in mask is never sent to the server
        if (mask & 0x8000) {
            throw new Error("Illegal mouse button mask (mask: " + mask + ")");
        }

        let extendedMouseButtons = mask & 0x7f80;

        if (this._extendedPointerEventSupported && extendedMouseButtons) {
            RFB.messages.extendedPointerEvent(this._sock, this._display.absX(x),
                                              this._display.absY(y), mask);
        } else {
            RFB.messages.pointerEvent(this._sock, this._display.absX(x),
                                      this._display.absY(y), mask);
        }
    }

    _handleWheel(ev) {
        if (this._rfbConnectionState !== 'connected') { return; }
        if (this._viewOnly) { return; } // View only, skip mouse events

        ev.stopPropagation();
        ev.preventDefault();

        let pos = clientToElement(ev.clientX, ev.clientY,
                                  this._canvas);

        let bmask = RFB._convertButtonMask(ev.buttons);
        let dX = ev.deltaX;
        let dY = ev.deltaY;

        // Pixel units unless it's non-zero.
        // Note that if deltamode is line or page won't matter since we aren't
        // sending the mouse wheel delta to the server anyway.
        // The difference between pixel and line can be important however since
        // we have a threshold that can be smaller than the line height.
        if (ev.deltaMode !== 0) {
            dX *= WHEEL_LINE_HEIGHT;
            dY *= WHEEL_LINE_HEIGHT;
        }

        // Mouse wheel events are sent in steps over VNC. This means that the VNC
        // protocol can't handle a wheel event with specific distance or speed.
        // Therefor, if we get a lot of small mouse wheel events we combine them.
        this._accumulatedWheelDeltaX += dX;
        this._accumulatedWheelDeltaY += dY;


        // Generate a mouse wheel step event when the accumulated delta
        // for one of the axes is large enough.
        if (Math.abs(this._accumulatedWheelDeltaX) >= WHEEL_STEP) {
            if (this._accumulatedWheelDeltaX < 0) {
                this._handleMouseButton(pos.x, pos.y, bmask | 1 << 5);
                this._handleMouseButton(pos.x, pos.y, bmask);
            } else if (this._accumulatedWheelDeltaX > 0) {
                this._handleMouseButton(pos.x, pos.y, bmask | 1 << 6);
                this._handleMouseButton(pos.x, pos.y, bmask);
            }

            this._accumulatedWheelDeltaX = 0;
        }
        if (Math.abs(this._accumulatedWheelDeltaY) >= WHEEL_STEP) {
            if (this._accumulatedWheelDeltaY < 0) {
                this._handleMouseButton(pos.x, pos.y, bmask | 1 << 3);
                this._handleMouseButton(pos.x, pos.y, bmask);
            } else if (this._accumulatedWheelDeltaY > 0) {
                this._handleMouseButton(pos.x, pos.y, bmask | 1 << 4);
                this._handleMouseButton(pos.x, pos.y, bmask);
            }

            this._accumulatedWheelDeltaY = 0;
        }
    }

    _fakeMouseMove(ev, elementX, elementY) {
        this._handleMouseMove(elementX, elementY);
        this._cursor.move(ev.detail.clientX, ev.detail.clientY);
    }

    _handleTapEvent(ev, bmask) {
        let pos = clientToElement(ev.detail.clientX, ev.detail.clientY,
                                  this._canvas);

        // If the user quickly taps multiple times we assume they meant to
        // hit the same spot, so slightly adjust coordinates

        if ((this._gestureLastTapTime !== null) &&
            ((Date.now() - this._gestureLastTapTime) < DOUBLE_TAP_TIMEOUT) &&
            (this._gestureFirstDoubleTapEv.detail.type === ev.detail.type)) {
            let dx = this._gestureFirstDoubleTapEv.detail.clientX - ev.detail.clientX;
            let dy = this._gestureFirstDoubleTapEv.detail.clientY - ev.detail.clientY;
            let distance = Math.hypot(dx, dy);

            if (distance < DOUBLE_TAP_THRESHOLD) {
                pos = clientToElement(this._gestureFirstDoubleTapEv.detail.clientX,
                                      this._gestureFirstDoubleTapEv.detail.clientY,
                                      this._canvas);
            } else {
                this._gestureFirstDoubleTapEv = ev;
            }
        } else {
            this._gestureFirstDoubleTapEv = ev;
        }
        this._gestureLastTapTime = Date.now();

        this._fakeMouseMove(this._gestureFirstDoubleTapEv, pos.x, pos.y);
        this._handleMouseButton(pos.x, pos.y, bmask);
        this._handleMouseButton(pos.x, pos.y, 0x0);
    }

    _handleGesture(ev) {
        let magnitude;

        let pos = clientToElement(ev.detail.clientX, ev.detail.clientY,
                                  this._canvas);
        switch (ev.type) {
            case 'gesturestart':
                switch (ev.detail.type) {
                    case 'onetap':
                        this._handleTapEvent(ev, 0x1);
                        break;
                    case 'twotap':
                        this._handleTapEvent(ev, 0x4);
                        break;
                    case 'threetap':
                        this._handleTapEvent(ev, 0x2);
                        break;
                    case 'drag':
                        if (this.dragViewport) {
                            this._viewportHasMoved = false;
                            this._viewportDragging = true;
                            this._viewportDragPos = {'x': pos.x, 'y': pos.y};
                        } else {
                            this._fakeMouseMove(ev, pos.x, pos.y);
                            this._handleMouseButton(pos.x, pos.y, 0x1);
                        }
                        break;
                    case 'longpress':
                        if (this.dragViewport) {
                            // If dragViewport is true, we need to wait to see
                            // if we have dragged outside the threshold before
                            // sending any events to the server.
                            this._viewportHasMoved = false;
                            this._viewportDragPos = {'x': pos.x, 'y': pos.y};
                        } else {
                            this._fakeMouseMove(ev, pos.x, pos.y);
                            this._handleMouseButton(pos.x, pos.y, 0x4);
                        }
                        break;
                    case 'twodrag':
                        this._gestureLastMagnitudeX = ev.detail.magnitudeX;
                        this._gestureLastMagnitudeY = ev.detail.magnitudeY;
                        this._fakeMouseMove(ev, pos.x, pos.y);
                        break;
                    case 'pinch':
                        this._gestureLastMagnitudeX = Math.hypot(ev.detail.magnitudeX,
                                                                 ev.detail.magnitudeY);
                        this._fakeMouseMove(ev, pos.x, pos.y);
                        break;
                }
                break;

            case 'gesturemove':
                switch (ev.detail.type) {
                    case 'onetap':
                    case 'twotap':
                    case 'threetap':
                        break;
                    case 'drag':
                    case 'longpress':
                        if (this.dragViewport) {
                            this._viewportDragging = true;
                            const deltaX = this._viewportDragPos.x - pos.x;
                            const deltaY = this._viewportDragPos.y - pos.y;

                            if (this._viewportHasMoved || (Math.abs(deltaX) > dragThreshold ||
                                                           Math.abs(deltaY) > dragThreshold)) {
                                this._viewportHasMoved = true;

                                this._viewportDragPos = {'x': pos.x, 'y': pos.y};
                                this._display.viewportChangePos(deltaX, deltaY);
                            }
                        } else {
                            this._fakeMouseMove(ev, pos.x, pos.y);
                        }
                        break;
                    case 'twodrag':
                        // Always scroll in the same position.
                        // We don't know if the mouse was moved so we need to move it
                        // every update.
                        this._fakeMouseMove(ev, pos.x, pos.y);
                        while ((ev.detail.magnitudeY - this._gestureLastMagnitudeY) > GESTURE_SCRLSENS) {
                            this._handleMouseButton(pos.x, pos.y, 0x8);
                            this._handleMouseButton(pos.x, pos.y, 0x0);
                            this._gestureLastMagnitudeY += GESTURE_SCRLSENS;
                        }
                        while ((ev.detail.magnitudeY - this._gestureLastMagnitudeY) < -GESTURE_SCRLSENS) {
                            this._handleMouseButton(pos.x, pos.y, 0x10);
                            this._handleMouseButton(pos.x, pos.y, 0x0);
                            this._gestureLastMagnitudeY -= GESTURE_SCRLSENS;
                        }
                        while ((ev.detail.magnitudeX - this._gestureLastMagnitudeX) > GESTURE_SCRLSENS) {
                            this._handleMouseButton(pos.x, pos.y, 0x20);
                            this._handleMouseButton(pos.x, pos.y, 0x0);
                            this._gestureLastMagnitudeX += GESTURE_SCRLSENS;
                        }
                        while ((ev.detail.magnitudeX - this._gestureLastMagnitudeX) < -GESTURE_SCRLSENS) {
                            this._handleMouseButton(pos.x, pos.y, 0x40);
                            this._handleMouseButton(pos.x, pos.y, 0x0);
                            this._gestureLastMagnitudeX -= GESTURE_SCRLSENS;
                        }
                        break;
                    case 'pinch':
                        // Always scroll in the same position.
                        // We don't know if the mouse was moved so we need to move it
                        // every update.
                        this._fakeMouseMove(ev, pos.x, pos.y);
                        magnitude = Math.hypot(ev.detail.magnitudeX, ev.detail.magnitudeY);
                        if (Math.abs(magnitude - this._gestureLastMagnitudeX) > GESTURE_ZOOMSENS) {
                            this._handleKeyEvent(KeyTable.XK_Control_L, "ControlLeft", true);
                            while ((magnitude - this._gestureLastMagnitudeX) > GESTURE_ZOOMSENS) {
                                this._handleMouseButton(pos.x, pos.y, 0x8);
                                this._handleMouseButton(pos.x, pos.y, 0x0);
                                this._gestureLastMagnitudeX += GESTURE_ZOOMSENS;
                            }
                            while ((magnitude -  this._gestureLastMagnitudeX) < -GESTURE_ZOOMSENS) {
                                this._handleMouseButton(pos.x, pos.y, 0x10);
                                this._handleMouseButton(pos.x, pos.y, 0x0);
                                this._gestureLastMagnitudeX -= GESTURE_ZOOMSENS;
                            }
                        }
                        this._handleKeyEvent(KeyTable.XK_Control_L, "ControlLeft", false);
                        break;
                }
                break;

            case 'gestureend':
                switch (ev.detail.type) {
                    case 'onetap':
                    case 'twotap':
                    case 'threetap':
                    case 'pinch':
                    case 'twodrag':
                        break;
                    case 'drag':
                        if (this.dragViewport) {
                            this._viewportDragging = false;
                        } else {
                            this._fakeMouseMove(ev, pos.x, pos.y);
                            this._handleMouseButton(pos.x, pos.y, 0x0);
                        }
                        break;
                    case 'longpress':
                        if (this._viewportHasMoved) {
                            // We don't want to send any events if we have moved
                            // our viewport
                            break;
                        }

                        if (this.dragViewport && !this._viewportHasMoved) {
                            this._fakeMouseMove(ev, pos.x, pos.y);
                            // If dragViewport is true, we need to wait to see
                            // if we have dragged outside the threshold before
                            // sending any events to the server.
                            this._handleMouseButton(pos.x, pos.y, 0x4);
                            this._handleMouseButton(pos.x, pos.y, 0x0);
                            this._viewportDragging = false;
                        } else {
                            this._fakeMouseMove(ev, pos.x, pos.y);
                            this._handleMouseButton(pos.x, pos.y, 0x0);
                        }
                        break;
                }
                break;
        }
    }

    _flushMouseMoveTimer(x, y) {
        if (this._mouseMoveTimer !== null) {
            clearTimeout(this._mouseMoveTimer);
            this._mouseMoveTimer = null;
            this._sendMouse(x, y, this._mouseButtonMask);
        }
    }

    // Message handlers

    _negotiateProtocolVersion() {
        if (this._sock.rQwait("version", 12)) {
            return false;
        }

        const sversion = this._sock.rQshiftStr(12).substr(4, 7);
        Log.Info("Server ProtocolVersion: " + sversion);
        let isRepeater = 0;
        switch (sversion) {
            case "000.000":  // UltraVNC repeater
                isRepeater = 1;
                break;
            case "003.003":
            case "003.006":  // UltraVNC
                this._rfbVersion = 3.3;
                break;
            case "003.007":
                this._rfbVersion = 3.7;
                break;
            case "003.889":  // Apple Remote Desktop
                this._rfbVersion = 3.8;
                this._rfbAppleARD = true;
                // ARD server ignores client PixelFormat and always sends RGB (not BGR)
                // despite ServerInit advertising BGR. Don't swap.
                this._decoders[encodings.encodingZlib].swapRedBlue = false;
                this._decoders[encodings.encodingRaw].swapRedBlue = false;
                this._decoders[encodings.encodingZRLE].swapRedBlue = false;
                this._decoders[encodings.encodingHextile].swapRedBlue = false;
                this._decoders[encodings.encodingRRE].swapRedBlue = false;
                break;
            case "003.008":
            case "004.000":  // Intel AMT KVM
            case "004.001":  // RealVNC 4.6
            case "005.000":  // RealVNC 5.3
                this._rfbVersion = 3.8;
                break;
            default:
                return this._fail("Invalid server version " + sversion);
        }

        if (isRepeater) {
            let repeaterID = "ID:" + this._repeaterID;
            while (repeaterID.length < 250) {
                repeaterID += "\0";
            }
            this._sock.sQpushString(repeaterID);
            this._sock.flush();
            return true;
        }

        if (this._rfbVersion > this._rfbMaxVersion) {
            this._rfbVersion = this._rfbMaxVersion;
        }

        let cversion;
        if (this._rfbAppleARD) {
            cversion = "003.889"; // ARD requires echoing the version exactly
        } else {
            cversion = "00" + parseInt(this._rfbVersion, 10) +
                       ".00" + ((this._rfbVersion * 10) % 10);
        }
        this._sock.sQpushString("RFB " + cversion + "\n");
        this._sock.flush();
        Log.Debug('Sent ProtocolVersion: ' + cversion);

        this._rfbInitState = 'Security';
    }

    _isSupportedSecurityType(type) {
        const clientTypes = [
            securityTypeNone,
            securityTypeVNCAuth,
            securityTypeRA2ne,
            securityTypeTight,
            securityTypeVeNCrypt,
            securityTypeXVP,
            securityTypeARD,
            securityTypeRSATunnel,
            securityTypeMSLogonII,
            securityTypePlain,
        ];

        return clientTypes.includes(type);
    }

    _negotiateSecurity() {
        if (this._rfbVersion >= 3.7) {
            // Server sends supported list, client decides
            const numTypes = this._sock.rQshift8();
            if (this._sock.rQwait("security type", numTypes, 1)) { return false; }

            if (numTypes === 0) {
                this._rfbInitState = "SecurityReason";
                this._securityContext = "no security types";
                this._securityStatus = 1;
                return true;
            }

            const types = this._sock.rQshiftBytes(numTypes);
            Log.Debug("Server security types: " + types);

            // Look for a matching security type. Prefer RSATunnel (33)
            // over ARD DH (30) when both are offered.
            this._rfbAuthScheme = -1;
            for (let type of types) {
                if (this._isSupportedSecurityType(type)) {
                    if (this._rfbAuthScheme === -1) {
                        this._rfbAuthScheme = type;
                    }
                    if (type === securityTypeRSATunnel) {
                        this._rfbAuthScheme = type;
                        break;
                    }
                }
            }

            if (this._rfbAuthScheme === -1) {
                return this._fail("Unsupported security types (types: " + types + ")");
            }

            this._sock.sQpush8(this._rfbAuthScheme);
            // Type 33 (RSATunnel) requires the auth byte and first payload
            // in a single TCP segment — defer flush to the handler.
            if (this._rfbAuthScheme !== securityTypeRSATunnel) {
                this._sock.flush();
            }
        } else {
            // Server decides
            if (this._sock.rQwait("security scheme", 4)) { return false; }
            this._rfbAuthScheme = this._sock.rQshift32();

            if (this._rfbAuthScheme == 0) {
                this._rfbInitState = "SecurityReason";
                this._securityContext = "authentication scheme";
                this._securityStatus = 1;
                return true;
            }
        }

        this._rfbInitState = 'Authentication';
        Log.Debug('Authenticating using scheme: ' + this._rfbAuthScheme);

        return true;
    }

    _handleSecurityReason() {
        if (this._sock.rQwait("reason length", 4)) {
            return false;
        }
        const strlen = this._sock.rQshift32();
        let reason = "";

        if (strlen > 0) {
            if (this._sock.rQwait("reason", strlen, 4)) { return false; }
            reason = this._sock.rQshiftStr(strlen);
        }

        if (reason !== "") {
            this.dispatchEvent(new CustomEvent(
                "securityfailure",
                { detail: { status: this._securityStatus,
                            reason: reason } }));

            return this._fail("Security negotiation failed on " +
                              this._securityContext +
                              " (reason: " + reason + ")");
        } else {
            this.dispatchEvent(new CustomEvent(
                "securityfailure",
                { detail: { status: this._securityStatus } }));

            return this._fail("Security negotiation failed on " +
                              this._securityContext);
        }
    }

    // authentication
    _negotiateXvpAuth() {
        if (this._rfbCredentials.username === undefined ||
            this._rfbCredentials.password === undefined ||
            this._rfbCredentials.target === undefined) {
            this.dispatchEvent(new CustomEvent(
                "credentialsrequired",
                { detail: { types: ["username", "password", "target"] } }));
            return false;
        }

        this._sock.sQpush8(this._rfbCredentials.username.length);
        this._sock.sQpush8(this._rfbCredentials.target.length);
        this._sock.sQpushString(this._rfbCredentials.username);
        this._sock.sQpushString(this._rfbCredentials.target);

        this._sock.flush();

        this._rfbAuthScheme = securityTypeVNCAuth;

        return this._negotiateAuthentication();
    }

    // VeNCrypt authentication, currently only supports version 0.2 and only Plain subtype
    _negotiateVeNCryptAuth() {

        // waiting for VeNCrypt version
        if (this._rfbVeNCryptState == 0) {
            if (this._sock.rQwait("vencrypt version", 2)) { return false; }

            const major = this._sock.rQshift8();
            const minor = this._sock.rQshift8();

            if (!(major == 0 && minor == 2)) {
                return this._fail("Unsupported VeNCrypt version " + major + "." + minor);
            }

            this._sock.sQpush8(0);
            this._sock.sQpush8(2);
            this._sock.flush();
            this._rfbVeNCryptState = 1;
        }

        // waiting for ACK
        if (this._rfbVeNCryptState == 1) {
            if (this._sock.rQwait("vencrypt ack", 1)) { return false; }

            const res = this._sock.rQshift8();

            if (res != 0) {
                return this._fail("VeNCrypt failure " + res);
            }

            this._rfbVeNCryptState = 2;
        }
        // must fall through here (i.e. no "else if"), beacause we may have already received
        // the subtypes length and won't be called again

        if (this._rfbVeNCryptState == 2) { // waiting for subtypes length
            if (this._sock.rQwait("vencrypt subtypes length", 1)) { return false; }

            const subtypesLength = this._sock.rQshift8();
            if (subtypesLength < 1) {
                return this._fail("VeNCrypt subtypes empty");
            }

            this._rfbVeNCryptSubtypesLength = subtypesLength;
            this._rfbVeNCryptState = 3;
        }

        // waiting for subtypes list
        if (this._rfbVeNCryptState == 3) {
            if (this._sock.rQwait("vencrypt subtypes", 4 * this._rfbVeNCryptSubtypesLength)) { return false; }

            const subtypes = [];
            for (let i = 0; i < this._rfbVeNCryptSubtypesLength; i++) {
                subtypes.push(this._sock.rQshift32());
            }

            // Look for a matching security type in the order that the
            // server prefers
            this._rfbAuthScheme = -1;
            for (let type of subtypes) {
                // Avoid getting in to a loop
                if (type === securityTypeVeNCrypt) {
                    continue;
                }

                if (this._isSupportedSecurityType(type)) {
                    this._rfbAuthScheme = type;
                    break;
                }
            }

            if (this._rfbAuthScheme === -1) {
                return this._fail("Unsupported security types (types: " + subtypes + ")");
            }

            this._sock.sQpush32(this._rfbAuthScheme);
            this._sock.flush();

            this._rfbVeNCryptState = 4;
            return true;
        }
    }

    _negotiatePlainAuth() {
        if (this._rfbCredentials.username === undefined ||
            this._rfbCredentials.password === undefined) {
            this.dispatchEvent(new CustomEvent(
                "credentialsrequired",
                { detail: { types: ["username", "password"] } }));
            return false;
        }

        const user = encodeUTF8(this._rfbCredentials.username);
        const pass = encodeUTF8(this._rfbCredentials.password);

        this._sock.sQpush32(user.length);
        this._sock.sQpush32(pass.length);
        this._sock.sQpushString(user);
        this._sock.sQpushString(pass);
        this._sock.flush();

        this._rfbInitState = "SecurityResult";
        return true;
    }

    _negotiateStdVNCAuth() {
        if (this._sock.rQwait("auth challenge", 16)) { return false; }

        if (this._rfbCredentials.password === undefined) {
            this.dispatchEvent(new CustomEvent(
                "credentialsrequired",
                { detail: { types: ["password"] } }));
            return false;
        }

        // TODO(directxman12): make genDES not require an Array
        const challenge = Array.prototype.slice.call(this._sock.rQshiftBytes(16));
        const response = RFB.genDES(this._rfbCredentials.password, challenge);
        this._sock.sQpushBytes(response);
        this._sock.flush();
        this._rfbInitState = "SecurityResult";
        return true;
    }

    // ARD encrypted event helpers

    _getArdECBCipher() {
        if (!this._ardECBCipher && this._ardDHKey) {
            this._ardECBCipher = AES128ECB.importKey(
                this._ardDHKey, { name: "AES-128-ECB" }, false, ["encrypt", "decrypt"]);
        }
        return this._ardECBCipher;
    }

    _handleArdSessionEncryption() {
        // Encoding 1103: server sends session key/IV encrypted with DH key
        // Payload: command(2) + version(2) + encryptedKey(16) + encryptedIV(16) = 36 bytes
        if (this._sock.rQwait("ArdSessionEncryption", 36)) {
            return false;
        }

        const cmdVersion = this._sock.rQshift32();  // command(2)+version(2) as u32
        if (cmdVersion !== 1) {
            Log.Warn("ARD: unexpected EncryptionInfo cmd/version: 0x" +
                     cmdVersion.toString(16));
        }

        const encKey = this._sock.rQshiftBytes(16);
        const encIV  = this._sock.rQshiftBytes(16);

        // Decrypt with AES-128-ECB using auth key (DH shared secret)
        const ecb = this._getArdECBCipher();
        this._ardSessionKey = ecb.decrypt({ name: "AES-128-ECB" }, encKey);
        this._ardSessionIV  = ecb.decrypt({ name: "AES-128-ECB" }, encIV);

        Log.Info("ARD: received session encryption key (encoding 1103)");

        // Flag for activation after current FBU completes
        this._ardPendingEncryption = true;
        return true;
    }

    _enableStreamEncryption() {
        const cbc = AES128CBC.importKey(
            this._ardSessionKey,
            { name: "AES-128-CBC" }, false, ["encrypt", "decrypt"]);
        this._sock.enableEncryption(cbc, SHA1, this._ardSessionIV);
        this._ardEncryptionEnabled = true;
        Log.Info("ARD: stream encryption enabled");

        // Any data remaining in the rQ after FBU processing is encrypted
        // server data that was buffered before encryption was enabled.
        // Re-route it through the decryption layer.
        this._sock.reprocessRemainingAsEncrypted();
    }

    _buildEncryptedKeyPayload(keysym, down) {
        const buf = new Uint8Array(16);
        buf[0] = 0xFF;
        buf[1] = down ? 1 : 0;
        const v = new DataView(buf.buffer);
        v.setUint32(2, keysym, false);
        v.setUint32(6, (performance.now() * 1000) >>> 0, false);
        // [10-11] reserved, [12-13] keycode, [14-15] unicode — left as zeros
        return buf;
    }

    _negotiateARDAuth() {
        Log.Info("ARD (type 30) authentication");

        if (this._rfbCredentials.username === undefined ||
            this._rfbCredentials.password === undefined) {
            this.dispatchEvent(new CustomEvent(
                "credentialsrequired",
                { detail: { types: ["username", "password"] } }));
            return false;
        }

        if (this._rfbCredentials.ardPublicKey != undefined &&
            this._rfbCredentials.ardCredentials != undefined) {
            // if the async web crypto is done return the results
            this._sock.sQpushBytes(this._rfbCredentials.ardCredentials);
            this._sock.sQpushBytes(this._rfbCredentials.ardPublicKey);
            this._sock.flush();
            this._rfbCredentials.ardCredentials = null;
            this._rfbCredentials.ardPublicKey = null;
            this._rfbInitState = "SecurityResult";
            return true;
        }

        if (this._sock.rQwait("read ard", 4)) { return false; }

        let generator = this._sock.rQshiftBytes(2);   // DH base generator value

        let keyLength = this._sock.rQshift16();

        if (this._sock.rQwait("read ard keylength", keyLength*2, 4)) { return false; }

        // read the server values
        let prime = this._sock.rQshiftBytes(keyLength);  // predetermined prime modulus
        let serverPublicKey = this._sock.rQshiftBytes(keyLength); // other party's public key

        let clientKey = legacyCrypto.generateKey(
            { name: "DH", g: generator, p: prime }, false, ["deriveBits"]);
        this._negotiateARDAuthAsync(keyLength, serverPublicKey, clientKey);

        return false;
    }

    // Pack username/password into a 128-byte credential buffer
    // (64 bytes each, null-terminated, random-padded)
    _packArdCredentials() {
        const username = encodeUTF8(this._rfbCredentials.username).substring(0, 63);
        const password = encodeUTF8(this._rfbCredentials.password).substring(0, 63);
        const buf = window.crypto.getRandomValues(new Uint8Array(128));
        for (let i = 0; i < username.length; i++) {
            buf[i] = username.charCodeAt(i);
        }
        buf[username.length] = 0;
        for (let i = 0; i < password.length; i++) {
            buf[64 + i] = password.charCodeAt(i);
        }
        buf[64 + password.length] = 0;
        return buf;
    }

    async _negotiateARDAuthAsync(keyLength, serverPublicKey, clientKey) {
        const clientPublicKey = legacyCrypto.exportKey("raw", clientKey.publicKey);
        const sharedKey = legacyCrypto.deriveBits(
            { name: "DH", public: serverPublicKey }, clientKey.privateKey, keyLength * 8);

        const credentials = this._packArdCredentials();

        const key = await legacyCrypto.digest("MD5", sharedKey);
        this._ardDHKey = new Uint8Array(key);
        const cipher = await legacyCrypto.importKey(
            "raw", key, { name: "AES-ECB" }, false, ["encrypt"]);
        const encrypted = await legacyCrypto.encrypt({ name: "AES-ECB" }, cipher, credentials);

        this._rfbCredentials.ardCredentials = encrypted;
        this._rfbCredentials.ardPublicKey = clientPublicKey;

        this._resumeAuthentication();
    }

    _negotiateRSATunnelAuth() {
        Log.Info("RSATunnel (type 33) authentication");

        // Stage 0: Check credentials
        if (this._rfbCredentials.username === undefined ||
            this._rfbCredentials.password === undefined) {
            this.dispatchEvent(new CustomEvent(
                "credentialsrequired",
                { detail: { types: ["username", "password"] } }));
            return false;
        }

        // Stage 3: Async results ready — send credentials
        if (this._ardRSATunnelStage === 3) {
            const { encryptedCreds, rsaCiphertext } = this._rfbCredentials.ardRSATunnelBlob;
            const rsaLen = rsaCiphertext.byteLength;
            const blobSize = 8 + 128 + 2 + rsaLen; // RSA1 header + creds + lenField + RSA ct

            // Length prefix (u32 BE)
            this._sock.sQpush32(blobSize);

            // RSA1 header (8 bytes)
            const header = new Uint8Array(8);
            const hView = new DataView(header.buffer);
            hView.setUint16(0, 1, true);          // version = 1 (LE)
            hView.setUint32(2, 0x31415352, true); // magic "RSA1" (LE)
            hView.setUint16(6, 1, false);         // sub-protocol = 1 Plain (BE)
            this._sock.sQpushBytes(header);

            // Encrypted credentials (128 bytes)
            this._sock.sQpushBytes(new Uint8Array(encryptedCreds));

            // RSA ciphertext length (u16 LE)
            const rsaLenBuf = new Uint8Array(2);
            new DataView(rsaLenBuf.buffer).setUint16(0, rsaLen, true);
            this._sock.sQpushBytes(rsaLenBuf);

            // RSA ciphertext
            this._sock.sQpushBytes(new Uint8Array(rsaCiphertext));
            this._sock.flush();

            this._rfbCredentials.ardRSATunnelBlob = null;
            this._ardRSATunnelStage = 4;
            Log.Info("RSATunnel: sent credential blob (" + blobSize + " bytes)");
        }

        // Stage 4: Wait for RSA response
        if (this._ardRSATunnelStage === 4) {
            if (this._sock.rQwait("RSATunnel response", 4)) { return false; }
            const responseLen = this._sock.rQshift32();
            if (responseLen > 4096) {
                return this._fail("RSATunnel: response too large (" +
                                  responseLen + " bytes)");
            }
            if (responseLen > 0) {
                if (this._sock.rQwait("RSATunnel response body", responseLen, 4)) { return false; }
                const responseData = this._sock.rQshiftBytes(responseLen);
                if (responseData.length >= 2) {
                    const view = new DataView(responseData.buffer, responseData.byteOffset);
                    const status = view.getUint16(0, true);
                    if (status !== 0) {
                        Log.Warn("RSATunnel: server response status: " + status +
                                 " — clearing cached RSA key");
                        // Cached key may be stale (server changed or different host
                        // behind the same gateway). Clear it so the next attempt
                        // fetches a fresh key.
                        this._clearCachedRSAKey();
                        if (status === 81 || status === 255) {
                            return this._fail("RSATunnel authentication denied");
                        }
                        return this._fail("RSATunnel authentication failed (status " +
                                          status + ") — please retry");
                    }
                }
            }
            this._ardRSATunnelStage = 0;
            this._rfbInitState = "SecurityResult";
            return true;
        }

        // Stage 0/1: Request server key or use cached
        if (this._ardRSATunnelStage === 0) {
            const cachedKey = this._getCachedRSAKey();
            if (cachedKey) {
                Log.Debug("RSATunnel: using cached server key");
                this._ardRSAServerKey = cachedKey;
                this._ardRSATunnelStage = 2;
            } else {
                // Send key request
                Log.Debug("RSATunnel: requesting server public key");

                // [u32be 10][u16le 1][u32le RSA1][u16be 0][u16 0] = 14 bytes
                this._sock.sQpush32(10);                // payload length (BE)
                const req = new Uint8Array(10);
                const rView = new DataView(req.buffer);
                rView.setUint16(0, 1, true);            // version = 1 (LE)
                rView.setUint32(2, 0x31415352, true);   // magic "RSA1" (LE)
                rView.setUint16(6, 0, false);           // sub-protocol = 0 Key Request (BE)
                rView.setUint16(8, 0, false);           // padding
                this._sock.sQpushBytes(req);
                this._sock.flush();

                this._ardRSATunnelStage = 1;
            }
        }

        // Stage 1: Read key response
        if (this._ardRSATunnelStage === 1) {
            if (this._sock.rQwait("RSATunnel key response length", 4)) { return false; }
            const payloadLen = this._sock.rQshift32(); // u32 BE
            if (payloadLen > 8192) {
                return this._fail("RSATunnel: key response too large (" +
                                  payloadLen + " bytes)");
            }

            if (this._sock.rQwait("RSATunnel key response", payloadLen, 4)) { return false; }
            const payload = this._sock.rQshiftBytes(payloadLen);
            const pView = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);

            // [u16le version][u16le respType][u16be keyDataLen][DER key][0x00]
            const keyDataLen = pView.getUint16(4, false); // BE
            const keyData = payload.slice(6, 6 + keyDataLen);

            const serverKey = RSACipher.parsePKCS1PublicKey(keyData);
            Log.Info("RSATunnel: received server key (" + (serverKey.n.length * 8) + "-bit)");

            this._ardRSAServerKey = serverKey;
            this._cacheRSAKey(serverKey);
            this._ardRSATunnelStage = 2;
        }

        // Stage 2: Start async credential encryption
        if (this._ardRSATunnelStage === 2) {
            this._negotiateRSATunnelAuthAsync(this._ardRSAServerKey);
            return false;
        }

        return false;
    }

    async _negotiateRSATunnelAuthAsync(serverKey) {
        try {
            // Generate 16 random bytes — used directly as AES key
            // (NOT MD5-hashed like Type 30)
            const randomBytes = window.crypto.getRandomValues(new Uint8Array(16));
            const aesKey = randomBytes.buffer;

            // Store as _ardDHKey for stream encryption (encoding 1103)
            this._ardDHKey = new Uint8Array(randomBytes);

            // Pack credentials (same format as Type 30)
            const credentials = this._packArdCredentials();

            // AES-ECB encrypt credentials
            const aesCipher = await legacyCrypto.importKey(
                "raw", aesKey, { name: "AES-ECB" }, false, ["encrypt"]);
            const encryptedCreds = await legacyCrypto.encrypt(
                { name: "AES-ECB" }, aesCipher, credentials);

            // RSA-PKCS1v1.5 encrypt the random bytes
            const n = serverKey.n;
            const e = new Uint8Array(n.length);
            e.set(serverKey.e, n.length - serverKey.e.length);
            const rsaCipher = await legacyCrypto.importKey(
                "raw", { n, e }, { name: "RSA-PKCS1-v1_5" }, false, ["encrypt"]);
            const rsaCiphertext = await legacyCrypto.encrypt(
                { name: "RSA-PKCS1-v1_5" }, rsaCipher, randomBytes);

            // Store results for sync re-entry
            this._rfbCredentials.ardRSATunnelBlob = { encryptedCreds, rsaCiphertext };
            this._ardRSATunnelStage = 3;
            this._resumeAuthentication();
        } catch (e) {
            Log.Error("RSATunnel async error: " + e.message + "\n" + e.stack);
            this._fail("RSATunnel auth error: " + e.message);
        }
    }

    _getCachedRSAKey() {
        if (!this._url) return null;
        try {
            const stored = localStorage.getItem('noVNC_rsaKey_' + this._url);
            if (!stored) return null;
            const parsed = JSON.parse(stored);
            return {
                n: new Uint8Array(parsed.n),
                e: new Uint8Array(parsed.e)
            };
        } catch (e) {
            return null;
        }
    }

    _cacheRSAKey(keyObj) {
        if (!this._url) return;
        try {
            localStorage.setItem('noVNC_rsaKey_' + this._url, JSON.stringify({
                n: Array.from(keyObj.n),
                e: Array.from(keyObj.e)
            }));
        } catch (e) {
            Log.Warn("Failed to cache RSA key: " + e);
        }
    }

    _clearCachedRSAKey() {
        if (!this._url) return;
        try {
            localStorage.removeItem('noVNC_rsaKey_' + this._url);
        } catch (e) {
            // ignore
        }
    }

    _negotiateTightUnixAuth() {
        if (this._rfbCredentials.username === undefined ||
            this._rfbCredentials.password === undefined) {
            this.dispatchEvent(new CustomEvent(
                "credentialsrequired",
                { detail: { types: ["username", "password"] } }));
            return false;
        }

        this._sock.sQpush32(this._rfbCredentials.username.length);
        this._sock.sQpush32(this._rfbCredentials.password.length);
        this._sock.sQpushString(this._rfbCredentials.username);
        this._sock.sQpushString(this._rfbCredentials.password);
        this._sock.flush();

        this._rfbInitState = "SecurityResult";
        return true;
    }

    _negotiateTightTunnels(numTunnels) {
        const clientSupportedTunnelTypes = {
            0: { vendor: 'TGHT', signature: 'NOTUNNEL' }
        };
        const serverSupportedTunnelTypes = {};
        // receive tunnel capabilities
        for (let i = 0; i < numTunnels; i++) {
            const capCode = this._sock.rQshift32();
            const capVendor = this._sock.rQshiftStr(4);
            const capSignature = this._sock.rQshiftStr(8);
            serverSupportedTunnelTypes[capCode] = { vendor: capVendor, signature: capSignature };
        }

        Log.Debug("Server Tight tunnel types: " + serverSupportedTunnelTypes);

        // Siemens touch panels have a VNC server that supports NOTUNNEL,
        // but forgets to advertise it. Try to detect such servers by
        // looking for their custom tunnel type.
        if (serverSupportedTunnelTypes[1] &&
            (serverSupportedTunnelTypes[1].vendor === "SICR") &&
            (serverSupportedTunnelTypes[1].signature === "SCHANNEL")) {
            Log.Debug("Detected Siemens server. Assuming NOTUNNEL support.");
            serverSupportedTunnelTypes[0] = { vendor: 'TGHT', signature: 'NOTUNNEL' };
        }

        // choose the notunnel type
        if (serverSupportedTunnelTypes[0]) {
            if (serverSupportedTunnelTypes[0].vendor != clientSupportedTunnelTypes[0].vendor ||
                serverSupportedTunnelTypes[0].signature != clientSupportedTunnelTypes[0].signature) {
                return this._fail("Client's tunnel type had the incorrect " +
                                  "vendor or signature");
            }
            Log.Debug("Selected tunnel type: " + clientSupportedTunnelTypes[0]);
            this._sock.sQpush32(0); // use NOTUNNEL
            this._sock.flush();
            return false; // wait until we receive the sub auth count to continue
        } else {
            return this._fail("Server wanted tunnels, but doesn't support " +
                              "the notunnel type");
        }
    }

    _negotiateTightAuth() {
        if (!this._rfbTightVNC) {  // first pass, do the tunnel negotiation
            if (this._sock.rQwait("num tunnels", 4)) { return false; }
            const numTunnels = this._sock.rQshift32();
            if (numTunnels > 0 && this._sock.rQwait("tunnel capabilities", 16 * numTunnels, 4)) { return false; }

            this._rfbTightVNC = true;

            if (numTunnels > 0) {
                this._negotiateTightTunnels(numTunnels);
                return false;  // wait until we receive the sub auth to continue
            }
        }

        // second pass, do the sub-auth negotiation
        if (this._sock.rQwait("sub auth count", 4)) { return false; }
        const subAuthCount = this._sock.rQshift32();
        if (subAuthCount === 0) {  // empty sub-auth list received means 'no auth' subtype selected
            this._rfbInitState = 'SecurityResult';
            return true;
        }

        if (this._sock.rQwait("sub auth capabilities", 16 * subAuthCount, 4)) { return false; }

        const clientSupportedTypes = {
            'STDVNOAUTH__': 1,
            'STDVVNCAUTH_': 2,
            'TGHTULGNAUTH': 129
        };

        const serverSupportedTypes = [];

        for (let i = 0; i < subAuthCount; i++) {
            this._sock.rQshift32(); // capNum
            const capabilities = this._sock.rQshiftStr(12);
            serverSupportedTypes.push(capabilities);
        }

        Log.Debug("Server Tight authentication types: " + serverSupportedTypes);

        for (let authType in clientSupportedTypes) {
            if (serverSupportedTypes.indexOf(authType) != -1) {
                this._sock.sQpush32(clientSupportedTypes[authType]);
                this._sock.flush();
                Log.Debug("Selected authentication type: " + authType);

                switch (authType) {
                    case 'STDVNOAUTH__':  // no auth
                        this._rfbInitState = 'SecurityResult';
                        return true;
                    case 'STDVVNCAUTH_':
                        this._rfbAuthScheme = securityTypeVNCAuth;
                        return true;
                    case 'TGHTULGNAUTH':
                        this._rfbAuthScheme = securityTypeUnixLogon;
                        return true;
                    default:
                        return this._fail("Unsupported tiny auth scheme " +
                                          "(scheme: " + authType + ")");
                }
            }
        }

        return this._fail("No supported sub-auth types!");
    }

    _handleRSAAESCredentialsRequired(event) {
        this.dispatchEvent(event);
    }

    _handleRSAAESServerVerification(event) {
        this.dispatchEvent(event);
    }

    _negotiateRA2neAuth() {
        if (this._rfbRSAAESAuthenticationState === null) {
            this._rfbRSAAESAuthenticationState = new RSAAESAuthenticationState(this._sock, () => this._rfbCredentials);
            this._rfbRSAAESAuthenticationState.addEventListener(
                "serververification", this._eventHandlers.handleRSAAESServerVerification);
            this._rfbRSAAESAuthenticationState.addEventListener(
                "credentialsrequired", this._eventHandlers.handleRSAAESCredentialsRequired);
        }
        this._rfbRSAAESAuthenticationState.checkInternalEvents();
        if (!this._rfbRSAAESAuthenticationState.hasStarted) {
            this._rfbRSAAESAuthenticationState.negotiateRA2neAuthAsync()
                .catch((e) => {
                    if (e.message !== "disconnect normally") {
                        this._fail(e.message);
                    }
                })
                .then(() => {
                    this._rfbInitState = "SecurityResult";
                    return true;
                }).finally(() => {
                    this._rfbRSAAESAuthenticationState.removeEventListener(
                        "serververification", this._eventHandlers.handleRSAAESServerVerification);
                    this._rfbRSAAESAuthenticationState.removeEventListener(
                        "credentialsrequired", this._eventHandlers.handleRSAAESCredentialsRequired);
                    this._rfbRSAAESAuthenticationState = null;
                });
        }
        return false;
    }

    _negotiateMSLogonIIAuth() {
        if (this._sock.rQwait("mslogonii dh param", 24)) { return false; }

        if (this._rfbCredentials.username === undefined ||
            this._rfbCredentials.password === undefined) {
            this.dispatchEvent(new CustomEvent(
                "credentialsrequired",
                { detail: { types: ["username", "password"] } }));
            return false;
        }

        const g = this._sock.rQshiftBytes(8);
        const p = this._sock.rQshiftBytes(8);
        const A = this._sock.rQshiftBytes(8);
        const dhKey = legacyCrypto.generateKey({ name: "DH", g: g, p: p }, true, ["deriveBits"]);
        const B = legacyCrypto.exportKey("raw", dhKey.publicKey);
        const secret = legacyCrypto.deriveBits({ name: "DH", public: A }, dhKey.privateKey, 64);

        const key = legacyCrypto.importKey("raw", secret, { name: "DES-CBC" }, false, ["encrypt"]);
        const username = encodeUTF8(this._rfbCredentials.username).substring(0, 255);
        const password = encodeUTF8(this._rfbCredentials.password).substring(0, 63);
        let usernameBytes = new Uint8Array(256);
        let passwordBytes = new Uint8Array(64);
        window.crypto.getRandomValues(usernameBytes);
        window.crypto.getRandomValues(passwordBytes);
        for (let i = 0; i < username.length; i++) {
            usernameBytes[i] = username.charCodeAt(i);
        }
        usernameBytes[username.length] = 0;
        for (let i = 0; i < password.length; i++) {
            passwordBytes[i] = password.charCodeAt(i);
        }
        passwordBytes[password.length] = 0;
        usernameBytes = legacyCrypto.encrypt({ name: "DES-CBC", iv: secret }, key, usernameBytes);
        passwordBytes = legacyCrypto.encrypt({ name: "DES-CBC", iv: secret }, key, passwordBytes);
        this._sock.sQpushBytes(B);
        this._sock.sQpushBytes(usernameBytes);
        this._sock.sQpushBytes(passwordBytes);
        this._sock.flush();
        this._rfbInitState = "SecurityResult";
        return true;
    }

    _negotiateAuthentication() {
        switch (this._rfbAuthScheme) {
            case securityTypeNone:
                if (this._rfbVersion >= 3.8) {
                    this._rfbInitState = 'SecurityResult';
                } else {
                    this._rfbInitState = 'ClientInitialisation';
                }
                return true;

            case securityTypeXVP:
                return this._negotiateXvpAuth();

            case securityTypeARD:
                return this._negotiateARDAuth();

            case securityTypeRSATunnel:
                return this._negotiateRSATunnelAuth();

            case securityTypeVNCAuth:
                return this._negotiateStdVNCAuth();

            case securityTypeTight:
                return this._negotiateTightAuth();

            case securityTypeVeNCrypt:
                return this._negotiateVeNCryptAuth();

            case securityTypePlain:
                return this._negotiatePlainAuth();

            case securityTypeUnixLogon:
                return this._negotiateTightUnixAuth();

            case securityTypeRA2ne:
                return this._negotiateRA2neAuth();

            case securityTypeMSLogonII:
                return this._negotiateMSLogonIIAuth();

            default:
                return this._fail("Unsupported auth scheme (scheme: " +
                                  this._rfbAuthScheme + ")");
        }
    }

    _handleSecurityResult() {
        if (this._sock.rQwait('VNC auth response ', 4)) { return false; }

        clearTimeout(this._authTimer);
        this._authTimer = null;

        const status = this._sock.rQshift32();

        if (status === 0) { // OK
            this._rfbInitState = 'ClientInitialisation';
            Log.Debug('Authentication OK');
            return true;
        } else {
            if (this._rfbVersion >= 3.8) {
                this._rfbInitState = "SecurityReason";
                this._securityContext = "security result";
                this._securityStatus = status;
                return true;
            } else {
                this.dispatchEvent(new CustomEvent(
                    "securityfailure",
                    { detail: { status: status } }));

                return this._fail("Security handshake failed");
            }
        }
    }

    _negotiateServerInit() {
        if (this._sock.rQwait("server initialization", 24)) { return false; }

        /* Screen size */
        const width = this._sock.rQshift16();
        const height = this._sock.rQshift16();

        /* PIXEL_FORMAT */
        const bpp         = this._sock.rQshift8();
        const depth       = this._sock.rQshift8();
        const bigEndian  = this._sock.rQshift8();
        const trueColor  = this._sock.rQshift8();

        const redMax     = this._sock.rQshift16();
        const greenMax   = this._sock.rQshift16();
        const blueMax    = this._sock.rQshift16();
        const redShift   = this._sock.rQshift8();
        const greenShift = this._sock.rQshift8();
        const blueShift  = this._sock.rQshift8();
        this._sock.rQskipBytes(3);  // padding

        // NB(directxman12): we don't want to call any callbacks or print messages until
        //                   *after* we're past the point where we could backtrack

        /* Connection name/title */
        const nameLength = this._sock.rQshift32();
        if (this._sock.rQwait('server init name', nameLength, 24)) { return false; }
        let name = this._sock.rQshiftStr(nameLength);

        // ARD ServerInit name has a 22-byte binary prefix (flags + capabilities).
        // Strip it before UTF-8 decoding.
        if (this._rfbAppleARD && nameLength >= 22 && name.charCodeAt(0) === 0x00) {
            // Parse and log all server-advertised fields before discarding the prefix.
            //
            // Session flags (bytes 2-5, u32be):
            //   bit 0 = observePermitted, bit 1 = mayControlPermitted,
            //   bit 2 = sessionSelectNeeded, bit 3 = dontConnectToVirtualDisplay
            //
            // Capability bitmap (bytes 6-21, 16 bytes):
            //   bytes 6-9 = 32-bit access rights bitmask (Section 16.1):
            //     bit 0=Chat, 1=Observe, 2=SendFiles, 3=DeleteFiles,
            //     4=GenerateReports, 5=OpenQuitApps, 6=ChangeSettings,
            //     7=PowerManagement, 8=Control(inverted),
            //     30=ShowObserverNotification, 31=Encrypted
            //   bytes 10-21 = remaining capability bits (unknown assignments)
            const serverFlags = ((name.charCodeAt(2) << 24) |
                                  (name.charCodeAt(3) << 16) |
                                  (name.charCodeAt(4) << 8)  |
                                   name.charCodeAt(5)) >>> 0;
            const accessRights = ((name.charCodeAt(6) << 24) |
                                   (name.charCodeAt(7) << 16) |
                                   (name.charCodeAt(8) << 8)  |
                                    name.charCodeAt(9)) >>> 0;
            let capHex = '';
            for (let i = 6; i < 22; i++) {
                capHex += name.charCodeAt(i).toString(16).padStart(2, '0');
                if (i < 21) capHex += ' ';
            }
            const canControl = (accessRights & 0x02) !== 0 && (accessRights & 0x100) === 0;
            Log.Info("ARD ServerInit: sessionFlags=0x" +
                     serverFlags.toString(16).padStart(8, '0') +
                     " (observeOK=" + ((serverFlags & 0x01) !== 0) +
                     " controlOK=" + ((serverFlags & 0x02) !== 0) +
                     " sessionSelect=" + ((serverFlags & 0x04) !== 0) +
                     " noVirtualDisplay=" + ((serverFlags & 0x08) !== 0) + ")" +
                     "\nARD ServerInit: accessRights=0x" +
                     accessRights.toString(16).padStart(8, '0') +
                     " canControl=" + canControl +
                     " (chat=" + ((accessRights & 0x01) !== 0) +
                     " observe=" + ((accessRights & 0x02) !== 0) +
                     " sendFiles=" + ((accessRights & 0x04) !== 0) +
                     " deleteFiles=" + ((accessRights & 0x08) !== 0) +
                     " reports=" + ((accessRights & 0x10) !== 0) +
                     " openApps=" + ((accessRights & 0x20) !== 0) +
                     " changeSettings=" + ((accessRights & 0x40) !== 0) +
                     " power=" + ((accessRights & 0x80) !== 0) +
                     " controlBlocked=" + ((accessRights & 0x100) !== 0) +
                     " showObserver=" + ((accessRights & 0x40000000) !== 0) +
                     " encrypted=" + ((accessRights & 0x80000000) !== 0) + ")" +
                     "\nARD ServerInit: capabilityBitmap=[" + capHex + "]");
            name = name.substring(name.lastIndexOf('\x00') + 1);
        }

        name = decodeUTF8(name, true);

        if (this._rfbTightVNC) {
            if (this._sock.rQwait('TightVNC extended server init header', 8, 24 + nameLength)) { return false; }
            // In TightVNC mode, ServerInit message is extended
            const numServerMessages = this._sock.rQshift16();
            const numClientMessages = this._sock.rQshift16();
            const numEncodings = this._sock.rQshift16();
            this._sock.rQskipBytes(2);  // padding

            const totalMessagesLength = (numServerMessages + numClientMessages + numEncodings) * 16;
            if (this._sock.rQwait('TightVNC extended server init header', totalMessagesLength, 32 + nameLength)) { return false; }

            // we don't actually do anything with the capability information that TIGHT sends,
            // so we just skip the all of this.

            // TIGHT server message capabilities
            this._sock.rQskipBytes(16 * numServerMessages);

            // TIGHT client message capabilities
            this._sock.rQskipBytes(16 * numClientMessages);

            // TIGHT encoding capabilities
            this._sock.rQskipBytes(16 * numEncodings);
        }

        // NB(directxman12): these are down here so that we don't run them multiple times
        //                   if we backtrack
        Log.Info("Screen: " + width + "x" + height +
                  ", bpp: " + bpp + ", depth: " + depth +
                  ", bigEndian: " + bigEndian +
                  ", trueColor: " + trueColor +
                  ", redMax: " + redMax +
                  ", greenMax: " + greenMax +
                  ", blueMax: " + blueMax +
                  ", redShift: " + redShift +
                  ", greenShift: " + greenShift +
                  ", blueShift: " + blueShift);

        // we're past the point where we could backtrack, so it's safe to call this
        this._setDesktopName(name);
        this._resize(width, height);

        if (!this._viewOnly) {
            this._keyboard.grab();
            this._asyncClipboard.grab();
        }

        this._fbDepth = 24;

        if (this._fbName === "Intel(r) AMT KVM") {
            Log.Warn("Intel AMT KVM only supports 8/16 bit depths. Using low color mode.");
            this._fbDepth = 8;
        }

        if (this._rfbAppleARD) {
            // Check if Session Select is needed
            const sessionSelectNeeded = (serverFlags & 0x04) !== 0;
            this._ardSessionSelectNeeded = sessionSelectNeeded;

            if (sessionSelectNeeded) {
                Log.Info("ARD init: Session Select required (fb=" +
                         this._fbWidth + "x" + this._fbHeight + " name=" + this._fbName + ")");
                // Session Select protocol runs before normal ARD init
                // Will transition to ARD init after session is granted
                this._rfbInitState = 'SessionSelectInfo';
                return true;
            }

            Log.Info("ARD init: fb=" + this._fbWidth + "x" + this._fbHeight +
                     " name=" + this._fbName);
            // ARD init sequence (Phase 5 + 6):
            // ViewerInfo → SetMode → SetDisplay → AutoPasteboard
            // → SetEncodings → PixelFormat → SetEncodings → SetEncryption
            // → FBUpdateRequest(incremental=0) → AutoFBUpdate
            // Native macOS client sends SetEncodings twice: once before
            // and once after SetPixelFormat.
            Log.Info("ARD init [1/10] ViewerInfo");
            this._sendArdViewerInfo();
            Log.Info("ARD init [2/10] SetMode(Control)");
            this._ardControlMode = 1;      // default: Control (shared)
            this._sendArdSetMode(1);
            Log.Info("ARD init [3/10] SetDisplay(combineAll=1, All)");
            this._sendArdSetDisplay();
            Log.Info("ARD init [4/10] AutoPasteboard(1)");
            this._sendArdAutoPasteboard(1);
            Log.Info("ARD init [5/10] SetEncodings(preset=" + this._ardQualityPreset + ")");
            this._sendEncodings();
            Log.Info("ARD init [6/10] PixelFormat(32bpp depth=" + this._fbDepth + ")");
            RFB.messages.pixelFormat(this._sock, this._fbDepth, true, 16, 8, 0);
            Log.Info("ARD init [7/10] SetEncodings(repeat)");
            this._sendEncodings();

            if (this._ardDHKey) {
                Log.Info("ARD init [8/10] SetEncryption(request)");
                RFB.messages.ardSetEncryption(this._sock, 1);
            } else {
                Log.Info("ARD init [8/10] SetEncryption skipped (no DH key)");
            }

            Log.Info("ARD init [9/11] FBUpdateRequest(full)");
            RFB.messages.fbUpdateRequest(this._sock, false, 0, 0,
                                         this._fbWidth, this._fbHeight);
            Log.Info("ARD init [10/11] AutoFBUpdate(enable)");
            this._sendArdAutoFBUpdate(1, 0, 0,
                                      this._fbWidth, this._fbHeight);
            this._sock.flush();
            setTimeout(() => {
                if (this._rfbConnectionState !== 'connected') return;
                Log.Info("ARD init [11/11] FBUpdateRequest+AutoFBUpdate(delayed 50ms)");
                RFB.messages.fbUpdateRequest(this._sock, false, 0, 0,
                                             this._fbWidth, this._fbHeight);
                this._sendArdAutoFBUpdate(1, 0, 0,
                                          this._fbWidth, this._fbHeight);
                this._sock.flush();
            }, 50);

            // Set default arrow cursor and track first-FBU cursor delivery
            this._ardActiveCursor = { type: 'system', id: 0 };
            this._setArdSystemCursor(0);
            this._ardGotCursor = false;
            this._ardFirstDisplayInfo = true;
            this._ardPhase3Pending = false;
        } else {
            RFB.messages.pixelFormat(this._sock, this._fbDepth, true);
            this._sendEncodings();
            RFB.messages.fbUpdateRequest(this._sock, false, 0, 0,
                                         this._fbWidth, this._fbHeight);
        }

        this._updateConnectionState('connected');
        return true;
    }

    _sendEncodings() {
        if (this._rfbAppleARD) {
            const presetEncodings = {
                halftone: [1000, 16, 6],
                gray: [1001, 16, 6],
                thousands: [1002, 16, 6],
                millions: [16, 6],
            };
            const encs = (presetEncodings[this._ardQualityPreset] ||
                          presetEncodings.millions).slice();
            encs.push(encodings.pseudoEncodingCursor);
            encs.push(encodings.pseudoEncodingArdCursorAlpha);
            encs.push(encodings.pseudoEncodingArdCursorPos);
            encs.push(encodings.pseudoEncodingDesktopSize);
            encs.push(encodings.pseudoEncodingArdDisplayInfo);
            encs.push(encodings.pseudoEncodingArdDisplayInfo2);
            encs.push(encodings.pseudoEncodingArdSessionEncryption);
            encs.push(encodings.pseudoEncodingArdUserInfo);
            RFB.messages.clientEncodings(this._sock, encs);
            return;
        }

        const encs = [];

        // In preference order
        encs.push(encodings.encodingCopyRect);
        // Only supported with full depth support
        if (this._fbDepth == 24) {
            if (supportsWebCodecsH264Decode) {
                encs.push(encodings.encodingH264);
            }
            encs.push(encodings.encodingTight);
            encs.push(encodings.encodingTightPNG);
            encs.push(encodings.encodingZRLE);
            encs.push(encodings.encodingJPEG);
            encs.push(encodings.encodingHextile);
            encs.push(encodings.encodingRRE);
            encs.push(encodings.encodingZlib);
        }
        encs.push(encodings.encodingRaw);

        // Psuedo-encoding settings
        encs.push(encodings.pseudoEncodingQualityLevel0 + this._qualityLevel);
        encs.push(encodings.pseudoEncodingCompressLevel0 + this._compressionLevel);

        encs.push(encodings.pseudoEncodingDesktopSize);
        encs.push(encodings.pseudoEncodingLastRect);
        encs.push(encodings.pseudoEncodingQEMUExtendedKeyEvent);
        encs.push(encodings.pseudoEncodingQEMULedEvent);
        encs.push(encodings.pseudoEncodingExtendedDesktopSize);
        encs.push(encodings.pseudoEncodingXvp);
        encs.push(encodings.pseudoEncodingFence);
        encs.push(encodings.pseudoEncodingContinuousUpdates);
        encs.push(encodings.pseudoEncodingDesktopName);
        encs.push(encodings.pseudoEncodingExtendedClipboard);
        encs.push(encodings.pseudoEncodingExtendedMouseButtons);

        if (this._fbDepth == 24) {
            encs.push(encodings.pseudoEncodingVMwareCursor);
            encs.push(encodings.pseudoEncodingCursor);
        }

        RFB.messages.clientEncodings(this._sock, encs);
    }

    _handleSessionInfo() {
        // Session Select: SessionInfo (S→C)
        // [u16be bodySize][u16be version=0x0100][u32be allowedCommands][u32 reserved][null-terminated username]
        if (this._sock.rQwait("SessionInfo header", 2)) { return false; }

        const bodySize = this._sock.rQpeek16();
        if (this._sock.rQwait("SessionInfo body", bodySize, 2)) { return false; }

        this._sock.rQskipBytes(2); // bodySize
        const version = this._sock.rQshift16();
        const allowedCommands = this._sock.rQshift32();
        this._sock.rQskipBytes(4); // reserved

        // Read null-terminated console username
        const remainingBytes = bodySize - 10; // 2 (version) + 4 (allowedCommands) + 4 (reserved)
        const usernameBytes = this._sock.rQshiftBytes(remainingBytes);
        let username = '';
        for (let i = 0; i < usernameBytes.length; i++) {
            if (usernameBytes[i] === 0) break;
            username += String.fromCharCode(usernameBytes[i]);
        }
        this._ardSessionSelectConsoleUser = username;

        Log.Info("ARD SessionInfo: version=0x" + version.toString(16).padStart(4, '0') +
                 " allowedCommands=0x" + allowedCommands.toString(16).padStart(8, '0') +
                 " consoleUser=" + (username || "(none)"));

        // Send SessionCommand: ConnectToConsole (command=1)
        // Default to always connect to console (physical display)
        this._sendSessionCommand(1); // 1 = ConnectToConsole

        this._rfbInitState = 'SessionSelectResult';
        return true;
    }

    _sendSessionCommand(command) {
        // SessionCommand v1: [u16be bodySize=72][u16be version=1][pad4][u8 cmd][pad][char[64] username]
        const bodySize = 72;
        const version = 1;
        const username = this._ardSessionSelectConsoleUser || '';

        this._sock.sQpush16(bodySize);
        this._sock.sQpush16(version);
        this._sock.sQpush32(0); // padding
        this._sock.sQpush8(command);
        this._sock.sQpush8(0); // padding

        // Username field: 64 bytes, null-padded
        for (let i = 0; i < 64; i++) {
            this._sock.sQpush8(i < username.length ? username.charCodeAt(i) : 0);
        }

        this._sock.flush();

        const commandName = (command === 0) ? 'RequestConsole' :
                            (command === 1) ? 'ConnectToConsole' :
                            (command === 2) ? 'ConnectToVirtualDisplay' : 'Unknown';
        Log.Info("ARD SessionCommand: " + commandName + " (cmd=" + command +
                 " user=" + (username || "(none)") + ")");
    }

    _handleSessionResult() {
        // SessionResult: [u16be bodySize=80][u16be version=1][u32be status][74 bytes reserved]
        if (this._sock.rQwait("SessionResult header", 2)) { return false; }

        const bodySize = this._sock.rQpeek16();
        if (this._sock.rQwait("SessionResult body", bodySize, 2)) { return false; }

        this._sock.rQskipBytes(2); // bodySize
        const version = this._sock.rQshift16();
        const status = this._sock.rQshift32();
        this._sock.rQskipBytes(bodySize - 6); // skip remaining reserved bytes

        const statusName = (status === 0) ? 'Granted' :
                           (status === 2) ? 'Pending' :
                           (status === 3) ? 'Pending' :
                           (status === 4) ? 'Granted' : 'Unknown';
        Log.Info("ARD SessionResult: status=" + status + " (" + statusName + ")");

        if (status === 2 || status === 3) {
            // Pending - wait for another SessionResult
            Log.Info("ARD SessionResult: waiting for next result...");
            // Stay in same state to read next SessionResult
            return true;
        }

        if (status === 0 || status === 4) {
            // Granted - proceed with ARD init
            Log.Info("ARD SessionResult: session granted, starting ARD init");
            this._ardSessionSelectNeeded = false;

            // Now proceed with normal ARD init sequence
            Log.Info("ARD init: fb=" + this._fbWidth + "x" + this._fbHeight +
                     " name=" + this._fbName);
            Log.Info("ARD init [1/10] ViewerInfo");
            this._sendArdViewerInfo();
            Log.Info("ARD init [2/10] SetMode(Control)");
            this._ardControlMode = 1;
            this._sendArdSetMode(1);
            Log.Info("ARD init [3/10] SetDisplay(combineAll=1, All)");
            this._sendArdSetDisplay();
            Log.Info("ARD init [4/10] AutoPasteboard(1)");
            this._sendArdAutoPasteboard(1);
            Log.Info("ARD init [5/10] SetEncodings(preset=" + this._ardQualityPreset + ")");
            this._sendEncodings();
            Log.Info("ARD init [6/10] PixelFormat(32bpp depth=" + this._fbDepth + ")");
            RFB.messages.pixelFormat(this._sock, this._fbDepth, true, 16, 8, 0);
            Log.Info("ARD init [7/10] SetEncodings(repeat)");
            this._sendEncodings();

            if (this._ardDHKey) {
                Log.Info("ARD init [8/10] SetEncryption(request)");
                RFB.messages.ardSetEncryption(this._sock, 1);
            } else {
                Log.Info("ARD init [8/10] SetEncryption skipped (no DH key)");
            }

            Log.Info("ARD init [9/11] FBUpdateRequest(full)");
            RFB.messages.fbUpdateRequest(this._sock, false, 0, 0,
                                         this._fbWidth, this._fbHeight);
            Log.Info("ARD init [10/11] AutoFBUpdate(enable)");
            this._sendArdAutoFBUpdate(1, 0, 0,
                                      this._fbWidth, this._fbHeight);
            this._sock.flush();
            setTimeout(() => {
                if (this._rfbConnectionState !== 'connected') return;
                Log.Info("ARD init [11/11] FBUpdateRequest+AutoFBUpdate(delayed 50ms)");
                RFB.messages.fbUpdateRequest(this._sock, false, 0, 0,
                                             this._fbWidth, this._fbHeight);
                this._sendArdAutoFBUpdate(1, 0, 0,
                                          this._fbWidth, this._fbHeight);
                this._sock.flush();
            }, 50);

            // Set default arrow cursor and track first-FBU cursor delivery
            this._ardActiveCursor = { type: 'system', id: 0 };
            this._setArdSystemCursor(0);
            this._ardGotCursor = false;
            this._ardFirstDisplayInfo = true;
            this._ardPhase3Pending = false;

            this._updateConnectionState('connected');
            return true;
        }

        // Any other status is an error
        return this._fail("Session Select failed: status=" + status);
    }

    /* RFB protocol initialization states:
     *   ProtocolVersion
     *   Security
     *   Authentication
     *   SecurityResult
     *   ClientInitialization - not triggered by server message
     *   ServerInitialization
     */
    _initMsg() {
        switch (this._rfbInitState) {
            case 'ProtocolVersion':
                return this._negotiateProtocolVersion();

            case 'Security':
                return this._negotiateSecurity();

            case 'Authentication':
                return this._negotiateAuthentication();

            case 'SecurityResult':
                if (!this._authTimer) {
                    this._authTimer = setTimeout(() => {
                        this._authTimer = null;
                        this._fail("Authentication timed out");
                    }, 10000);
                }
                return this._handleSecurityResult();

            case 'SecurityReason':
                return this._handleSecurityReason();

            case 'ClientInitialisation':
                // 0xc1 = shared (bit 0) + ARD extension flags (bits 6-7)
                this._sock.sQpush8(this._rfbAppleARD ? 0xc1 :
                    (this._shared ? 1 : 0));
                this._sock.flush();
                this._rfbInitState = 'ServerInitialisation';
                return true;

            case 'ServerInitialisation':
                return this._negotiateServerInit();

            case 'SessionSelectInfo':
                return this._handleSessionInfo();

            case 'SessionSelectResult':
                return this._handleSessionResult();

            default:
                return this._fail("Unknown init state (state: " +
                                  this._rfbInitState + ")");
        }
    }

    // Resume authentication handshake after it was paused for some
    // reason, e.g. waiting for a password from the user
    _resumeAuthentication() {
        // We use setTimeout() so it's run in its own context, just like
        // it originally did via the WebSocket's event handler
        setTimeout(this._initMsg.bind(this), 0);
    }

    _handleSetColourMapMsg() {
        Log.Debug("SetColorMapEntries");

        return this._fail("Unexpected SetColorMapEntries message");
    }

    _writeClipboard(text) {
        if (this._viewOnly) return;
        if (this._asyncClipboard.writeClipboard(text)) return;
        // Fallback clipboard
        this.dispatchEvent(
            new CustomEvent("clipboard", {detail: {text: text}})
        );
    }

    _handleServerCutText() {
        Log.Debug("ServerCutText");

        if (this._sock.rQwait("ServerCutText header", 7, 1)) { return false; }

        this._sock.rQskipBytes(3);  // Padding

        let length = this._sock.rQshift32();
        length = toSigned32bit(length);

        if (this._sock.rQwait("ServerCutText content", Math.abs(length), 8)) { return false; }

        if (length >= 0) {
            //Standard msg
            const text = this._sock.rQshiftStr(length);
            if (this._viewOnly) {
                return true;
            }

            this._writeClipboard(text);

        } else {
            //Extended msg.
            length = Math.abs(length);
            const flags = this._sock.rQshift32();
            let formats = flags & 0x0000FFFF;
            let actions = flags & 0xFF000000;

            let isCaps = (!!(actions & extendedClipboardActionCaps));
            if (isCaps) {
                this._clipboardServerCapabilitiesFormats = {};
                this._clipboardServerCapabilitiesActions = {};

                // Update our server capabilities for Formats
                for (let i = 0; i <= 15; i++) {
                    let index = 1 << i;

                    // Check if format flag is set.
                    if ((formats & index)) {
                        this._clipboardServerCapabilitiesFormats[index] = true;
                        // We don't send unsolicited clipboard, so we
                        // ignore the size
                        this._sock.rQshift32();
                    }
                }

                // Update our server capabilities for Actions
                for (let i = 24; i <= 31; i++) {
                    let index = 1 << i;
                    this._clipboardServerCapabilitiesActions[index] = !!(actions & index);
                }

                /*  Caps handling done, send caps with the clients
                    capabilities set as a response */
                let clientActions = [
                    extendedClipboardActionCaps,
                    extendedClipboardActionRequest,
                    extendedClipboardActionPeek,
                    extendedClipboardActionNotify,
                    extendedClipboardActionProvide
                ];
                RFB.messages.extendedClipboardCaps(this._sock, clientActions, {extendedClipboardFormatText: 0});

            } else if (actions === extendedClipboardActionRequest) {
                if (this._viewOnly) {
                    return true;
                }

                // Check if server has told us it can handle Provide and there is clipboard data to send.
                if (this._clipboardText != null &&
                    this._clipboardServerCapabilitiesActions[extendedClipboardActionProvide]) {

                    if (formats & extendedClipboardFormatText) {
                        RFB.messages.extendedClipboardProvide(this._sock, [extendedClipboardFormatText], [this._clipboardText]);
                    }
                }

            } else if (actions === extendedClipboardActionPeek) {
                if (this._viewOnly) {
                    return true;
                }

                if (this._clipboardServerCapabilitiesActions[extendedClipboardActionNotify]) {

                    if (this._clipboardText != null) {
                        RFB.messages.extendedClipboardNotify(this._sock, [extendedClipboardFormatText]);
                    } else {
                        RFB.messages.extendedClipboardNotify(this._sock, []);
                    }
                }

            } else if (actions === extendedClipboardActionNotify) {
                if (this._viewOnly) {
                    return true;
                }

                if (this._clipboardServerCapabilitiesActions[extendedClipboardActionRequest]) {

                    if (formats & extendedClipboardFormatText) {
                        RFB.messages.extendedClipboardRequest(this._sock, [extendedClipboardFormatText]);
                    }
                }

            } else if (actions === extendedClipboardActionProvide) {
                if (this._viewOnly) {
                    return true;
                }

                if (!(formats & extendedClipboardFormatText)) {
                    return true;
                }
                // Ignore what we had in our clipboard client side.
                this._clipboardText = null;

                // FIXME: Should probably verify that this data was actually requested
                let zlibStream = this._sock.rQshiftBytes(length - 4);
                let streamInflator = new Inflator();
                let textData = null;

                streamInflator.setInput(zlibStream);
                for (let i = 0; i <= 15; i++) {
                    let format = 1 << i;

                    if (formats & format) {

                        let size = 0x00;
                        let sizeArray = streamInflator.inflate(4);

                        size |= (sizeArray[0] << 24);
                        size |= (sizeArray[1] << 16);
                        size |= (sizeArray[2] << 8);
                        size |= (sizeArray[3]);
                        let chunk = streamInflator.inflate(size);

                        if (format === extendedClipboardFormatText) {
                            textData = chunk;
                        }
                    }
                }
                streamInflator.setInput(null);

                if (textData !== null) {
                    let tmpText = "";
                    for (let i = 0; i < textData.length; i++) {
                        tmpText += String.fromCharCode(textData[i]);
                    }
                    textData = tmpText;

                    textData = decodeUTF8(textData);
                    if ((textData.length > 0) && "\0" === textData.charAt(textData.length - 1)) {
                        textData = textData.slice(0, -1);
                    }

                    textData = textData.replaceAll("\r\n", "\n");

                    this._writeClipboard(textData);
                }
            } else {
                return this._fail("Unexpected action in extended clipboard message: " + actions);
            }
        }
        return true;
    }

    _handleServerFenceMsg() {
        if (this._sock.rQwait("ServerFence header", 8, 1)) { return false; }
        this._sock.rQskipBytes(3); // Padding
        let flags = this._sock.rQshift32();
        let length = this._sock.rQshift8();

        if (this._sock.rQwait("ServerFence payload", length, 9)) { return false; }

        if (length > 64) {
            Log.Warn("Bad payload length (" + length + ") in fence response");
            length = 64;
        }

        const payload = this._sock.rQshiftStr(length);

        this._supportsFence = true;

        /*
         * Fence flags
         *
         *  (1<<0)  - BlockBefore
         *  (1<<1)  - BlockAfter
         *  (1<<2)  - SyncNext
         *  (1<<31) - Request
         */

        if (!(flags & (1<<31))) {
            return this._fail("Unexpected fence response");
        }

        // Filter out unsupported flags
        // FIXME: support syncNext
        flags &= (1<<0) | (1<<1);

        // BlockBefore and BlockAfter are automatically handled by
        // the fact that we process each incoming message
        // synchronuosly.
        RFB.messages.clientFence(this._sock, flags, payload);

        return true;
    }

    _handleXvpMsg() {
        if (this._sock.rQwait("XVP version and message", 3, 1)) { return false; }
        this._sock.rQskipBytes(1);  // Padding
        const xvpVer = this._sock.rQshift8();
        const xvpMsg = this._sock.rQshift8();

        switch (xvpMsg) {
            case 0:  // XVP_FAIL
                Log.Error("XVP operation failed");
                break;
            case 1:  // XVP_INIT
                this._rfbXvpVer = xvpVer;
                Log.Info("XVP extensions enabled (version " + this._rfbXvpVer + ")");
                this._setCapability("power", true);
                break;
            default:
                this._fail("Illegal server XVP message (msg: " + xvpMsg + ")");
                break;
        }

        return true;
    }

    // ARD AutoPasteboard (0x15) — subscribe to clipboard notifications
    _sendArdAutoPasteboard(command) {
        this._ardClipboardSyncEnabled = (command !== 0);
        this._sock.sQpush8(0x15);       // message type
        this._sock.sQpush8(0x00);       // padding
        this._sock.sQpush16(command);   // command (1=enable, 0=disable)
        this._sock.sQpush32(0);         // reserved
        // Don't flush here — batch with SetEncodings
        Log.Debug("ARD: queued AutoPasteboard(" + command + ")");
    }

    // ARD ViewerInfo (0x21) — Client identity, 66 bytes total
    // type(1) + pad(1) + size(2) + appClass(2) + appId(4) + appVer(3×4) +
    //   osVer(3×4) + commandSupport(32)
    _sendArdViewerInfo() {
        this._sock.sQpush8(0x21);         // message type
        this._sock.sQpush8(0x00);         // padding
        this._sock.sQpush16(0x003e);      // body size = 62
        this._sock.sQpush16(0x0001);      // appClass = 1
        this._sock.sQpush32(0x00000002);  // appId = 2 (Screen Sharing)
        this._sock.sQpush32(6);           // appVersion.major
        this._sock.sQpush32(1);           // appVersion.minor
        this._sock.sQpush32(0);           // appVersion.patch
        this._sock.sQpush32(26);          // osVersion.major (macOS 26)
        this._sock.sQpush32(2);           // osVersion.minor
        this._sock.sQpush32(0);           // osVersion.patch
        // Command Support bitmap (32 bytes = 256 bits)
        this._sock.sQpush8(0xb0);         // byte 0
        this._sock.sQpush8(0x00);         // byte 1
        this._sock.sQpush8(0x0c);         // byte 2
        this._sock.sQpush8(0x03);         // byte 3
        this._sock.sQpush8(0x90);         // byte 4
        this._sock.sQpush8(0x00);         // byte 5
        this._sock.sQpush8(0x00);         // byte 6
        this._sock.sQpush8(0x00);         // byte 7
        this._sock.sQpush8(0x00);         // byte 8
        this._sock.sQpush8(0x00);         // byte 9
        this._sock.sQpush8(0x40);         // byte 10
        this._sock.sQpush8(0x00);         // byte 11
        for (let i = 12; i < 32; i++) {
            this._sock.sQpush8(0x00);     // bytes 12-31: zero
        }
        Log.Debug("ARD: queued ViewerInfo (66 bytes)");
    }

    // ARD SetMode (0x0a) — 4 bytes
    // mode: 0=Observe, 1=Control, 2=Exclusive
    _sendArdSetMode(mode) {
        this._sock.sQpush8(0x0a);       // message type
        this._sock.sQpush8(0);          // padding
        this._sock.sQpush8(0);          // padding
        this._sock.sQpush8(mode);       // control mode
        Log.Debug("ARD: queued SetMode(" + mode + ")");
    }

    // ARD SessionVisibility (0x0c) — 6 + msgLen bytes
    // visible=true:  show screen (disengage curtain), msgLen=0, no text
    // visible=false: curtain screen, display message text (UTF-8)
    // Message convention: "curtain\r\rScreen locked by <user>"
    _sendArdSessionVisibility(visible, message) {
        const enc = new TextEncoder();
        const msgBytes = visible ? new Uint8Array(0) : enc.encode(message);
        const msgLen = msgBytes.length;
        this._sock.sQpush8(0x0c);           // message type
        this._sock.sQpush8(0);              // padding
        this._sock.sQpush16(visible ? 1 : 0); // visibility: 0=curtain, 1=show
        this._sock.sQpush16(msgLen);        // message length
        for (let i = 0; i < msgLen; i++) {
            this._sock.sQpush8(msgBytes[i]);
        }
        Log.Info("ARD: SessionVisibility → " + (visible ? "show" : "curtain") +
                 " visibility=" + (visible ? 1 : 0) +
                 " msgLen=" + msgLen +
                 (msgLen > 0 ? ' msg="' + message.substring(0, 60) + '"' : ''));
    }

    // ARD SetDisplay (0x0d) — 8 bytes
    // Selects which display to share. CombineAll=1 shows all displays.
    _sendArdSetDisplay() {
        this._sock.sQpush8(0x0d);                      // message type
        this._sock.sQpush8(this._ardCombineAllDisplays); // combineAll
        this._sock.sQpush16(0);                         // padding
        this._sock.sQpush32(this._ardSelectedDisplayId); // displayId
        Log.Debug("ARD: queued SetDisplay(combineAll=" +
                 this._ardCombineAllDisplays +
                 ", displayId=" + this._ardSelectedDisplayId + ")");
    }

    // ARD SetServerScaling (0x08) — 10 bytes
    // Instructs the server to render at a given scale factor before encoding.
    // factor 1.0 = native resolution; the client confirms this after each
    // DisplayInfo2 so the server knows not to downscale the framebuffer.
    _sendArdSetServerScaling(factor) {
        this._sock.sQpush8(0x08);   // message type
        this._sock.sQpush8(0x00);   // padding
        const buf = new ArrayBuffer(8);
        new DataView(buf).setFloat64(0, factor, false); // big-endian f64
        const bytes = new Uint8Array(buf);
        for (let i = 0; i < 8; i++) {
            this._sock.sQpush8(bytes[i]);
        }
        Log.Debug("ARD: queued SetServerScaling(" + factor + ")");
    }

    // ARD AutoFramebufferUpdate (0x09) — 16 bytes
    // Tells the server to automatically push framebuffer updates
    // without waiting for explicit FBUpdateRequests.
    _sendArdAutoFBUpdate(enabled, x, y, w, h) {
        this._sock.sQpush8(0x09);       // message type
        this._sock.sQpush8(0x00);       // padding
        this._sock.sQpush16(enabled);   // 1=enable, 0=disable
        this._sock.sQpush32(0);         // interval ms (0 = server default)
        this._sock.sQpush16(x);         // region x
        this._sock.sQpush16(y);         // region y
        this._sock.sQpush16(w);         // region width
        this._sock.sQpush16(h);         // region height
    }

    // Request a full (non-incremental) framebuffer update and enable
    // automatic server-pushed updates for the given region.
    _requestArdFullUpdate(w, h) {
        RFB.messages.fbUpdateRequest(this._sock, false, 0, 0, w, h);
        this._sendArdAutoFBUpdate(1, 0, 0, w, h);
        this._sock.flush();
        setTimeout(() => {
            if (this._rfbConnectionState !== 'connected') return;
            RFB.messages.fbUpdateRequest(this._sock, false, 0, 0, w, h);
            this._sendArdAutoFBUpdate(1, 0, 0, w, h);
            this._sock.flush();
        }, 50);
    }

    // ARD StateChange (0x14)
    // Wire: [pad 1][size u16be][flags u16][statusCode u16][extra...]
    _handleArdStateChange() {
        if (this._sock.rQwait("ArdStateChange header", 3)) { return false; }

        const rQ = this._sock.rQpeekBytes(3);
        const size = (rQ[1] << 8) | rQ[2];

        if (this._sock.rQwait("ArdStateChange full", 3 + size)) { return false; }

        this._sock.rQskipBytes(3); // padding + size
        if (size < 4) {
            if (size > 0) {
                this._sock.rQskipBytes(size);
            }
            return true;
        }

        const flags = this._sock.rQshift16();
        const statusCode = this._sock.rQshift16();

        if (size > 4) {
            this._sock.rQskipBytes(size - 4);
        }

        switch (statusCode) {
            case 1:
                Log.Info("ARD StateChange: LocalUserClosedConnection");
                this._updateConnectionState('disconnecting');
                break;
            case 2: {
                if (!this._ardClipboardSyncEnabled) {
                    Log.Debug("ARD StateChange: PasteboardChanged — sync disabled, ignoring");
                    break;
                }
                const now = Date.now();
                if (!this._ardLastClipboardReqTime ||
                    now - this._ardLastClipboardReqTime > 500) {
                    Log.Debug("ARD StateChange: PasteboardChanged — requesting clipboard");
                    this._ardLastClipboardReqTime = now;
                    RFB.messages.ardClipboardRequest(this._sock,
                                                     this._ardClipboardSessionId);
                } else {
                    Log.Debug("ARD StateChange: PasteboardChanged — throttled");
                }
                break;
            }
            case 3:
                if (!this._ardClipboardSyncEnabled) {
                    Log.Debug("ARD StateChange: PasteboardDataNeeded — sync disabled, ignoring");
                    break;
                }
                Log.Debug("ARD StateChange: PasteboardDataNeeded — sending clipboard");
                if (this._ardLastClipboardSent) {
                    this._sendArdClipboard(this._ardLastClipboardSent);
                }
                break;
            case 4: {
                this._ardTickleCount++;
                const sinceLastFbu = this._ardLastFbuTime
                    ? (Date.now() - this._ardLastFbuTime)
                    : -1;
                Log.Info("ARD StateChange: Tickle #" + this._ardTickleCount +
                         " (last FBU " + (sinceLastFbu < 0 ? "never" :
                         sinceLastFbu + "ms ago") + ")");
                // The server stops pushing FBUs after ~3s of C→S silence and
                // sends Tickles waiting for a response.  AutoFBUpdate tells it
                // the client is alive and streaming should resume.  Respond on
                // every Tickle so the server never has to send more than one.
                this._sendArdAutoFBUpdate(1, 0, 0,
                                          this._fbWidth, this._fbHeight);
                this._sock.flush();
                break;
            }
            case 5:
                Log.Info("ARD StateChange: DisplaySleep");
                break;
            case 6:
                Log.Info("ARD StateChange: DisplayWake");
                break;
            case 11:
                Log.Info("ARD StateChange: CursorHidden");
                this._updateCursor(new Uint8Array(4), 0, 0, 1, 1);
                break;
            case 12:
                // CursorVisible fires as the server's acknowledgment of both
                // curtain engage and disengage via SessionVisibility (0x0c).
                Log.Info("ARD StateChange: CursorVisible" +
                         (this._ardCurtainActive ? " (curtain engaged)" : ""));
                this._reapplyArdCursor();
                break;
            default:
                Log.Info("ARD StateChange: unknown code=" + statusCode +
                         " flags=0x" + flags.toString(16));
                break;
        }

        return true;
    }

    // ARD ClipboardSend (0x1f)
    // Wire: format(1) + reserved(2) + sessionId(4) + uncompressedSize(4) +
    //        compressedSize(4) + zlibData(compressedSize)
    _handleArdClipboardSend() {
        if (this._sock.rQwait("ArdClipboardSend header", 15)) { return false; }

        const rQ = this._sock.rQpeekBytes(15);
        const compressedSize = (rQ[11] << 24) | (rQ[12] << 16) |
                               (rQ[13] << 8) | rQ[14];

        if (this._sock.rQwait("ArdClipboardSend payload",
                              15 + compressedSize)) { return false; }

        const format = this._sock.rQshift8();
        this._sock.rQskipBytes(2); // reserved
        const sessionId = this._sock.rQshift32();
        const uncompressedSize = this._sock.rQshift32();
        this._sock.rQshift32(); // compressedSize (already known)

        this._ardClipboardSessionId = sessionId;

        Log.Debug("ARD ClipboardSend: format=" + format +
                 " session=" + sessionId +
                 " uncompressed=" + uncompressedSize +
                 " compressed=" + compressedSize);

        if (compressedSize === 0 || uncompressedSize === 0) {
            this._sock.rQskipBytes(compressedSize); // consume payload even if empty
            return true;
        }

        if (uncompressedSize > 10 * 1024 * 1024) {
            Log.Warn("ARD ClipboardSend: uncompressed size " +
                     uncompressedSize + " exceeds 10MB limit, discarding");
            this._sock.rQskipBytes(compressedSize);
            return true;
        }

        const zlibData = this._sock.rQshiftBytes(compressedSize);

        // Fresh Inflator per message (zlib state doesn't carry over)
        const inflator = new Inflator();
        inflator.setInput(zlibData);
        const decompressed = inflator.inflate(uncompressedSize);
        inflator.setInput(null);

        let text = this._parseArdPasteboard(decompressed);

        if (text.length > 0 && text.charAt(text.length - 1) === "\0") {
            text = text.slice(0, -1);
        }

        text = text.replaceAll("\r\n", "\n");

        if (text === this._ardLastClipboardRecv) {
            return true;
        }
        this._ardLastClipboardRecv = text;

        const manual = this._ardClipboardManualRequest;
        this._ardClipboardManualRequest = false;
        if (!this._ardClipboardSyncEnabled && !manual) {
            Log.Debug("ARD ClipboardSend: sync disabled, not writing to local clipboard");
            return true;
        }
        Log.Debug("ARD ClipboardSend: received " + text.length + " chars");
        this._writeClipboard(text);

        return true;
    }

    // Parse ARD pasteboard binary format, extract plain text.
    // Wire: [u32 numTypes] per type: [u32 nameLen][name][u32 flags]
    //       [u32 numProps] per prop: [u32 keyLen][key][u32 valLen][val]
    //       [u32 dataLen][data]
    _parseArdPasteboard(data) {
        const td = new TextDecoder('utf-8', { fatal: false });

        if (data.length < 8 || data[0] !== 0 || data[1] !== 0) {
            return td.decode(data);
        }

        try {
            const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
            let off = 0;

            const numTypes = dv.getUint32(off); off += 4;
            if (numTypes === 0 || numTypes > 20) {
                throw new Error("unlikely numTypes: " + numTypes);
            }

            const types = [];
            for (let t = 0; t < numTypes; t++) {
                const nameLen = dv.getUint32(off); off += 4;
                if (nameLen > 256 || off + nameLen > data.length) {
                    throw new Error("bad nameLen=" + nameLen);
                }
                const name = td.decode(data.slice(off, off + nameLen));
                off += nameLen;

                off += 4; // flags

                const numProps = dv.getUint32(off); off += 4;
                if (numProps > 20) throw new Error("bad numProps=" + numProps);
                for (let p = 0; p < numProps; p++) {
                    const keyLen = dv.getUint32(off); off += 4;
                    if (keyLen > 256 || off + keyLen > data.length) {
                        throw new Error("bad keyLen=" + keyLen);
                    }
                    off += keyLen;
                    const valLen = dv.getUint32(off); off += 4;
                    if (valLen > 65536 || off + valLen > data.length) {
                        throw new Error("bad valLen=" + valLen);
                    }
                    off += valLen;
                }

                const dataLen = dv.getUint32(off); off += 4;
                if (off + dataLen > data.length) {
                    throw new Error("bad dataLen=" + dataLen);
                }
                types.push({ name, data: data.slice(off, off + dataLen), dataLen });
                off += dataLen;
            }

            for (const type of types) {
                if (type.name === 'public.utf8-plain-text' && type.dataLen > 0) {
                    return td.decode(type.data);
                }
            }
            for (const type of types) {
                if (type.name === 'com.apple.traditional-mac-plain-text' &&
                    type.dataLen > 0) {
                    return td.decode(type.data);
                }
            }
            Log.Debug("ARD Pasteboard: no text types in " + numTypes + " types");
            return '';
        } catch (e) {
            Log.Warn("ARD Pasteboard parse failed: " + e.message);
        }

        return td.decode(data).replace(/\0/g, '');
    }

    // Build ARD pasteboard blob and send as ClipboardSend (0x1f)
    _sendArdClipboard(text) {
        if (!text) return;

        const te = new TextEncoder();
        const typeName = te.encode('public.utf8-plain-text');
        const textData = te.encode(text);

        // [u32 numTypes][u32 nameLen][name][u32 flags][u32 numProps][u32 dataLen][data]
        const pbSize = 4 + (4 + typeName.length + 4 + 4 + 4 + textData.length);
        const pb = new Uint8Array(pbSize);
        const dv = new DataView(pb.buffer);
        let off = 0;

        dv.setUint32(off, 1); off += 4;              // numTypes = 1
        dv.setUint32(off, typeName.length); off += 4; // nameLen
        pb.set(typeName, off); off += typeName.length; // name
        dv.setUint32(off, 0); off += 4;              // flags = 0
        dv.setUint32(off, 0); off += 4;              // numProps = 0
        dv.setUint32(off, textData.length); off += 4; // dataLen
        pb.set(textData, off);

        const deflator = new Deflator();
        const compressed = deflator.deflate(pb);

        Log.Debug("ARD ClipboardSend: sending " + text.length +
                 " chars, compressed=" + compressed.length);

        RFB.messages.ardClipboardSend(
            this._sock, this._ardClipboardSessionId,
            pbSize, compressed);
    }

    _normalMsg() {
        let msgType;
        if (this._FBU.rects > 0) {
            msgType = 0;
        } else {
            msgType = this._sock.rQshift8();
        }

        let first, ret;
        switch (msgType) {
            case 0:  // FramebufferUpdate
                ret = this._framebufferUpdate();
                if (ret && !this._enabledContinuousUpdates) {
                    // ARD: if the first FBU didn't include cursor data,
                    // re-send SetEncodings once to prompt the server.
                    if (this._rfbAppleARD && this._ardGotCursor === false) {
                        Log.Info("ARD: first FBU had no cursor, " +
                                 "re-sending SetEncodings");
                        this._ardGotCursor = null;  // only retry once
                        this._sendEncodings();
                        RFB.messages.fbUpdateRequest(this._sock, false, 0, 0,
                                                     this._fbWidth, this._fbHeight);
                        this._sendArdAutoFBUpdate(1, 0, 0,
                                                  this._fbWidth, this._fbHeight);
                    } else {
                        RFB.messages.fbUpdateRequest(this._sock, true, 0, 0,
                                                     this._fbWidth, this._fbHeight);
                    }
                }
                return ret;

            case 1:  // SetColorMapEntries
                return this._handleSetColourMapMsg();

            case 2:  // Bell
                Log.Debug("Bell");
                this.dispatchEvent(new CustomEvent(
                    "bell",
                    { detail: {} }));
                return true;

            case 3:  // ServerCutText
                return this._handleServerCutText();

            case 150: // EndOfContinuousUpdates
                first = !this._supportsContinuousUpdates;
                this._supportsContinuousUpdates = true;
                this._enabledContinuousUpdates = false;
                if (first) {
                    this._enabledContinuousUpdates = true;
                    this._updateContinuousUpdates();
                    Log.Info("Enabling continuous updates.");
                } else {
                    // FIXME: We need to send a framebufferupdaterequest here
                    // if we add support for turning off continuous updates
                }
                return true;

            case 248: // ServerFence
                return this._handleServerFenceMsg();

            case 250:  // XVP
                return this._handleXvpMsg();

            case 0x14: // ARD StateChange
                return this._handleArdStateChange();

            case 0x1f: // ARD ClipboardSend
                return this._handleArdClipboardSend();

            case 0x52: // 'R' — ARD server-initiated re-handshake ("RFB ...")
                if (this._rfbAppleARD) {
                    // Server sent "RFB 003.889\n" on the existing connection —
                    // this happens after login. Consume the remaining 11 bytes
                    // ("FB 003.889\n"), echo the version back, then reset to the
                    // Security init state so the auth machinery handles the rest.
                    if (this._sock.rQwait("ARD re-handshake version", 11)) {
                        return false;
                    }
                    this._sock.rQskipBytes(11); // consume "FB 003.889\n"
                    Log.Info("ARD: server re-handshake — resetting to Security");
                    this._sock.sQpushString("RFB 003.889\n");
                    this._sock.flush();
                    // Reset encryption and auth state for fresh re-auth
                    this._ardDHKey = null;
                    this._ardECBCipher = null;
                    this._ardSessionKey = null;
                    this._ardSessionIV = null;
                    this._ardPendingEncryption = false;
                    this._ardEncryptionEnabled = false;
                    this._ardFirstDisplayInfo = true;
                    this._ardPhase3Pending = false;
                    // Reset per-session display state; notify UI so stale
                    // display buttons are cleared while re-auth completes.
                    this._ardDisplays = [];
                    this.dispatchEvent(new CustomEvent(
                        "arddisplaylist",
                        { detail: { displays: [] } }));
                    // Transition back into the init state machine without creating
                    // a new WebSocket (_connect() would do that, so bypass it).
                    this._rfbConnectionState = 'connecting';
                    this._rfbInitState = 'Security';
                    return false; // exit the 'connected' while-loop
                }
                this._fail("Unexpected server message (type " + msgType + ")");
                return true;

            default:
                this._fail("Unexpected server message (type " + msgType + ")");
                Log.Debug("sock.rQpeekBytes(30): " + this._sock.rQpeekBytes(30));
                return true;
        }
    }

    _framebufferUpdate() {
        if (this._FBU.rects === 0) {
            if (this._sock.rQwait("FBU header", 3, 1)) { return false; }
            this._sock.rQskipBytes(1);  // Padding
            this._FBU.rects = this._sock.rQshift16();

            // Make sure the previous frame is fully rendered first
            // to avoid building up an excessive queue
            if (this._display.pending()) {
                this._flushing = true;
                this._display.flush()
                    .then(() => {
                        this._flushing = false;
                        // Resume processing
                        if (!this._sock.rQwait("message", 1)) {
                            this._handleMessage();
                        }
                    });
                return false;
            }
        }

        while (this._FBU.rects > 0) {
            if (this._FBU.encoding === null) {
                if (this._sock.rQwait("rect header", 12)) { return false; }
                /* New FramebufferUpdate */

                this._FBU.x = this._sock.rQshift16();
                this._FBU.y = this._sock.rQshift16();
                this._FBU.width = this._sock.rQshift16();
                this._FBU.height = this._sock.rQshift16();
                this._FBU.encoding = this._sock.rQshift32();
                /* Encodings are signed */
                this._FBU.encoding >>= 0;
            }

            if (!this._handleRect()) {
                return false;
            }

            this._FBU.rects--;
            this._FBU.encoding = null;
        }

        this._display.flip();

        // Track FBU timing for freeze detection
        this._ardLastFbuTime = Date.now();
        this._ardTickleCount = 0;

        // After each frame, re-subscribe to AutoFBUpdate so the server keeps
        // pushing.  This mirrors how the native ARD client calls
        // RFBAutoFrameUpdate after every frame it receives in readFrameData:.
        // Without this the server's subscription silently expires after a few
        // seconds of C→S silence, causing the Tickle storm / freeze.
        if (this._rfbAppleARD) {
            this._sendArdAutoFBUpdate(1, 0, 0,
                                      this._fbWidth, this._fbHeight);
            this._sock.flush();
        }

        // Activate stream encryption after the FBU that delivered the key
        if (this._ardPendingEncryption) {
            this._ardPendingEncryption = false;
            RFB.messages.ardSetEncryption(this._sock, 2);  // acknowledge
            Log.Info("ARD: sent SetEncryption(acknowledge)");
            this._enableStreamEncryption();
            RFB.messages.fbUpdateRequest(this._sock, false, 0, 0,
                                         this._fbWidth, this._fbHeight);
            this._sendArdAutoFBUpdate(1, 0, 0,
                                      this._fbWidth, this._fbHeight);
        }

        return true;  // We finished this FBU
    }

    _handleRect() {
        switch (this._FBU.encoding) {
            case encodings.pseudoEncodingLastRect:
                this._FBU.rects = 1; // Will be decreased when we return
                return true;

            case encodings.pseudoEncodingVMwareCursor:
                return this._handleVMwareCursor();

            case encodings.pseudoEncodingCursor:
                return this._handleCursor();

            case encodings.pseudoEncodingQEMUExtendedKeyEvent:
                this._qemuExtKeyEventSupported = true;
                return true;

            case encodings.pseudoEncodingDesktopName:
                return this._handleDesktopName();

            case encodings.pseudoEncodingDesktopSize:
                Log.Info("DesktopSize: " + this._fbWidth + "x" +
                         this._fbHeight + " -> " + this._FBU.width +
                         "x" + this._FBU.height);
                this._resize(this._FBU.width, this._FBU.height);
                // ARD: after resize request a full (non-incremental) frame at
                // the new dimensions so the server sends a clean I-frame
                // baseline before resuming delta pushes via AutoFBUpdate.
                if (this._rfbAppleARD) {
                    RFB.messages.fbUpdateRequest(this._sock, false, 0, 0,
                                                 this._fbWidth, this._fbHeight);
                    this._sendArdAutoFBUpdate(
                        1, 0, 0, this._fbWidth, this._fbHeight);
                    this._sock.flush();
                }
                return true;

            case encodings.pseudoEncodingExtendedDesktopSize:
                return this._handleExtendedDesktopSize();

            case encodings.pseudoEncodingExtendedMouseButtons:
                this._extendedPointerEventSupported = true;
                return true;

            case encodings.pseudoEncodingQEMULedEvent:
                return this._handleLedEvent();

            case encodings.pseudoEncodingArdSessionEncryption:
                return this._handleArdSessionEncryption();

            case encodings.pseudoEncodingArdUserInfo:
                return this._handleArdUserInfo();

            case encodings.pseudoEncodingArdCursorPos:
                return this._handleArdCursorPos();

            case encodings.pseudoEncodingArdCursorAlpha:
                return this._handleArdCursorAlpha();

            case encodings.pseudoEncodingArdDisplayInfo:
                return this._handleArdDisplayInfo();

            case encodings.pseudoEncodingArdDisplayInfo2:
                return this._handleArdDisplayInfo2();

            default:
                return this._handleDataRect();
        }
    }

    _handleVMwareCursor() {
        const hotx = this._FBU.x;  // hotspot-x
        const hoty = this._FBU.y;  // hotspot-y
        const w = this._FBU.width;
        const h = this._FBU.height;
        if (this._sock.rQwait("VMware cursor encoding", 1)) {
            return false;
        }

        const cursorType = this._sock.rQshift8();

        this._sock.rQshift8(); //Padding

        let rgba;
        const bytesPerPixel = 4;

        //Classic cursor
        if (cursorType == 0) {
            //Used to filter away unimportant bits.
            //OR is used for correct conversion in js.
            const PIXEL_MASK = 0xffffff00 | 0;
            rgba = new Array(w * h * bytesPerPixel);

            if (this._sock.rQwait("VMware cursor classic encoding",
                                  (w * h * bytesPerPixel) * 2, 2)) {
                return false;
            }

            let andMask = new Array(w * h);
            for (let pixel = 0; pixel < (w * h); pixel++) {
                andMask[pixel] = this._sock.rQshift32();
            }

            let xorMask = new Array(w * h);
            for (let pixel = 0; pixel < (w * h); pixel++) {
                xorMask[pixel] = this._sock.rQshift32();
            }

            for (let pixel = 0; pixel < (w * h); pixel++) {
                if (andMask[pixel] == 0) {
                    //Fully opaque pixel
                    let bgr = xorMask[pixel];
                    let r   = bgr >> 8  & 0xff;
                    let g   = bgr >> 16 & 0xff;
                    let b   = bgr >> 24 & 0xff;

                    rgba[(pixel * bytesPerPixel)     ] = r;    //r
                    rgba[(pixel * bytesPerPixel) + 1 ] = g;    //g
                    rgba[(pixel * bytesPerPixel) + 2 ] = b;    //b
                    rgba[(pixel * bytesPerPixel) + 3 ] = 0xff; //a

                } else if ((andMask[pixel] & PIXEL_MASK) ==
                           PIXEL_MASK) {
                    //Only screen value matters, no mouse colouring
                    if (xorMask[pixel] == 0) {
                        //Transparent pixel
                        rgba[(pixel * bytesPerPixel)     ] = 0x00;
                        rgba[(pixel * bytesPerPixel) + 1 ] = 0x00;
                        rgba[(pixel * bytesPerPixel) + 2 ] = 0x00;
                        rgba[(pixel * bytesPerPixel) + 3 ] = 0x00;

                    } else if ((xorMask[pixel] & PIXEL_MASK) ==
                               PIXEL_MASK) {
                        //Inverted pixel, not supported in browsers.
                        //Fully opaque instead.
                        rgba[(pixel * bytesPerPixel)     ] = 0x00;
                        rgba[(pixel * bytesPerPixel) + 1 ] = 0x00;
                        rgba[(pixel * bytesPerPixel) + 2 ] = 0x00;
                        rgba[(pixel * bytesPerPixel) + 3 ] = 0xff;

                    } else {
                        //Unhandled xorMask
                        rgba[(pixel * bytesPerPixel)     ] = 0x00;
                        rgba[(pixel * bytesPerPixel) + 1 ] = 0x00;
                        rgba[(pixel * bytesPerPixel) + 2 ] = 0x00;
                        rgba[(pixel * bytesPerPixel) + 3 ] = 0xff;
                    }

                } else {
                    //Unhandled andMask
                    rgba[(pixel * bytesPerPixel)     ] = 0x00;
                    rgba[(pixel * bytesPerPixel) + 1 ] = 0x00;
                    rgba[(pixel * bytesPerPixel) + 2 ] = 0x00;
                    rgba[(pixel * bytesPerPixel) + 3 ] = 0xff;
                }
            }

        //Alpha cursor.
        } else if (cursorType == 1) {
            if (this._sock.rQwait("VMware cursor alpha encoding",
                                  (w * h * 4), 2)) {
                return false;
            }

            rgba = new Array(w * h * bytesPerPixel);

            for (let pixel = 0; pixel < (w * h); pixel++) {
                let data = this._sock.rQshift32();

                rgba[(pixel * 4)     ] = data >> 24 & 0xff; //r
                rgba[(pixel * 4) + 1 ] = data >> 16 & 0xff; //g
                rgba[(pixel * 4) + 2 ] = data >> 8 & 0xff;  //b
                rgba[(pixel * 4) + 3 ] = data & 0xff;       //a
            }

        } else {
            Log.Warn("The given cursor type is not supported: "
                      + cursorType + " given.");
            return false;
        }

        this._updateCursor(rgba, hotx, hoty, w, h);

        return true;
    }

    _handleCursor() {
        const hotx = this._FBU.x;  // hotspot-x
        const hoty = this._FBU.y;  // hotspot-y
        const w = this._FBU.width;
        const h = this._FBU.height;

        const pixelslength = w * h * 4;
        const masklength = Math.ceil(w / 8) * h;

        let bytes = pixelslength + masklength;
        if (this._sock.rQwait("cursor encoding", bytes)) {
            return false;
        }

        // Decode from BGRX pixels + bit mask to RGBA
        const pixels = this._sock.rQshiftBytes(pixelslength);
        const mask = this._sock.rQshiftBytes(masklength);
        let rgba = new Uint8Array(w * h * 4);

        let pixIdx = 0;
        for (let y = 0; y < h; y++) {
            for (let x = 0; x < w; x++) {
                let maskIdx = y * Math.ceil(w / 8) + Math.floor(x / 8);
                let alpha = (mask[maskIdx] << (x % 8)) & 0x80 ? 255 : 0;
                rgba[pixIdx    ] = pixels[pixIdx + 2];
                rgba[pixIdx + 1] = pixels[pixIdx + 1];
                rgba[pixIdx + 2] = pixels[pixIdx];
                rgba[pixIdx + 3] = alpha;
                pixIdx += 4;
            }
        }

        this._updateCursor(rgba, hotx, hoty, w, h);

        return true;
    }

    // Encoding 1102: ArdUserInfo — logged-in username and avatar image.
    // An empty username means the login window is active (no user at console).
    // The avatar PNG uses BGRA channel order (R and B swapped vs standard RGBA).
    _handleArdUserInfo() {
        // Minimum: 2-byte nameLen + 4-byte imageSize + 4-byte imageEncoding = 10 bytes
        if (this._sock.rQwait("ArdUserInfo header", 10)) { return false; }

        const nameLenPeek = this._sock.rQpeekBytes(2);
        const nameLen = (nameLenPeek[0] << 8) | nameLenPeek[1];
        const totalHeaderSize = 2 + nameLen + 8;  // nameLen field + name + imageSize + imageEncoding

        if (this._sock.rQwait("ArdUserInfo name+header", totalHeaderSize)) { return false; }

        this._sock.rQskipBytes(2);                         // name length field
        const nameBytes = this._sock.rQshiftBytes(nameLen);
        const username = new TextDecoder().decode(nameBytes);

        const imageSize = this._sock.rQshift32() >>> 0;
        const imageEncoding = this._sock.rQshift32() >>> 0; // 6 = PNG

        if (imageSize > 0) {
            if (this._sock.rQwait("ArdUserInfo avatar", imageSize)) { return false; }
            const compressedBytes = this._sock.rQshiftBytes(imageSize);

            // ARD sends zlib-compressed PNG (encoding=6), not raw PNG
            // Decompressed size unknown — try inflating with a large buffer
            const inflator = new Inflator();
            inflator.setInput(compressedBytes);
            let pngBytes;
            try {
                // Try progressively larger buffers until inflate succeeds
                for (let size of [4096, 8192, 16384, 32768]) {
                    try {
                        pngBytes = inflator.inflate(size);
                        break; // Success
                    } catch (e) {
                        if (e.message !== "Incomplete zlib block") throw e;
                        inflator.reset();
                        inflator.setInput(compressedBytes);
                    }
                }
            } finally {
                inflator.setInput(null);
            }

            this._ardUserAvatarPng = pngBytes;  // Raw BGRA pixel data, cached for future use
        } else {
            this._ardUserAvatarPng = null;
        }

        const prevUsername = this._ardUsername;
        this._ardUsername = username;

        Log.Info("ARD UserInfo: username=" + (username || "(none — login window)") +
                 " avatarSize=" + (imageSize > 0 ? imageSize + "b enc=" + imageEncoding : "none"));

        // Always dispatch event so avatar updates even if username unchanged
        this.dispatchEvent(new CustomEvent('arduserinfo',
            { detail: { username: username, hasAvatar: imageSize > 0 } }));

        return true;
    }

    // Encoding 1100: ArdCursorPos — remote cursor position hint.
    // noVNC renders the cursor locally from mouse events, so this is a no-op.
    _handleArdCursorPos() {
        return true;
    }

    // Encoding 1104: ArdCursorAlpha
    // Two modes distinguished by width/height:
    //   New Cursor (w>0, h>0): defines and caches a cursor image (ID > 999)
    //   Set Cursor (w=0, h=0): activates a cursor by ID
    //     - ID 0-999: system cursor (no pixel data; client maps to CSS cursor)
    //     - ID > 999: previously cached custom cursor
    // Both carry: u32be cursorID + u32be dataSize + [dataSize bytes]
    _handleArdCursorAlpha() {
        this._ardGotCursor = true;
        const hotx = this._FBU.x;
        const hoty = this._FBU.y;
        const w = this._FBU.width;
        const h = this._FBU.height;

        // Peek at the 8-byte header (cursorID + dataSize) before consuming
        if (this._sock.rQwait("ArdCursor header", 8)) { return false; }
        const hdr = this._sock.rQpeekBytes(8);
        const cursorId = ((hdr[0] << 24) | (hdr[1] << 16) |
                          (hdr[2] << 8)  |  hdr[3]) >>> 0;
        const dataSize = ((hdr[4] << 24) | (hdr[5] << 16) |
                          (hdr[6] << 8)  |  hdr[7]) >>> 0;

        // Wait for complete message: 8-byte header + compressed payload
        if (this._sock.rQwait("ArdCursor payload", 8 + dataSize)) { return false; }

        // Consume the 8-byte header
        this._sock.rQskipBytes(8);

        // --- Set Cursor (w=0, h=0): activate cursor by ID ---
        if (w === 0 && h === 0) {
            Log.Info("ArdCursorAlpha: SetCursor id=" + cursorId +
                     (cursorId < 1000 ? " (system)" : " (custom)") +
                     " dataSize=" + dataSize);

            if (dataSize > 0) {
                this._sock.rQskipBytes(dataSize);
            }

            if (cursorId < 1000) {
                this._ardActiveCursor = { type: 'system', id: cursorId };
                this._setArdSystemCursor(cursorId);
            } else {
                const cachedUrl = this._ardCursorUrlCache[cursorId];
                if (cachedUrl) {
                    this._ardActiveCursor = { type: 'custom', id: cursorId };
                    this._canvas.style.cursor = cachedUrl;
                } else {
                    const cached = this._ardCursorCache[cursorId];
                    if (cached) {
                        this._ardActiveCursor = { type: 'custom', id: cursorId };
                        this._updateCursor(cached.rgba, cached.hotx, cached.hoty,
                                           cached.w, cached.h);
                    } else {
                        Log.Warn("ArdCursorAlpha: SetCursor unknown id " +
                                 cursorId + ", falling back to default arrow");
                        this._ardActiveCursor = { type: 'system', id: 0 };
                        this._setArdSystemCursor(0);
                    }
                }
            }
            return true;
        }

        // --- New Cursor (w>0, h>0): decompress and cache ---

        if (w > 256 || h > 256) {
            Log.Warn("ArdCursorAlpha: cursor too large (" +
                     w + "x" + h + "), skipping");
            this._sock.rQskipBytes(dataSize);
            return true;
        }

        Log.Debug("ArdCursorAlpha: NewCursor id=" + cursorId +
                 " " + w + "x" + h + " hotspot=" + hotx + "," + hoty +
                 " compressed=" + dataSize + " bytes");

        // Decompress cursor data: w*h*5 bytes total
        //   First w*h*4 bytes: pixel data in BGRX format
        //   Last  w*h*1 bytes: separate alpha mask (8-bit per pixel)
        const pixelCount = w * h;
        const decompressedSize = pixelCount * 5;
        const compressed = new Uint8Array(
            this._sock.rQshiftBytes(dataSize, false));

        this._ardCursorZlib.reset();
        this._ardCursorZlib.setInput(compressed);
        const decompressed = this._ardCursorZlib.inflate(decompressedSize);
        this._ardCursorZlib.setInput(null);

        // Convert BGRX + separate alpha → RGBA
        const rgba = new Uint8Array(pixelCount * 4);
        const alphaOffset = pixelCount * 4;
        for (let i = 0; i < pixelCount; i++) {
            const srcOff = i * 4;
            const dstOff = i * 4;
            rgba[dstOff]     = decompressed[srcOff + 2]; // R
            rgba[dstOff + 1] = decompressed[srcOff + 1]; // G
            rgba[dstOff + 2] = decompressed[srcOff];     // B
            rgba[dstOff + 3] = decompressed[alphaOffset + i]; // A
        }

        // Cache and activate (evict oldest entry when cache is full)
        const cacheKeys = Object.keys(this._ardCursorCache);
        if (cacheKeys.length >= 100) {
            const oldest = cacheKeys[0];
            delete this._ardCursorCache[oldest];
            delete this._ardCursorUrlCache[oldest];
        }
        this._ardCursorCache[cursorId] = {
            rgba: rgba, hotx: hotx, hoty: hoty, w: w, h: h
        };

        this._ardActiveCursor = { type: 'custom', id: cursorId };
        this._updateCursor(rgba, hotx, hoty, w, h);

        // Cache the generated CSS cursor URL for fast SetCursor switching
        this._ardCursorUrlCache[cursorId] = this._canvas.style.cursor;

        return true;
    }

    // Map ARD system cursor IDs (0-999) to CSS cursor names
    _setArdSystemCursor(cursorId) {
        const cssCursors = {
            0: 'default',       // Arrow
            1: 'text',          // IBeam
            2: 'crosshair',     // Crosshair
            3: 'grabbing',      // ClosedHand
            4: 'grab',          // OpenHand
            5: 'pointer',       // PointingHand
            6: 'w-resize',      // ResizeLeft
            7: 'e-resize',      // ResizeRight
            8: 'ew-resize',     // ResizeLeftRight
        };

        const cssName = cssCursors[cursorId] || 'default';
        this._canvas.style.cursor = cssName;
    }

    // Re-apply the last known cursor after CursorVisible state change
    _reapplyArdCursor() {
        if (!this._ardActiveCursor) {
            return;
        }
        const c = this._ardActiveCursor;
        if (c.type === 'system') {
            this._setArdSystemCursor(c.id);
        } else if (c.type === 'custom') {
            const cachedUrl = this._ardCursorUrlCache[c.id];
            if (cachedUrl) {
                this._canvas.style.cursor = cachedUrl;
            } else {
                const cached = this._ardCursorCache[c.id];
                if (cached) {
                    this._updateCursor(cached.rgba, cached.hotx, cached.hoty,
                                       cached.w, cached.h);
                }
            }
        }
    }

    // Encoding 1101: DisplayInfo
    // Display configuration: framebuffer dimensions + per-display entries.
    // Payload: Width(2) + Height(2) + Count(2) + Flags(2) = 8 bytes
    //   + Count * [ID(4) + W(2) + H(2) + Magic(4) + PixelFormat(16)] = 28 bytes each
    _handleArdDisplayInfo() {
        if (this._sock.rQwait("ArdDisplayInfo header", 8)) { return false; }
        const hdr = this._sock.rQpeekBytes(8);
        const fbWidth  = (hdr[0] << 8) | hdr[1];
        const fbHeight = (hdr[2] << 8) | hdr[3];
        const count    = (hdr[4] << 8) | hdr[5];
        const flags    = (hdr[6] << 8) | hdr[7];

        const perDisplaySize = 28;
        const totalSize = 8 + count * perDisplaySize;

        if (this._sock.rQwait("ArdDisplayInfo full", totalSize)) { return false; }

        this._sock.rQskipBytes(8);

        Log.Debug("ArdDisplayInfo: " + fbWidth + "x" + fbHeight +
                 " displays=" + count + " flags=0x" + flags.toString(16));

        this._ardDisplays = [];
        for (let i = 0; i < count; i++) {
            const displayId = this._sock.rQshift32() >>> 0;
            const dw = this._sock.rQshift16();
            const dh = this._sock.rQshift16();
            const magic = this._sock.rQshift32() >>> 0;
            this._sock.rQskipBytes(16);  // PixelFormat (not needed)

            this._ardDisplays.push({
                id: displayId, width: dw, height: dh, magic: magic
            });

            Log.Debug("  Display " + i + ": id=" + displayId +
                      " " + dw + "x" + dh +
                      " magic=0x" + magic.toString(16));
        }

        Log.Debug("ArdDisplayInfo: arddisplaylist count=" +
                  this._ardDisplays.length + " ids=[" +
                  this._ardDisplays.map(d => d.id).join(",") + "]");
        this.dispatchEvent(new CustomEvent(
            "arddisplaylist",
            { detail: { displays: this._ardDisplays } }));

        return true;
    }

    // Encoding 1105: DisplayInfo2
    // Extended display info with Retina/HiDPI support. Size-prefixed payload.
    // Payload: Size(2) + Version(2) + Width(2) + Height(2) + ScaledW(2) +
    //   ScaledH(2) + DisplayID(4) + Flags(4) + DisplayCount(2) = 22 bytes fixed
    //   + Count * 56 bytes per-display entries
    _handleArdDisplayInfo2() {
        if (this._sock.rQwait("ArdDisplayInfo2 header", 2)) { return false; }
        const sizePeek = this._sock.rQpeekBytes(2);
        const payloadSize = (sizePeek[0] << 8) | sizePeek[1];

        const totalSize = 2 + payloadSize;
        if (this._sock.rQwait("ArdDisplayInfo2 full", totalSize)) { return false; }

        this._sock.rQskipBytes(2);

        if (payloadSize < 20) {
            Log.Warn("ArdDisplayInfo2: payload too small (" +
                     payloadSize + "), skipping");
            if (payloadSize > 0) {
                this._sock.rQskipBytes(payloadSize);
            }
            return true;
        }

        const version      = this._sock.rQshift16();
        const fbWidth      = this._sock.rQshift16();
        const fbHeight     = this._sock.rQshift16();
        const scaledW      = this._sock.rQshift16();
        const scaledH      = this._sock.rQshift16();
        const displayId    = this._sock.rQshift32() >>> 0;
        const displayFlags = this._sock.rQshift32() >>> 0;
        const displayCount = this._sock.rQshift16();

        // Store combined desktop dimensions (scaled = actual framebuffer size)
        this._ardCombinedFbWidth = scaledW;
        this._ardCombinedFbHeight = scaledH;

        // Curtain state: server sets bits 0-1 (mask 0x03) when screen is blanked.
        const serverCurtained = (displayFlags & 0x03) === 0x03;

        Log.Info("ArdDisplayInfo2: v" + version +
                 " fb=" + fbWidth + "x" + fbHeight +
                 " scaled=" + scaledW + "x" + scaledH +
                 " activeDisplay=" + displayId +
                 " displays=" + displayCount +
                 " flags=0x" + displayFlags.toString(16).padStart(8, '0') +
                 " curtain=" + serverCurtained);

        const perDisplaySize = 56;
        const remainingBytes = payloadSize - 20;
        const displaysToParse = Math.min(
            displayCount,
            Math.floor(remainingBytes / perDisplaySize)
        );

        // Rect coordinates are signed i16 (displays can have negative origins)
        function s16(v) { return v > 0x7FFF ? v - 0x10000 : v; }

        this._ardDisplays = [];
        for (let i = 0; i < displaysToParse; i++) {
            // Read 8-byte doubles via DataView
            const scaleBytes = this._sock.rQshiftBytes(16, false);
            const dv = new DataView(scaleBytes.buffer,
                                    scaleBytes.byteOffset,
                                    scaleBytes.byteLength);
            const backingScale  = dv.getFloat64(0, false);  // big-endian
            const displayScale  = dv.getFloat64(8, false);

            const dId           = this._sock.rQshift32() >>> 0;
            const dTop          = s16(this._sock.rQshift16());
            const dLeft         = s16(this._sock.rQshift16());
            const dBottom       = s16(this._sock.rQshift16());
            const dRight        = s16(this._sock.rQshift16());
            const bTop          = s16(this._sock.rQshift16());
            const bLeft         = s16(this._sock.rQshift16());
            const bBottom       = s16(this._sock.rQshift16());
            const bRight        = s16(this._sock.rQshift16());
            const dFlags        = this._sock.rQshift32() >>> 0;
            this._sock.rQskipBytes(16);  // PixelFormat

            const isPrimary = (dFlags & 1) !== 0;
            this._ardDisplays.push({
                id: dId,
                width: dRight - dLeft,
                height: dBottom - dTop,
                backingWidth: bRight - bLeft,
                backingHeight: bBottom - bTop,
                backingScale: backingScale,
                displayScale: displayScale,
                primary: isPrimary
            });

            Log.Debug("  Display " + i + ": id=" + dId +
                      " rect=(" + dLeft + "," + dTop +
                     ")-(" + dRight + "," + dBottom + ")" +
                     " backing=(" + bLeft + "," + bTop +
                     ")-(" + bRight + "," + bBottom + ")" +
                     " scale=" + backingScale.toFixed(1) + "x" +
                     (isPrimary ? " [primary]" : ""));
        }

        // Skip any remaining unparsed bytes
        const parsedBytes = 20 + displaysToParse * perDisplaySize;
        const leftover = payloadSize - parsedBytes;
        if (leftover > 0) {
            this._sock.rQskipBytes(leftover);
        }

        Log.Debug("ArdDisplayInfo2: arddisplaylist count=" +
                  this._ardDisplays.length + " ids=[" +
                  this._ardDisplays.map(d => d.id).join(",") + "]");
        this.dispatchEvent(new CustomEvent(
            "arddisplaylist",
            { detail: { displays: this._ardDisplays } }));

        // Update curtain state from server-confirmed flags.
        // The server sets bits 0-1 (0x03) in the global flags field when the
        // screen is blanked; it clears them when the curtain is removed.
        if (serverCurtained !== this._ardCurtainActive) {
            Log.Info("ArdDisplayInfo2: curtain state → " +
                     (serverCurtained ? "CURTAINED" : "VISIBLE") +
                     " (flags=0x" + displayFlags.toString(16).padStart(8, '0') + ")");
            this._ardCurtainActive = serverCurtained;
            this.dispatchEvent(new CustomEvent('ardcurtainchange',
                { detail: { active: serverCurtained } }));
        }

        // Update console state from DI2 global flags.
        // Bit 3 (0x08) = lock screen; bit 4 (0x10) = login window.
        // Either set means no active user session at the console.
        const consoleActive = (displayFlags & 0x18) === 0;
        if (consoleActive !== this._ardConsoleActive) {
            const reason = (displayFlags & 0x10) ? "LOGIN WINDOW" :
                           (displayFlags & 0x08) ? "LOCKED" : "ACTIVE";
            Log.Info("ArdDisplayInfo2: console state → " + reason +
                     " (flags=0x" + displayFlags.toString(16).padStart(8, '0') + ")");
            this._ardConsoleActive = consoleActive;
            this.dispatchEvent(new CustomEvent('ardconsolestate',
                { detail: { active: consoleActive } }));
        }

        // When the display config changes mid-session (monitor plugged in
        // or removed), the server stops sending FBUs until we acknowledge
        // the new layout.  Re-send SetEncodings + SetDisplay + a full
        // FBUpdateRequest so the server resumes streaming.
        // Only do this when the combined size actually changed to avoid
        // an infinite loop (every FBU can carry DisplayInfo2).
        const prevW = this._ardPrevCombinedW || 0;
        const prevH = this._ardPrevCombinedH || 0;
        const prevCount = this._ardPrevDisplayCount;
        this._ardPrevCombinedW = scaledW;
        this._ardPrevCombinedH = scaledH;
        this._ardPrevDisplayCount = this._ardDisplays.length;

        // Resize canvas when the server's framebuffer dimensions change.
        // The server sends DisplayInfo2 (not DesktopSize) on display switch.
        if (scaledW !== this._fbWidth || scaledH !== this._fbHeight) {
            Log.Info("ArdDisplayInfo2: resizing canvas " +
                     this._fbWidth + "x" + this._fbHeight +
                     " → " + scaledW + "x" + scaledH);
            this._resize(scaledW, scaledH);
            // Clear stale image so old display content doesn't show
            // during the brief window before new FBUs arrive.
            this._display.fillRect(0, 0, scaledW, scaledH, [0, 0, 0]);
        }

        // Phase 2: server confirmed layout change via DisplayInfo2.
        // Mirrors the native ARD client's reactive pattern:
        //   SetServerScaling(1.0) + FBUpdateRequest(dims) + SetDisplay + SetPixelFormat
        // The SetDisplay causes the server to emit one more echo DI2 (Phase 3),
        // at which point we send the final FBUpdateRequest + AutoFBUpdate.
        //
        // Triggers on:
        //   - First DisplayInfo2 after connect (kicks pixel streaming)
        //   - Dimension change (display switch confirmed, or monitor plug/unplug)
        //   - Display count change (monitor added/removed without dimension change)
        const displayCountChanged = this._rfbConnectionState === 'connected' &&
            prevCount > 0 && this._ardDisplays.length !== prevCount;
        const dimensionsChanged = this._rfbConnectionState === 'connected' &&
            (scaledW !== prevW || scaledH !== prevH) && prevW > 0;

        // If count changed but dimensions didn't, fire a full update directly
        // to unfreeze the stream (no Phase 2/3 needed — layout is already stable).
        if (displayCountChanged && !dimensionsChanged && !this._ardFirstDisplayInfo) {
            Log.Info("ArdDisplayInfo2: display count changed " +
                     prevCount + " → " + this._ardDisplays.length +
                     ", refreshing stream");
            this._requestArdFullUpdate(scaledW, scaledH);
        }

        if (this._ardFirstDisplayInfo || dimensionsChanged) {
            if (this._ardFirstDisplayInfo) {
                Log.Info("ArdDisplayInfo2: Phase 2 (first after connect) " +
                         scaledW + "x" + scaledH);
            } else {
                Log.Info("ArdDisplayInfo2: Phase 2 (config changed " +
                         prevW + "x" + prevH + " → " +
                         scaledW + "x" + scaledH + ")");
            }
            this._ardFirstDisplayInfo = false;
            this._sendArdSetDisplay();
            RFB.messages.pixelFormat(this._sock, this._fbDepth, true);
            this._sock.flush();
            if (this._ardCombineAllDisplays) {
                // Server does not echo a second DI2 for the All-displays view —
                // go straight to Phase 3 instead of waiting indefinitely.
                Log.Info("ArdDisplayInfo2: Phase 3 (requesting frame, All view) " +
                         scaledW + "x" + scaledH);
                this._ardPhase3Pending = false;
                this._sendArdSetServerScaling(1.0);
                this._requestArdFullUpdate(scaledW, scaledH);
            } else {
                this._ardPhase3Pending = true;
            }
        } else if (this._ardPhase3Pending) {
            // Phase 3: server's echo DI2 arrived — display config is now
            // stable. Send SetServerScaling(1.0) then request pixel data.
            Log.Info("ArdDisplayInfo2: Phase 3 (requesting frame) " +
                     scaledW + "x" + scaledH);
            this._ardPhase3Pending = false;
            this._sendArdSetServerScaling(1.0);
            this._requestArdFullUpdate(scaledW, scaledH);
        } else if (this._rfbConnectionState === 'connected') {
            // No layout change but server sent DI2 anyway (e.g. session state
            // change signalled by a flags transition).  Re-affirm AutoFBUpdate
            // so the server knows the client is alive and streaming can continue.
            Log.Info("ArdDisplayInfo2: state-only change (flags=0x" +
                     displayFlags.toString(16) + "), re-subscribing AutoFBUpdate");
            this._sendArdAutoFBUpdate(1, 0, 0, scaledW, scaledH);
            this._sock.flush();
        }

        Log.Debug("ArdDisplayInfo2: " + scaledW + "x" + scaledH +
                  " displays=" + this._ardDisplays.length);

        return true;
    }

    _handleDesktopName() {
        if (this._sock.rQwait("DesktopName", 4)) {
            return false;
        }

        let length = this._sock.rQshift32();

        if (this._sock.rQwait("DesktopName", length, 4)) {
            return false;
        }

        let name = this._sock.rQshiftStr(length);
        name = decodeUTF8(name, true);

        this._setDesktopName(name);

        return true;
    }

    _handleLedEvent() {
        if (this._sock.rQwait("LED status", 1)) {
            return false;
        }

        let data = this._sock.rQshift8();
        // ScrollLock state can be retrieved with data & 1. This is currently not needed.
        let numLock = data & 2 ? true : false;
        let capsLock = data & 4 ? true : false;
        this._remoteCapsLock = capsLock;
        this._remoteNumLock = numLock;

        return true;
    }

    _handleExtendedDesktopSize() {
        if (this._sock.rQwait("ExtendedDesktopSize", 4)) {
            return false;
        }

        const numberOfScreens = this._sock.rQpeek8();

        let bytes = 4 + (numberOfScreens * 16);
        if (this._sock.rQwait("ExtendedDesktopSize", bytes)) {
            return false;
        }

        const firstUpdate = !this._supportsSetDesktopSize;
        this._supportsSetDesktopSize = true;

        this._sock.rQskipBytes(1);  // number-of-screens
        this._sock.rQskipBytes(3);  // padding

        for (let i = 0; i < numberOfScreens; i += 1) {
            // Save the id and flags of the first screen
            if (i === 0) {
                this._screenID = this._sock.rQshift32();    // id
                this._sock.rQskipBytes(2);                  // x-position
                this._sock.rQskipBytes(2);                  // y-position
                this._sock.rQskipBytes(2);                  // width
                this._sock.rQskipBytes(2);                  // height
                this._screenFlags = this._sock.rQshift32(); // flags
            } else {
                this._sock.rQskipBytes(16);
            }
        }

        /*
         * The x-position indicates the reason for the change:
         *
         *  0 - server resized on its own
         *  1 - this client requested the resize
         *  2 - another client requested the resize
         */

        if (this._FBU.x === 1) {
            this._pendingRemoteResize = false;
        }

        // We need to handle errors when we requested the resize.
        if (this._FBU.x === 1 && this._FBU.y !== 0) {
            let msg;
            // The y-position indicates the status code from the server
            switch (this._FBU.y) {
                case 1:
                    msg = "Resize is administratively prohibited";
                    break;
                case 2:
                    msg = "Out of resources";
                    break;
                case 3:
                    msg = "Invalid screen layout";
                    break;
                default:
                    msg = "Unknown reason";
                    break;
            }
            Log.Warn("Server did not accept the resize request: "
                     + msg);
        } else {
            this._resize(this._FBU.width, this._FBU.height);
        }

        // Normally we only apply the current resize mode after a
        // window resize event. However there is no such trigger on the
        // initial connect. And we don't know if the server supports
        // resizing until we've gotten here.
        if (firstUpdate) {
            this._requestRemoteResize();
        }

        if (this._FBU.x === 1 && this._FBU.y === 0) {
            // We might have resized again whilst waiting for the
            // previous request, so check if we are in sync
            this._requestRemoteResize();
        }

        return true;
    }

    _handleDataRect() {
        let decoder = this._decoders[this._FBU.encoding];
        if (!decoder) {
            this._fail("Unsupported encoding (encoding: " +
                       this._FBU.encoding + ")");
            return false;
        }

        try {
            return decoder.decodeRect(this._FBU.x, this._FBU.y,
                                      this._FBU.width, this._FBU.height,
                                      this._sock, this._display,
                                      this._fbDepth);
        } catch (err) {
            this._fail("Error decoding rect: " + err);
            return false;
        }
    }

    _updateContinuousUpdates() {
        if (!this._enabledContinuousUpdates) { return; }

        RFB.messages.enableContinuousUpdates(this._sock, true, 0, 0,
                                             this._fbWidth, this._fbHeight);
    }

    // Handle resize-messages from the server
    _resize(width, height) {
        this._fbWidth = width;
        this._fbHeight = height;

        this._display.resize(this._fbWidth, this._fbHeight);

        // Adjust the visible viewport based on the new dimensions
        this._updateClip();
        this._updateScale();

        this._updateContinuousUpdates();

        // Keep this size until browser client size changes
        this._saveExpectedClientSize();
    }

    _xvpOp(ver, op) {
        if (this._rfbXvpVer < ver) { return; }
        Log.Info("Sending XVP operation " + op + " (version " + ver + ")");
        RFB.messages.xvpOp(this._sock, ver, op);
    }

    _updateCursor(rgba, hotx, hoty, w, h) {
        this._cursorImage = {
            rgbaPixels: rgba,
            hotx: hotx, hoty: hoty, w: w, h: h,
        };
        this._refreshCursor();
    }

    _shouldShowDotCursor() {
        // Called when this._cursorImage is updated
        if (!this._showDotCursor) {
            // User does not want to see the dot, so...
            return false;
        }

        // The dot should not be shown if the cursor is already visible,
        // i.e. contains at least one not-fully-transparent pixel.
        // So iterate through all alpha bytes in rgba and stop at the
        // first non-zero.
        for (let i = 3; i < this._cursorImage.rgbaPixels.length; i += 4) {
            if (this._cursorImage.rgbaPixels[i]) {
                return false;
            }
        }

        // At this point, we know that the cursor is fully transparent, and
        // the user wants to see the dot instead of this.
        return true;
    }

    _refreshCursor() {
        if (this._rfbConnectionState !== "connecting" &&
            this._rfbConnectionState !== "connected") {
            return;
        }
        const image = this._shouldShowDotCursor() ? RFB.cursors.dot : this._cursorImage;
        this._cursor.change(image.rgbaPixels,
                            image.hotx, image.hoty,
                            image.w, image.h
        );
    }

    static genDES(password, challenge) {
        const passwordChars = password.split('').map(c => c.charCodeAt(0));
        const key = legacyCrypto.importKey(
            "raw", passwordChars, { name: "DES-ECB" }, false, ["encrypt"]);
        return legacyCrypto.encrypt({ name: "DES-ECB" }, key, challenge);
    }
}

// Class Methods
RFB.messages = {
    keyEvent(sock, keysym, down) {
        sock.sQpush8(4); // msg-type
        sock.sQpush8(down);

        sock.sQpush16(0);

        sock.sQpush32(keysym);

        sock.flush();
    },

    QEMUExtendedKeyEvent(sock, keysym, down, keycode) {
        function getRFBkeycode(xtScanCode) {
            const upperByte = (keycode >> 8);
            const lowerByte = (keycode & 0x00ff);
            if (upperByte === 0xe0 && lowerByte < 0x7f) {
                return lowerByte | 0x80;
            }
            return xtScanCode;
        }

        sock.sQpush8(255); // msg-type
        sock.sQpush8(0); // sub msg-type

        sock.sQpush16(down);

        sock.sQpush32(keysym);

        const RFBkeycode = getRFBkeycode(keycode);

        sock.sQpush32(RFBkeycode);

        sock.flush();
    },

    pointerEvent(sock, x, y, mask) {
        sock.sQpush8(5); // msg-type

        // Marker bit must be set to 0, otherwise the server might
        // confuse the marker bit with the highest bit in a normal
        // PointerEvent message.
        mask = mask & 0x7f;
        sock.sQpush8(mask);

        sock.sQpush16(x);
        sock.sQpush16(y);

        sock.flush();
    },

    extendedPointerEvent(sock, x, y, mask) {
        sock.sQpush8(5); // msg-type

        let higherBits = (mask >> 7) & 0xff;

        // Bits 2-7 are reserved
        if (higherBits & 0xfc) {
            throw new Error("Invalid mouse button mask: " + mask);
        }

        let lowerBits = mask & 0x7f;
        lowerBits |= 0x80; // Set marker bit to 1

        sock.sQpush8(lowerBits);
        sock.sQpush16(x);
        sock.sQpush16(y);
        sock.sQpush8(higherBits);

        sock.flush();
    },

    // Used to build Notify and Request data.
    _buildExtendedClipboardFlags(actions, formats) {
        let data = new Uint8Array(4);
        let formatFlag = 0x00000000;
        let actionFlag = 0x00000000;

        for (let i = 0; i < actions.length; i++) {
            actionFlag |= actions[i];
        }

        for (let i = 0; i < formats.length; i++) {
            formatFlag |= formats[i];
        }

        data[0] = actionFlag >> 24; // Actions
        data[1] = 0x00;             // Reserved
        data[2] = 0x00;             // Reserved
        data[3] = formatFlag;       // Formats

        return data;
    },

    extendedClipboardProvide(sock, formats, inData) {
        // Deflate incomming data and their sizes
        let deflator = new Deflator();
        let dataToDeflate = [];

        for (let i = 0; i < formats.length; i++) {
            // We only support the format Text at this time
            if (formats[i] != extendedClipboardFormatText) {
                throw new Error("Unsupported extended clipboard format for Provide message.");
            }

            // Change lone \r or \n into \r\n as defined in rfbproto
            inData[i] = inData[i].replace(/\r\n|\r|\n/gm, "\r\n");

            // Check if it already has \0
            let text = encodeUTF8(inData[i] + "\0");

            dataToDeflate.push( (text.length >> 24) & 0xFF,
                                (text.length >> 16) & 0xFF,
                                (text.length >>  8) & 0xFF,
                                (text.length & 0xFF));

            for (let j = 0; j < text.length; j++) {
                dataToDeflate.push(text.charCodeAt(j));
            }
        }

        let deflatedData = deflator.deflate(new Uint8Array(dataToDeflate));

        // Build data  to send
        let data = new Uint8Array(4 + deflatedData.length);
        data.set(RFB.messages._buildExtendedClipboardFlags([extendedClipboardActionProvide],
                                                           formats));
        data.set(deflatedData, 4);

        RFB.messages.clientCutText(sock, data, true);
    },

    extendedClipboardNotify(sock, formats) {
        let flags = RFB.messages._buildExtendedClipboardFlags([extendedClipboardActionNotify],
                                                              formats);
        RFB.messages.clientCutText(sock, flags, true);
    },

    extendedClipboardRequest(sock, formats) {
        let flags = RFB.messages._buildExtendedClipboardFlags([extendedClipboardActionRequest],
                                                              formats);
        RFB.messages.clientCutText(sock, flags, true);
    },

    extendedClipboardCaps(sock, actions, formats) {
        let formatKeys = Object.keys(formats);
        let data  = new Uint8Array(4 + (4 * formatKeys.length));

        formatKeys.map(x => parseInt(x));
        formatKeys.sort((a, b) =>  a - b);

        data.set(RFB.messages._buildExtendedClipboardFlags(actions, []));

        let loopOffset = 4;
        for (let i = 0; i < formatKeys.length; i++) {
            data[loopOffset]     = formats[formatKeys[i]] >> 24;
            data[loopOffset + 1] = formats[formatKeys[i]] >> 16;
            data[loopOffset + 2] = formats[formatKeys[i]] >> 8;
            data[loopOffset + 3] = formats[formatKeys[i]] >> 0;

            loopOffset += 4;
            data[3] |= (1 << formatKeys[i]); // Update our format flags
        }

        RFB.messages.clientCutText(sock, data, true);
    },

    clientCutText(sock, data, extended = false) {
        sock.sQpush8(6); // msg-type

        sock.sQpush8(0); // padding
        sock.sQpush8(0); // padding
        sock.sQpush8(0); // padding

        let length;
        if (extended) {
            length = toUnsigned32bit(-data.length);
        } else {
            length = data.length;
        }

        sock.sQpush32(length);
        sock.sQpushBytes(data);
        sock.flush();
    },

    setDesktopSize(sock, width, height, id, flags) {
        sock.sQpush8(251); // msg-type

        sock.sQpush8(0); // padding

        sock.sQpush16(width);
        sock.sQpush16(height);

        sock.sQpush8(1); // number-of-screens

        sock.sQpush8(0); // padding

        // screen array
        sock.sQpush32(id);
        sock.sQpush16(0); // x-position
        sock.sQpush16(0); // y-position
        sock.sQpush16(width);
        sock.sQpush16(height);
        sock.sQpush32(flags);

        sock.flush();
    },

    clientFence(sock, flags, payload) {
        sock.sQpush8(248); // msg-type

        sock.sQpush8(0); // padding
        sock.sQpush8(0); // padding
        sock.sQpush8(0); // padding

        sock.sQpush32(flags);

        sock.sQpush8(payload.length);
        sock.sQpushString(payload);

        sock.flush();
    },

    enableContinuousUpdates(sock, enable, x, y, width, height) {
        sock.sQpush8(150); // msg-type

        sock.sQpush8(enable);

        sock.sQpush16(x);
        sock.sQpush16(y);
        sock.sQpush16(width);
        sock.sQpush16(height);

        sock.flush();
    },

    pixelFormat(sock, depth, trueColor, redShift, greenShift, blueShift) {
        let bpp;

        if (depth > 16) {
            bpp = 32;
        } else if (depth > 8) {
            bpp = 16;
        } else {
            bpp = 8;
        }

        const bits = Math.floor(depth/3);

        // Use provided shifts or default to RGB byte order
        if (redShift === undefined) { redShift = bits * 0; }
        if (greenShift === undefined) { greenShift = bits * 1; }
        if (blueShift === undefined) { blueShift = bits * 2; }

        sock.sQpush8(0); // msg-type

        sock.sQpush8(0); // padding
        sock.sQpush8(0); // padding
        sock.sQpush8(0); // padding

        sock.sQpush8(bpp);
        sock.sQpush8(depth);
        sock.sQpush8(0); // little-endian
        sock.sQpush8(trueColor ? 1 : 0);

        sock.sQpush16((1 << bits) - 1); // red-max
        sock.sQpush16((1 << bits) - 1); // green-max
        sock.sQpush16((1 << bits) - 1); // blue-max

        sock.sQpush8(redShift);
        sock.sQpush8(greenShift);
        sock.sQpush8(blueShift);

        sock.sQpush8(0); // padding
        sock.sQpush8(0); // padding
        sock.sQpush8(0); // padding

        sock.flush();
    },

    clientEncodings(sock, encodings) {
        sock.sQpush8(2); // msg-type

        sock.sQpush8(0); // padding

        sock.sQpush16(encodings.length);
        for (let i = 0; i < encodings.length; i++) {
            sock.sQpush32(encodings[i]);
        }

        sock.flush();
    },

    fbUpdateRequest(sock, incremental, x, y, w, h) {
        if (typeof(x) === "undefined") { x = 0; }
        if (typeof(y) === "undefined") { y = 0; }

        sock.sQpush8(3); // msg-type

        sock.sQpush8(incremental ? 1 : 0);

        sock.sQpush16(x);
        sock.sQpush16(y);
        sock.sQpush16(w);
        sock.sQpush16(h);

        sock.flush();
    },

    xvpOp(sock, ver, op) {
        sock.sQpush8(250); // msg-type

        sock.sQpush8(0); // padding

        sock.sQpush8(ver);
        sock.sQpush8(op);

        sock.flush();
    },

    encryptedEvent(sock, flags, encryptedPayload) {
        sock.sQpush8(0x10);              // msg-type: EncryptedEvent
        sock.sQpush8(flags);             // flags
        sock.sQpushBytes(encryptedPayload); // 16 bytes AES-ECB encrypted
        sock.flush();
    },

    ardClipboardRequest(sock, sessionId) {
        sock.sQpush8(0x0b); // msg-type: ClipboardRequest
        sock.sQpush8(0x00); // format (plain text)
        sock.sQpush16(0);   // reserved
        sock.sQpush32(sessionId);
        sock.flush();
    },

    ardClipboardSend(sock, sessionId, uncompressedSize, compressedData) {
        sock.sQpush8(0x1f);                        // msg-type: ClipboardSend
        sock.sQpush8(0x00);                        // format (plain text)
        sock.sQpush16(0);                          // reserved
        sock.sQpush32(sessionId);                  // session ID
        sock.sQpush32(uncompressedSize);            // uncompressed size
        sock.sQpush32(compressedData.length);       // compressed size
        sock.sQpushBytes(compressedData);           // zlib data
        sock.flush();
    },

    ardSetEncryption(sock, command) {
        sock.sQpush8(0x12);       // msg-type: SetEncryption
        sock.sQpush8(0x00);       // padding
        sock.sQpush16(command);   // 1=request, 2=acknowledge
        sock.sQpush16(1);         // level (1=all data)
        if (command === 1) {
            sock.sQpush16(1);     // numMethods=1
            sock.sQpush32(1);     // method=AES-128
        } else {
            sock.sQpush16(0);     // numMethods=0
        }
        sock.flush();
    },
};

RFB.cursors = {
    none: {
        rgbaPixels: new Uint8Array(),
        w: 0, h: 0,
        hotx: 0, hoty: 0,
    },

    dot: {
        /* eslint-disable indent */
        rgbaPixels: new Uint8Array([
            255, 255, 255, 255,   0,   0,   0, 255, 255, 255, 255, 255,
              0,   0,   0, 255,   0,   0,   0,   0,   0,   0,  0,  255,
            255, 255, 255, 255,   0,   0,   0, 255, 255, 255, 255, 255,
        ]),
        /* eslint-enable indent */
        w: 3, h: 3,
        hotx: 1, hoty: 1,
    }
};
