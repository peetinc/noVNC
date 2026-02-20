/*
 * noVNC: HTML5 VNC client
 * Copyright (C) 2019 The noVNC authors
 * Licensed under MPL 2.0 (see LICENSE.txt)
 *
 * See README.md for usage and integration instructions.
 */

import * as Log from '../core/util/logging.js';
import _, { l10n } from './localization.js';
import { isTouchDevice, isMac, isIOS, isAndroid, isChromeOS, isSafari,
         hasScrollbarGutter, dragThreshold, browserAsyncClipboardSupport }
    from '../core/util/browser.js';
import { setCapture, getPointerEvent } from '../core/util/events.js';
import KeyTable from "../core/input/keysym.js";
import keysyms from "../core/input/keysymdef.js";
import Keyboard from "../core/input/keyboard.js";
import RFB from "../core/rfb.js";
import WakeLockManager from './wakelock.js';
import * as WebUtil from "./webutil.js";

const PAGE_TITLE = "noVNC";

const LINGUAS = ["cs", "de", "el", "es", "fr", "hr", "hu", "it", "ja", "ko", "nl", "pl", "pt_BR", "ru", "sv", "tr", "uk", "zh_CN", "zh_TW"];

const UI = {

    customSettings: {},

    connected: false,
    desktopName: "",

    statusTimeout: null,
    hideKeyboardTimeout: null,
    idleControlbarTimeout: null,
    closeControlbarTimeout: null,

    controlbarGrabbed: false,
    controlbarDrag: false,
    controlbarMouseDownClientY: 0,
    controlbarMouseDownOffsetY: 0,

    lastKeyboardinput: null,
    defaultKeyboardinputLen: 100,

    inhibitReconnect: true,
    reconnectCallback: null,
    reconnectPassword: null,
    reconnectAttempt: 0,
    reconnectMaxAttempts: 10,
    reconnectEllipsisInterval: null,

    wakeLockManager: new WakeLockManager(),

    async start(options={}) {
        UI.customSettings = options.settings || {};
        if (UI.customSettings.defaults === undefined) {
            UI.customSettings.defaults = {};
        }
        if (UI.customSettings.mandatory === undefined) {
            UI.customSettings.mandatory = {};
        }

        // Set up translations
        try {
            await l10n.setup(LINGUAS, "app/locale/");
        } catch (err) {
            Log.Error("Failed to load translations: " + err);
        }

        // Initialize setting storage
        await WebUtil.initSettings();

        // Wait for the page to load
        if (document.readyState !== "interactive" && document.readyState !== "complete") {
            await new Promise((resolve, reject) => {
                document.addEventListener('DOMContentLoaded', resolve);
            });
        }

        UI.initSettings();

        // Translate the DOM
        l10n.translateDOM();

        // We rely on modern APIs which might not be available in an
        // insecure context
        if (!window.isSecureContext) {
            // FIXME: This gets hidden when connecting
            UI.showStatus(_("Running without HTTPS is not recommended, crashes or other issues are likely."), 'error');
        }

        // Try to fetch version number
        try {
            let response = await fetch('./package.json');
            if (!response.ok) {
                throw Error("" + response.status + " " + response.statusText);
            }

            let packageInfo = await response.json();
            Array.from(document.getElementsByClassName('noVNC_version')).forEach(el => el.innerText = packageInfo.version);
        } catch (err) {
            Log.Error("Couldn't fetch package.json: " + err);
            Array.from(document.getElementsByClassName('noVNC_version_wrapper'))
                .concat(Array.from(document.getElementsByClassName('noVNC_version_separator')))
                .forEach(el => el.style.display = 'none');
        }

        // Adapt the interface for touch screen devices
        if (isTouchDevice) {
            // Remove the address bar
            setTimeout(() => window.scrollTo(0, 1), 100);
        }

        // Restore control bar position
        if (WebUtil.readSetting('controlbar_pos') === 'right') {
            UI.toggleControlbarSide();
        }

        UI.initFullscreen();

        // Setup event handlers
        UI.addControlbarHandlers();
        UI.addTouchSpecificHandlers();
        UI.addExtraKeysHandlers();
        UI.addDisplaySelectHandlers();
        UI.addClipboardButtonHandlers();
        UI.addCurtainHandlers();
        UI.addKeyboardShortcutHandlers();
        UI.addQualitySelectHandlers();
        UI.addMachineHandlers();
        UI.addConnectionControlHandlers();
        UI.addClipboardHandlers();
        UI.addSettingsHandlers();
        UI.updateArdControlSettings(false);  // ensure ARD-only rows start hidden
        document.getElementById("noVNC_status")
            .addEventListener('click', UI.hideStatus);

        // Bootstrap fallback input handler
        UI.keyboardinputReset();

        UI.openControlbar();

        UI.updateVisualState('init');

        document.documentElement.classList.remove("noVNC_loading");

        let autoconnect = UI.getSetting('autoconnect');
        if (autoconnect === 'true' || autoconnect == '1') {
            UI.connect();
        } else {
            // Show the connect panel on first load unless autoconnecting
            UI.openConnectPanel();
        }
    },

    initFullscreen() {
        // Only show the button if fullscreen is properly supported
        // * Safari doesn't support alphanumerical input while in fullscreen
        if (!isSafari() &&
            (document.documentElement.requestFullscreen ||
             document.documentElement.mozRequestFullScreen ||
             document.documentElement.webkitRequestFullscreen ||
             document.body.msRequestFullscreen)) {
            document.getElementById('noVNC_fullscreen_button')
                .classList.remove("noVNC_hidden");
            UI.addFullscreenHandlers();
        }
    },

    initSettings() {
        // Logging selection dropdown
        const llevels = ['error', 'warn', 'info', 'debug'];
        for (let i = 0; i < llevels.length; i += 1) {
            UI.addOption(document.getElementById('noVNC_setting_logging'), llevels[i], llevels[i]);
        }

        // Settings with immediate effects
        UI.initSetting('logging', 'warn');
        UI.updateLogging();

        UI.setupSettingLabels();

        /* Populate the controls if defaults are provided in the URL */
        UI.initSetting('host', '');
        UI.initSetting('port', 0);
        UI.initSetting('encrypt', (window.location.protocol === "https:"));
        UI.initSetting('password');
        UI.initSetting('autoconnect', false);
        UI.initSetting('view_clip', false);
        UI.initSetting('resize', 'scale');
        UI.initSetting('quality', 6);
        UI.initSetting('compression', 2);
        UI.initSetting('shared', true);
        UI.initSetting('bell', 'on');
        UI.initSetting('view_only', false);
        UI.initSetting('show_dot', false);
        UI.initSetting('path', 'websockify');
        UI.initSetting('repeaterID', '');
        UI.initSetting('reconnect', false);
        UI.initSetting('reconnect_delay', 5000);
        UI.initSetting('keep_device_awake', false);
    },
    // Adds a link to the label elements on the corresponding input elements
    setupSettingLabels() {
        const labels = document.getElementsByTagName('LABEL');
        for (let i = 0; i < labels.length; i++) {
            const htmlFor = labels[i].htmlFor;
            if (htmlFor != '') {
                const elem = document.getElementById(htmlFor);
                if (elem) elem.label = labels[i];
            } else {
                // If 'for' isn't set, use the first input element child
                const children = labels[i].children;
                for (let j = 0; j < children.length; j++) {
                    if (children[j].form !== undefined) {
                        children[j].label = labels[i];
                        break;
                    }
                }
            }
        }
    },

/* ------^-------
*     /INIT
* ==============
* EVENT HANDLERS
* ------v------*/

    addControlbarHandlers() {
        document.getElementById("noVNC_control_bar")
            .addEventListener('mousemove', UI.activateControlbar);
        document.getElementById("noVNC_control_bar")
            .addEventListener('mouseup', UI.activateControlbar);
        document.getElementById("noVNC_control_bar")
            .addEventListener('mousedown', UI.activateControlbar);
        document.getElementById("noVNC_control_bar")
            .addEventListener('keydown', UI.activateControlbar);

        document.getElementById("noVNC_control_bar")
            .addEventListener('mousedown', UI.keepControlbar);
        document.getElementById("noVNC_control_bar")
            .addEventListener('keydown', UI.keepControlbar);

        document.getElementById("noVNC_view_drag_button")
            .addEventListener('click', UI.toggleViewDrag);

        document.getElementById("noVNC_control_bar_handle")
            .addEventListener('mousedown', UI.controlbarHandleMouseDown);
        document.getElementById("noVNC_control_bar_handle")
            .addEventListener('mouseup', UI.controlbarHandleMouseUp);
        document.getElementById("noVNC_control_bar_handle")
            .addEventListener('mousemove', UI.dragControlbarHandle);
        // resize events aren't available for elements
        window.addEventListener('resize', UI.updateControlbarHandle);

        const exps = document.getElementsByClassName("noVNC_expander");
        for (let i = 0;i < exps.length;i++) {
            exps[i].addEventListener('click', UI.toggleExpander);
        }
    },

    addTouchSpecificHandlers() {
        document.getElementById("noVNC_keyboard_button")
            .addEventListener('click', UI.toggleVirtualKeyboard);

        UI.touchKeyboard = new Keyboard(document.getElementById('noVNC_keyboardinput'));
        UI.touchKeyboard.onkeyevent = UI.keyEvent;
        UI.touchKeyboard.grab();
        document.getElementById("noVNC_keyboardinput")
            .addEventListener('input', UI.keyInput);
        document.getElementById("noVNC_keyboardinput")
            .addEventListener('focus', UI.onfocusVirtualKeyboard);
        document.getElementById("noVNC_keyboardinput")
            .addEventListener('blur', UI.onblurVirtualKeyboard);
        document.getElementById("noVNC_keyboardinput")
            .addEventListener('submit', () => false);

        document.documentElement
            .addEventListener('mousedown', UI.keepVirtualKeyboard, true);

        document.getElementById("noVNC_control_bar")
            .addEventListener('touchstart', UI.activateControlbar);
        document.getElementById("noVNC_control_bar")
            .addEventListener('touchmove', UI.activateControlbar);
        document.getElementById("noVNC_control_bar")
            .addEventListener('touchend', UI.activateControlbar);
        document.getElementById("noVNC_control_bar")
            .addEventListener('input', UI.activateControlbar);

        document.getElementById("noVNC_control_bar")
            .addEventListener('touchstart', UI.keepControlbar);
        document.getElementById("noVNC_control_bar")
            .addEventListener('input', UI.keepControlbar);

        document.getElementById("noVNC_control_bar_handle")
            .addEventListener('touchstart', UI.controlbarHandleMouseDown);
        document.getElementById("noVNC_control_bar_handle")
            .addEventListener('touchend', UI.controlbarHandleMouseUp);
        document.getElementById("noVNC_control_bar_handle")
            .addEventListener('touchmove', UI.dragControlbarHandle);
    },

    addExtraKeysHandlers() {
        document.getElementById("noVNC_toggle_extra_keys_button")
            .addEventListener('click', UI.toggleExtraKeys);
        document.getElementById("noVNC_toggle_ctrl_button")
            .addEventListener('click', UI.toggleCtrl);
        document.getElementById("noVNC_toggle_windows_button")
            .addEventListener('click', UI.toggleWindows);
        document.getElementById("noVNC_toggle_alt_button")
            .addEventListener('click', UI.toggleAlt);
        document.getElementById("noVNC_send_tab_button")
            .addEventListener('click', UI.sendTab);
        document.getElementById("noVNC_send_esc_button")
            .addEventListener('click', UI.sendEsc);
        document.getElementById("noVNC_send_ctrl_alt_del_button")
            .addEventListener('click', UI.sendCtrlAltDel);
    },

    addMachineHandlers() {
        document.getElementById("noVNC_shutdown_button")
            .addEventListener('click', () => UI.rfb.machineShutdown());
        document.getElementById("noVNC_reboot_button")
            .addEventListener('click', () => UI.rfb.machineReboot());
        document.getElementById("noVNC_reset_button")
            .addEventListener('click', () => UI.rfb.machineReset());
        document.getElementById("noVNC_power_button")
            .addEventListener('click', UI.togglePowerPanel);
    },

    addConnectionControlHandlers() {
        document.getElementById("noVNC_disconnect_button")
            .addEventListener('click', UI.disconnect);
        document.getElementById("noVNC_connect_button")
            .addEventListener('click', UI.connect);
        document.getElementById("noVNC_cancel_reconnect_button")
            .addEventListener('click', UI.cancelReconnect);

        document.getElementById("noVNC_approve_server_button")
            .addEventListener('click', UI.approveServer);
        document.getElementById("noVNC_reject_server_button")
            .addEventListener('click', UI.rejectServer);
        document.getElementById("noVNC_credentials_button")
            .addEventListener('click', UI.setCredentials);
        document.getElementById("noVNC_ard_session_share_button")
            .addEventListener('click', UI.ardSessionSelectShare);
        document.getElementById("noVNC_ard_session_virtual_button")
            .addEventListener('click', UI.ardSessionSelectVirtual);
    },

    addClipboardHandlers() {
        document.getElementById("noVNC_clipboard_button")
            .addEventListener('click', UI.toggleClipboardPanel);
        document.getElementById("noVNC_clipboard_text")
            .addEventListener('change', UI.clipboardSend);
    },

    // Add a call to save settings when the element changes,
    // unless the optional parameter changeFunc is used instead.
    addSettingChangeHandler(name, changeFunc) {
        const settingElem = document.getElementById("noVNC_setting_" + name);
        if (changeFunc === undefined) {
            changeFunc = () => UI.saveSetting(name);
        }
        settingElem.addEventListener('change', changeFunc);
    },

    addSettingsHandlers() {
        document.getElementById("noVNC_settings_button")
            .addEventListener('click', UI.toggleSettingsPanel);

        UI.addSettingChangeHandler('encrypt');
        UI.addSettingChangeHandler('resize');
        UI.addSettingChangeHandler('resize', UI.applyResizeMode);
        UI.addSettingChangeHandler('resize', UI.updateViewClip);
        UI.addSettingChangeHandler('quality');
        UI.addSettingChangeHandler('quality', UI.updateQuality);
        UI.addSettingChangeHandler('compression');
        UI.addSettingChangeHandler('compression', UI.updateCompression);
        UI.addSettingChangeHandler('view_clip');
        UI.addSettingChangeHandler('view_clip', UI.updateViewClip);
        UI.addSettingChangeHandler('shared');
        UI.addSettingChangeHandler('shared', () => {
            // When connected to ARD, clicking Shared mode → Control (mode 1).
            // If the user tries to uncheck it, snap back (radio behaviour).
            if (UI.rfb && UI.rfb.isAppleARD) UI.setArdControlModeUI(1);
        });
        UI.addSettingChangeHandler('view_only');
        UI.addSettingChangeHandler('view_only', UI.updateViewOnly);
        // Exclusive control — ARD only, not persisted
        document.getElementById('noVNC_setting_exclusive_control')
            .addEventListener('change', () => {
                if (UI.rfb && UI.rfb.isAppleARD) UI.setArdControlModeUI(2);
            });
        UI.addSettingChangeHandler('show_dot');
        UI.addSettingChangeHandler('show_dot', UI.updateShowDotCursor);
        UI.addSettingChangeHandler('keep_device_awake');
        UI.addSettingChangeHandler('keep_device_awake', UI.updateRequestWakelock);
        UI.addSettingChangeHandler('host');
        UI.addSettingChangeHandler('port');
        UI.addSettingChangeHandler('path');
        UI.addSettingChangeHandler('repeaterID');
        UI.addSettingChangeHandler('logging');
        UI.addSettingChangeHandler('logging', UI.updateLogging);
        UI.addSettingChangeHandler('reconnect');
        UI.addSettingChangeHandler('reconnect_delay');
    },

    addFullscreenHandlers() {
        document.getElementById("noVNC_fullscreen_button")
            .addEventListener('click', UI.toggleFullscreen);

        window.addEventListener('fullscreenchange', UI.updateFullscreenButton);
        window.addEventListener('mozfullscreenchange', UI.updateFullscreenButton);
        window.addEventListener('webkitfullscreenchange', UI.updateFullscreenButton);
        window.addEventListener('msfullscreenchange', UI.updateFullscreenButton);
    },

/* ------^-------
 * /EVENT HANDLERS
 * ==============
 *     VISUAL
 * ------v------*/

    // Disable/enable controls depending on connection state
    updateVisualState(state) {

        document.documentElement.classList.remove("noVNC_connecting");
        document.documentElement.classList.remove("noVNC_connected");
        document.documentElement.classList.remove("noVNC_disconnecting");
        document.documentElement.classList.remove("noVNC_reconnecting");

        const transitionElem = document.getElementById("noVNC_transition_text");
        switch (state) {
            case 'init':
                break;
            case 'connecting':
                transitionElem.textContent = _("Connecting...");
                document.documentElement.classList.add("noVNC_connecting");
                break;
            case 'connected':
                document.documentElement.classList.add("noVNC_connected");
                break;
            case 'disconnecting':
                transitionElem.textContent = _("Disconnecting...");
                document.documentElement.classList.add("noVNC_disconnecting");
                break;
            case 'disconnected':
                break;
            case 'reconnecting':
                transitionElem.textContent = _("Reconnecting...");
                document.documentElement.classList.add("noVNC_reconnecting");
                break;
            default:
                Log.Error("Invalid visual state: " + state);
                UI.showStatus(_("Internal error"), 'error');
                return;
        }

        if (UI.connected) {
            UI.updateViewClip();

            UI.disableSetting('encrypt');
            UI.disableSetting('shared');
            UI.disableSetting('host');
            UI.disableSetting('port');
            UI.disableSetting('path');
            UI.disableSetting('repeaterID');

            // Hide the controlbar after 2 seconds
            UI.closeControlbarTimeout = setTimeout(UI.closeControlbar, 2000);
        } else {
            UI.enableSetting('encrypt');
            UI.enableSetting('shared');
            UI.enableSetting('host');
            UI.enableSetting('port');
            UI.enableSetting('path');
            UI.enableSetting('repeaterID');
            UI.updatePowerButton();
            UI.keepControlbar();
        }

        // State change closes dialogs as they may not be relevant
        // anymore
        UI.closeAllPanels();
        document.getElementById('noVNC_verify_server_dlg')
            .classList.remove('noVNC_open');
        document.getElementById('noVNC_credentials_dlg')
            .classList.remove('noVNC_open');
    },

    showStatus(text, statusType, time) {
        const statusElem = document.getElementById('noVNC_status');

        if (typeof statusType === 'undefined') {
            statusType = 'normal';
        }

        // Don't overwrite more severe visible statuses and never
        // errors. Only shows the first error.
        if (statusElem.classList.contains("noVNC_open")) {
            if (statusElem.classList.contains("noVNC_status_error")) {
                return;
            }
            if (statusElem.classList.contains("noVNC_status_warn") &&
                statusType === 'normal') {
                return;
            }
        }

        clearTimeout(UI.statusTimeout);

        switch (statusType) {
            case 'error':
                statusElem.classList.remove("noVNC_status_warn");
                statusElem.classList.remove("noVNC_status_normal");
                statusElem.classList.add("noVNC_status_error");
                break;
            case 'warning':
            case 'warn':
                statusElem.classList.remove("noVNC_status_error");
                statusElem.classList.remove("noVNC_status_normal");
                statusElem.classList.add("noVNC_status_warn");
                break;
            case 'normal':
            case 'info':
            default:
                statusElem.classList.remove("noVNC_status_error");
                statusElem.classList.remove("noVNC_status_warn");
                statusElem.classList.add("noVNC_status_normal");
                break;
        }

        statusElem.textContent = text;
        statusElem.classList.add("noVNC_open");

        // If no time was specified, show the status for 1.5 seconds
        if (typeof time === 'undefined') {
            time = 1500;
        }

        // Error messages do not timeout
        if (statusType !== 'error') {
            UI.statusTimeout = window.setTimeout(UI.hideStatus, time);
        }
    },

    hideStatus() {
        clearTimeout(UI.statusTimeout);
        document.getElementById('noVNC_status').classList.remove("noVNC_open");
    },

    activateControlbar(event) {
        clearTimeout(UI.idleControlbarTimeout);
        // We manipulate the anchor instead of the actual control
        // bar in order to avoid creating new a stacking group
        document.getElementById('noVNC_control_bar_anchor')
            .classList.remove("noVNC_idle");
        UI.idleControlbarTimeout = window.setTimeout(UI.idleControlbar, 2000);
    },

    idleControlbar() {
        // Don't fade if a child of the control bar has focus
        if (document.getElementById('noVNC_control_bar')
            .contains(document.activeElement) && document.hasFocus()) {
            UI.activateControlbar();
            return;
        }

        document.getElementById('noVNC_control_bar_anchor')
            .classList.add("noVNC_idle");
    },

    keepControlbar() {
        clearTimeout(UI.closeControlbarTimeout);
    },

    openControlbar() {
        document.getElementById('noVNC_control_bar')
            .classList.add("noVNC_open");
    },

    closeControlbar() {
        UI.closeAllPanels();
        document.getElementById('noVNC_control_bar')
            .classList.remove("noVNC_open");
        UI.rfb.focus();
    },

    toggleControlbar() {
        if (document.getElementById('noVNC_control_bar')
            .classList.contains("noVNC_open")) {
            UI.closeControlbar();
        } else {
            UI.openControlbar();
        }
    },

    toggleControlbarSide() {
        // Temporarily disable animation, if bar is displayed, to avoid weird
        // movement. The transitionend-event will not fire when display=none.
        const bar = document.getElementById('noVNC_control_bar');
        const barDisplayStyle = window.getComputedStyle(bar).display;
        if (barDisplayStyle !== 'none') {
            bar.style.transitionDuration = '0s';
            bar.addEventListener('transitionend', () => bar.style.transitionDuration = '');
        }

        const anchor = document.getElementById('noVNC_control_bar_anchor');
        if (anchor.classList.contains("noVNC_right")) {
            WebUtil.writeSetting('controlbar_pos', 'left');
            anchor.classList.remove("noVNC_right");
        } else {
            WebUtil.writeSetting('controlbar_pos', 'right');
            anchor.classList.add("noVNC_right");
        }

        // Consider this a movement of the handle
        UI.controlbarDrag = true;

        // The user has "followed" hint, let's hide it until the next drag
        UI.showControlbarHint(false, false);
    },

    showControlbarHint(show, animate=true) {
        const hint = document.getElementById('noVNC_control_bar_hint');

        if (animate) {
            hint.classList.remove("noVNC_notransition");
        } else {
            hint.classList.add("noVNC_notransition");
        }

        if (show) {
            hint.classList.add("noVNC_active");
        } else {
            hint.classList.remove("noVNC_active");
        }
    },

    dragControlbarHandle(e) {
        if (!UI.controlbarGrabbed) return;

        const ptr = getPointerEvent(e);

        const anchor = document.getElementById('noVNC_control_bar_anchor');
        if (ptr.clientX < (window.innerWidth * 0.1)) {
            if (anchor.classList.contains("noVNC_right")) {
                UI.toggleControlbarSide();
            }
        } else if (ptr.clientX > (window.innerWidth * 0.9)) {
            if (!anchor.classList.contains("noVNC_right")) {
                UI.toggleControlbarSide();
            }
        }

        if (!UI.controlbarDrag) {
            const dragDistance = Math.abs(ptr.clientY - UI.controlbarMouseDownClientY);

            if (dragDistance < dragThreshold) return;

            UI.controlbarDrag = true;
        }

        const eventY = ptr.clientY - UI.controlbarMouseDownOffsetY;

        UI.moveControlbarHandle(eventY);

        e.preventDefault();
        e.stopPropagation();
        UI.keepControlbar();
        UI.activateControlbar();
    },

    // Move the handle but don't allow any position outside the bounds
    moveControlbarHandle(viewportRelativeY) {
        const handle = document.getElementById("noVNC_control_bar_handle");
        const handleHeight = handle.getBoundingClientRect().height;
        const controlbarBounds = document.getElementById("noVNC_control_bar")
            .getBoundingClientRect();
        const margin = 10;

        // These heights need to be non-zero for the below logic to work
        if (handleHeight === 0 || controlbarBounds.height === 0) {
            return;
        }

        let newY = viewportRelativeY;

        // Check if the coordinates are outside the control bar
        if (newY < controlbarBounds.top + margin) {
            // Force coordinates to be below the top of the control bar
            newY = controlbarBounds.top + margin;

        } else if (newY > controlbarBounds.top +
                   controlbarBounds.height - handleHeight - margin) {
            // Force coordinates to be above the bottom of the control bar
            newY = controlbarBounds.top +
                controlbarBounds.height - handleHeight - margin;
        }

        // Corner case: control bar too small for stable position
        if (controlbarBounds.height < (handleHeight + margin * 2)) {
            newY = controlbarBounds.top +
                (controlbarBounds.height - handleHeight) / 2;
        }

        // The transform needs coordinates that are relative to the parent
        const parentRelativeY = newY - controlbarBounds.top;
        handle.style.transform = "translateY(" + parentRelativeY + "px)";
    },

    updateControlbarHandle() {
        // Since the control bar is fixed on the viewport and not the page,
        // the move function expects coordinates relative the the viewport.
        const handle = document.getElementById("noVNC_control_bar_handle");
        const handleBounds = handle.getBoundingClientRect();
        UI.moveControlbarHandle(handleBounds.top);
    },

    controlbarHandleMouseUp(e) {
        if ((e.type == "mouseup") && (e.button != 0)) return;

        // mouseup and mousedown on the same place toggles the controlbar
        if (UI.controlbarGrabbed && !UI.controlbarDrag) {
            UI.toggleControlbar();
            e.preventDefault();
            e.stopPropagation();
            UI.keepControlbar();
            UI.activateControlbar();
        }
        UI.controlbarGrabbed = false;
        UI.showControlbarHint(false);
    },

    controlbarHandleMouseDown(e) {
        if ((e.type == "mousedown") && (e.button != 0)) return;

        const ptr = getPointerEvent(e);

        const handle = document.getElementById("noVNC_control_bar_handle");
        const bounds = handle.getBoundingClientRect();

        // Touch events have implicit capture
        if (e.type === "mousedown") {
            setCapture(handle);
        }

        UI.controlbarGrabbed = true;
        UI.controlbarDrag = false;

        UI.showControlbarHint(true);

        UI.controlbarMouseDownClientY = ptr.clientY;
        UI.controlbarMouseDownOffsetY = ptr.clientY - bounds.top;
        e.preventDefault();
        e.stopPropagation();
        UI.keepControlbar();
        UI.activateControlbar();
    },

    toggleExpander(e) {
        if (this.classList.contains("noVNC_open")) {
            this.classList.remove("noVNC_open");
        } else {
            this.classList.add("noVNC_open");
        }
    },

/* ------^-------
 *    /VISUAL
 * ==============
 *    SETTINGS
 * ------v------*/

    // Initial page load read/initialization of settings
    initSetting(name, defVal) {
        // Has the user overridden the default value?
        if (name in UI.customSettings.defaults) {
            defVal = UI.customSettings.defaults[name];
        }
        // Check Query string followed by cookie
        let val = WebUtil.getConfigVar(name);
        if (val === null) {
            val = WebUtil.readSetting(name, defVal);
        }
        WebUtil.setSetting(name, val);
        UI.updateSetting(name);
        // Has the user forced a value?
        if (name in UI.customSettings.mandatory) {
            val = UI.customSettings.mandatory[name];
            UI.forceSetting(name, val);
        }
        return val;
    },

    // Set the new value, update and disable form control setting
    forceSetting(name, val) {
        WebUtil.setSetting(name, val);
        UI.updateSetting(name);
        UI.disableSetting(name);
    },

    // Update cookie and form control setting. If value is not set, then
    // updates from control to current cookie setting.
    updateSetting(name) {

        // Update the settings control
        let value = UI.getSetting(name);

        const ctrl = document.getElementById('noVNC_setting_' + name);
        if (ctrl === null) {
            return;
        }

        if (ctrl.type === 'checkbox') {
            ctrl.checked = value;
        } else if (typeof ctrl.options !== 'undefined') {
            for (let i = 0; i < ctrl.options.length; i += 1) {
                if (ctrl.options[i].value === value) {
                    ctrl.selectedIndex = i;
                    break;
                }
            }
        } else {
            ctrl.value = value;
        }
    },

    // Save control setting to cookie
    saveSetting(name) {
        const ctrl = document.getElementById('noVNC_setting_' + name);
        let val;
        if (ctrl.type === 'checkbox') {
            val = ctrl.checked;
        } else if (typeof ctrl.options !== 'undefined') {
            val = ctrl.options[ctrl.selectedIndex].value;
        } else {
            val = ctrl.value;
        }
        WebUtil.writeSetting(name, val);
        //Log.Debug("Setting saved '" + name + "=" + val + "'");
        return val;
    },

    // Read form control compatible setting from cookie
    getSetting(name) {
        const ctrl = document.getElementById('noVNC_setting_' + name);
        let val = WebUtil.readSetting(name);
        if (typeof val !== 'undefined' && val !== null &&
            ctrl !== null && ctrl.type === 'checkbox') {
            if (val.toString().toLowerCase() in {'0': 1, 'no': 1, 'false': 1}) {
                val = false;
            } else {
                val = true;
            }
        }
        return val;
    },

    // These helpers compensate for the lack of parent-selectors and
    // previous-sibling-selectors in CSS which are needed when we want to
    // disable the labels that belong to disabled input elements.
    disableSetting(name) {
        const ctrl = document.getElementById('noVNC_setting_' + name);
        if (ctrl !== null) {
            ctrl.disabled = true;
            if (ctrl.label !== undefined) {
                ctrl.label.classList.add('noVNC_disabled');
            }
        }
    },

    enableSetting(name) {
        const ctrl = document.getElementById('noVNC_setting_' + name);
        if (ctrl !== null) {
            ctrl.disabled = false;
            if (ctrl.label !== undefined) {
                ctrl.label.classList.remove('noVNC_disabled');
            }
        }
    },

/* ------^-------
 *   /SETTINGS
 * ==============
 *    PANELS
 * ------v------*/

    closeAllPanels() {
        UI.closeSettingsPanel();
        UI.closePowerPanel();
        UI.closeClipboardPanel();
        UI.closeCurtainPanel();
        UI.closeExtraKeys();
        UI.closeDisplaySelect();
        UI.closeQualitySelect();
    },

/* ------^-------
 *   /PANELS
 * ==============
 * SETTINGS (panel)
 * ------v------*/

    openSettingsPanel() {
        UI.closeAllPanels();
        UI.openControlbar();

        // Refresh UI elements from saved cookies
        UI.updateSetting('encrypt');
        UI.updateSetting('view_clip');
        UI.updateSetting('resize');
        UI.updateSetting('quality');
        UI.updateSetting('compression');
        UI.updateSetting('shared');
        UI.updateSetting('view_only');
        UI.updateSetting('path');
        UI.updateSetting('repeaterID');
        UI.updateSetting('logging');
        UI.updateSetting('reconnect');
        UI.updateSetting('reconnect_delay');

        document.getElementById('noVNC_settings')
            .classList.add("noVNC_open");
        document.getElementById('noVNC_settings_button')
            .classList.add("noVNC_selected");
    },

    closeSettingsPanel() {
        document.getElementById('noVNC_settings')
            .classList.remove("noVNC_open");
        document.getElementById('noVNC_settings_button')
            .classList.remove("noVNC_selected");
    },

    toggleSettingsPanel() {
        if (document.getElementById('noVNC_settings')
            .classList.contains("noVNC_open")) {
            UI.closeSettingsPanel();
        } else {
            UI.openSettingsPanel();
        }
    },

/* ------^-------
 *   /SETTINGS
 * ==============
 *     POWER
 * ------v------*/

    openPowerPanel() {
        UI.closeAllPanels();
        UI.openControlbar();

        document.getElementById('noVNC_power')
            .classList.add("noVNC_open");
        document.getElementById('noVNC_power_button')
            .classList.add("noVNC_selected");
    },

    closePowerPanel() {
        document.getElementById('noVNC_power')
            .classList.remove("noVNC_open");
        document.getElementById('noVNC_power_button')
            .classList.remove("noVNC_selected");
    },

    togglePowerPanel() {
        if (document.getElementById('noVNC_power')
            .classList.contains("noVNC_open")) {
            UI.closePowerPanel();
        } else {
            UI.openPowerPanel();
        }
    },

    // Disable/enable power button
    updatePowerButton() {
        if (UI.connected &&
            UI.rfb.capabilities.power &&
            !UI.rfb.viewOnly) {
            document.getElementById('noVNC_power_button')
                .classList.remove("noVNC_hidden");
        } else {
            document.getElementById('noVNC_power_button')
                .classList.add("noVNC_hidden");
            // Close power panel if open
            UI.closePowerPanel();
        }
    },

/* ------^-------
 *    /POWER
 * ==============
 *   CLIPBOARD
 * ------v------*/

    openClipboardPanel() {
        UI.closeAllPanels();
        UI.openControlbar();

        document.getElementById('noVNC_clipboard')
            .classList.add("noVNC_open");
        document.getElementById('noVNC_clipboard_button')
            .classList.add("noVNC_selected");
    },

    closeClipboardPanel() {
        document.getElementById('noVNC_clipboard')
            .classList.remove("noVNC_open");
        document.getElementById('noVNC_clipboard_button')
            .classList.remove("noVNC_selected");
    },

    toggleClipboardPanel() {
        if (document.getElementById('noVNC_clipboard')
            .classList.contains("noVNC_open")) {
            UI.closeClipboardPanel();
        } else {
            UI.openClipboardPanel();
        }
    },

    clipboardReceive(e) {
        Log.Debug(">> UI.clipboardReceive: " + e.detail.text.substr(0, 40) + "...");
        const text = e.detail.text;
        document.getElementById('noVNC_clipboard_text').value = text;
        // Always push to the browser's native clipboard — whether triggered
        // by auto-sync or a manual "get". The sync flag gates whether we
        // request clipboard data at all (in rfb.js), not what we do with it
        // once it arrives.
        navigator.clipboard.writeText(text).catch(() => {});
        Log.Debug("<< UI.clipboardReceive");
    },

    clipboardSend() {
        const text = document.getElementById('noVNC_clipboard_text').value;
        Log.Debug(">> UI.clipboardSend: " + text.substr(0, 40) + "...");
        UI.rfb.clipboardPasteFrom(text);
        Log.Debug("<< UI.clipboardSend");
    },

/* ------^-------
 *  /CLIPBOARD
 * ==============
 *  CONNECTION
 * ------v------*/

    openConnectPanel() {
        document.getElementById('noVNC_connect_dlg')
            .classList.add("noVNC_open");
    },

    closeConnectPanel() {
        document.getElementById('noVNC_connect_dlg')
            .classList.remove("noVNC_open");
    },

    connect(event, password) {

        // Ignore when rfb already exists
        if (typeof UI.rfb !== 'undefined') {
            return;
        }

        const host = UI.getSetting('host');
        const port = UI.getSetting('port');
        const path = UI.getSetting('path');

        if (typeof password === 'undefined') {
            password = UI.getSetting('password');
            UI.reconnectPassword = password;
        }

        if (password === null) {
            password = undefined;
        }

        UI.hideStatus();

        UI.closeConnectPanel();

        UI.updateVisualState('connecting');

        let url;

        if (host) {
            url = new URL("https://" + host);

            url.protocol = UI.getSetting('encrypt') ? 'wss:' : 'ws:';
            if (port) {
                url.port = port;
            }

            // "./" is needed to force URL() to interpret the path-variable as
            // a path and not as an URL. This is relevant if for example path
            // starts with more than one "/", in which case it would be
            // interpreted as a host name instead.
            url = new URL("./" + path, url);
        } else {
            // Current (May 2024) browsers support relative WebSocket
            // URLs natively, but we need to support older browsers for
            // some time.
            url = new URL(path, location.href);
            url.protocol = (window.location.protocol === "https:") ? 'wss:' : 'ws:';
        }

        if (UI.getSetting('keep_device_awake')) {
            UI.wakeLockManager.acquire();
        }

        try {
            UI.rfb = new RFB(document.getElementById('noVNC_container'),
                             url.href,
                             { shared: UI.getSetting('shared'),
                               repeaterID: UI.getSetting('repeaterID'),
                               credentials: { password: password } });
        } catch (exc) {
            Log.Error("Failed to connect to server: " + exc);
            UI.updateVisualState('disconnected');
            UI.showStatus(_("Failed to connect to server: ") + exc, 'error');
            return;
        }

        UI.rfb.addEventListener("connect", UI.connectFinished);
        UI.rfb.addEventListener("disconnect", UI.disconnectFinished);
        UI.rfb.addEventListener("arddisplaylist", UI.ardDisplayListUpdated);
        UI.rfb.addEventListener("serververification", UI.serverVerify);
        UI.rfb.addEventListener("credentialsrequired", UI.credentials);
        UI.rfb.addEventListener("ardsessionselect", UI.ardSessionSelect);
        UI.rfb.addEventListener("securityfailure", UI.securityFailed);
        UI.rfb.addEventListener("clippingviewport", UI.updateViewDrag);
        UI.rfb.addEventListener("capabilities", UI.updatePowerButton);
        UI.rfb.addEventListener("clipboard", UI.clipboardReceive);
        UI.rfb.addEventListener("ardcurtainchange", UI.curtainStateChanged);
        UI.rfb.addEventListener("arduserinfo", UI.ardUserInfoChanged);
        UI.rfb.addEventListener("ardconsolestate", UI.ardConsoleStateChanged);
        UI.rfb.addEventListener("bell", UI.bell);
        UI.rfb.addEventListener("desktopname", UI.updateDesktopName);
        UI.rfb.clipViewport = UI.getSetting('view_clip');
        UI.rfb.scaleViewport = UI.getSetting('resize') === 'scale';
        UI.rfb.resizeSession = UI.getSetting('resize') === 'remote';
        UI.rfb.qualityLevel = parseInt(UI.getSetting('quality'));
        UI.rfb.compressionLevel = parseInt(UI.getSetting('compression'));
        UI.rfb.showDotCursor = UI.getSetting('show_dot');

        UI.updateViewOnly(); // requires UI.rfb
        UI.updateClipboard();
    },

    disconnect() {
        UI.rfb.disconnect();

        UI.connected = false;

        // Disable automatic reconnecting
        UI.inhibitReconnect = true;

        UI.updateVisualState('disconnecting');

        // Don't display the connection settings until we're actually disconnected
    },

    startReconnectAnimation(attempt) {
        // Stop any existing animation
        if (UI.reconnectEllipsisInterval) {
            clearInterval(UI.reconnectEllipsisInterval);
        }

        const transitionText = document.getElementById('noVNC_transition_text');
        let ellipsisCount = 0;

        const updateText = () => {
            const ellipsis = '.'.repeat((ellipsisCount % 3) + 1);
            transitionText.textContent = `Reconnecting${ellipsis} (attempt ${attempt}/${UI.reconnectMaxAttempts})`;
            ellipsisCount++;
        };

        updateText();
        UI.reconnectEllipsisInterval = setInterval(updateText, 500);
    },

    stopReconnectAnimation() {
        if (UI.reconnectEllipsisInterval) {
            clearInterval(UI.reconnectEllipsisInterval);
            UI.reconnectEllipsisInterval = null;
        }
    },

    reconnect() {
        UI.reconnectCallback = null;

        // if reconnect has been disabled in the meantime, do nothing.
        if (UI.inhibitReconnect) {
            return;
        }

        UI.connect(null, UI.reconnectPassword);
    },

    cancelReconnect() {
        if (UI.reconnectCallback !== null) {
            clearTimeout(UI.reconnectCallback);
            UI.reconnectCallback = null;
        }

        UI.stopReconnectAnimation();
        UI.reconnectAttempt = 0;
        UI.updateVisualState('disconnected');

        UI.openControlbar();
        UI.openConnectPanel();
    },

    connectFinished(e) {
        UI.connected = true;
        UI.inhibitReconnect = false;
        UI.reconnectAttempt = 0; // Reset on successful connection
        UI.stopReconnectAnimation();

        let msg;
        if (UI.getSetting('encrypt')) {
            msg = _("Connected (encrypted) to ") + UI.desktopName;
        } else {
            msg = _("Connected (unencrypted) to ") + UI.desktopName;
        }
        UI.showStatus(msg);
        UI.updateVisualState('connected');

        // Adapt modifier key labels for ARD (Mac) connections
        if (UI.rfb && UI.rfb.isAppleARD) {
            UI.applyMacKeyLabels();
        }

        UI.updateClipboardButtons(true);
        UI.updateArdControlSettings(!!(UI.rfb && UI.rfb.isAppleARD));
        UI.updateCurtainButton(!!(UI.rfb && UI.rfb.isAppleARD));
        UI.updateBeforeUnload();

        // Do this last because it can only be used on rendered elements
        UI.rfb.focus();
    },

    disconnectFinished(e) {
        const wasConnected = UI.connected;

        // This variable is ideally set when disconnection starts, but
        // when the disconnection isn't clean or if it is initiated by
        // the server, we need to do it here as well since
        // UI.disconnect() won't be used in those cases.
        UI.connected = false;
        UI.updateClipboardButtons(false);
        UI.updateArdControlSettings(false);
        UI.updateCurtainButton(false);

        // Hide ARD user avatar
        const avatarDiv = document.getElementById('noVNC_ard_user_avatar');
        if (avatarDiv) {
            avatarDiv.style.display = 'none';
        }

        UI.rfb = undefined;
        UI.wakeLockManager.release();

        if (!e.detail.clean) {
            UI.updateVisualState('disconnected');
            if (wasConnected) {
                UI.showStatus(_("Something went wrong, connection is closed"),
                              'error');
            } else {
                UI.showStatus(_("Failed to connect to server"), 'error');
            }
        }
        // ARD: Always auto-reconnect (like Screen Sharing.app)
        const isARD = wasConnected && UI.reconnectPassword !== null;
        const shouldReconnect = isARD || (UI.getSetting('reconnect', false) === true);

        if (shouldReconnect && !UI.inhibitReconnect) {
            UI.updateVisualState('reconnecting');

            // ARD uses Screen Sharing's fast reconnect pattern
            if (isARD) {
                UI.reconnectAttempt++;

                // Backoff delays: 100ms, 1s, 2s, 5s, 10s, then cap at 10s
                let delay;
                if (UI.reconnectAttempt === 1) delay = 100;
                else if (UI.reconnectAttempt === 2) delay = 1000;
                else if (UI.reconnectAttempt === 3) delay = 2000;
                else if (UI.reconnectAttempt === 4) delay = 5000;
                else delay = 10000; // Cap at 10s for remaining attempts

                if (UI.reconnectAttempt >= UI.reconnectMaxAttempts) {
                    UI.showStatus(_("Reconnect failed after ") + UI.reconnectAttempt + _(" attempts"), 'error');
                    UI.updateVisualState('disconnected');
                    UI.openControlbar();
                    UI.openConnectPanel();
                    return;
                }

                UI.startReconnectAnimation(UI.reconnectAttempt);
                UI.reconnectCallback = setTimeout(UI.reconnect, delay);
            } else {
                // Standard reconnect using setting
                const delay = parseInt(UI.getSetting('reconnect_delay'));
                UI.reconnectCallback = setTimeout(UI.reconnect, delay);
            }
            return;
        } else {
            UI.updateVisualState('disconnected');
            UI.showStatus(_("Disconnected"), 'normal');
        }

        UI.updateBeforeUnload();

        document.title = PAGE_TITLE;

        UI.openControlbar();
        UI.openConnectPanel();
    },

    securityFailed(e) {
        let msg;
        // On security failures we might get a string with a reason
        // directly from the server. Note that we can't control if
        // this string is translated or not.
        if ('reason' in e.detail) {
            msg = _("New connection has been rejected with reason: ") +
                e.detail.reason;
        } else {
            msg = _("New connection has been rejected");
        }
        UI.showStatus(msg, 'error');
    },

    handleBeforeUnload(e) {
        // Trigger a "Leave site?" warning prompt before closing the
        // page. Modern browsers (Oct 2025) accept either (or both)
        // preventDefault() or a nonempty returnValue, though the latter is
        // considered legacy. The custom string is ignored by modern browsers,
        // which display a native message, but older browsers will show it.
        e.preventDefault();
        e.returnValue = _("Are you sure you want to disconnect the session?");
    },

    updateBeforeUnload() {
        // Remove first to avoid adding duplicates
        window.removeEventListener("beforeunload", UI.handleBeforeUnload);
        if (!UI.rfb?.viewOnly && UI.connected) {
            window.addEventListener("beforeunload", UI.handleBeforeUnload);
        }
    },

/* ------^-------
 *  /CONNECTION
 * ==============
 * SERVER VERIFY
 * ------v------*/

    async serverVerify(e) {
        const type = e.detail.type;
        if (type === 'RSA') {
            const publickey = e.detail.publickey;
            let fingerprint = await window.crypto.subtle.digest("SHA-1", publickey);
            // The same fingerprint format as RealVNC
            fingerprint = Array.from(new Uint8Array(fingerprint).slice(0, 8)).map(
                x => x.toString(16).padStart(2, '0')).join('-');
            document.getElementById('noVNC_verify_server_dlg').classList.add('noVNC_open');
            document.getElementById('noVNC_fingerprint').innerHTML = fingerprint;
        }
    },

    approveServer(e) {
        e.preventDefault();
        document.getElementById('noVNC_verify_server_dlg').classList.remove('noVNC_open');
        UI.rfb.approveServer();
    },

    rejectServer(e) {
        e.preventDefault();
        document.getElementById('noVNC_verify_server_dlg').classList.remove('noVNC_open');
        UI.disconnect();
    },

/* ------^-------
 * /SERVER VERIFY
 * ==============
 *   PASSWORD
 * ------v------*/

    ardSessionSelect(e) {
        const username = e.detail.username;
        const hasUser = e.detail.hasConsoleUser;

        // Only show picker if console user is logged in
        if (!hasUser) {
            return; // Auto-connects to console
        }

        // Show session select dialog
        const usernameSpan = document.getElementById('noVNC_ard_session_username');
        usernameSpan.textContent = username;

        document.getElementById('noVNC_ard_session_dlg').classList.add('noVNC_open');

        Log.Info("ARD Session Select: Waiting for user to choose session type");
        UI.showStatus(_("Choose session type"), "normal");
    },

    ardSessionSelectShare(e) {
        e.preventDefault();
        document.getElementById('noVNC_ard_session_dlg').classList.remove('noVNC_open');
        UI.rfb.selectSessionType(1); // ConnectToConsole
    },

    ardSessionSelectVirtual(e) {
        e.preventDefault();
        document.getElementById('noVNC_ard_session_dlg').classList.remove('noVNC_open');
        UI.rfb.selectSessionType(2); // ConnectToVirtualDisplay
    },

    credentials(e) {
        // FIXME: handle more types

        document.getElementById("noVNC_username_block").classList.remove("noVNC_hidden");
        document.getElementById("noVNC_password_block").classList.remove("noVNC_hidden");

        let inputFocus = "none";
        if (e.detail.types.indexOf("username") === -1) {
            document.getElementById("noVNC_username_block").classList.add("noVNC_hidden");
        } else {
            inputFocus = inputFocus === "none" ? "noVNC_username_input" : inputFocus;
        }
        if (e.detail.types.indexOf("password") === -1) {
            document.getElementById("noVNC_password_block").classList.add("noVNC_hidden");
        } else {
            inputFocus = inputFocus === "none" ? "noVNC_password_input" : inputFocus;
        }
        document.getElementById('noVNC_credentials_dlg')
            .classList.add('noVNC_open');

        setTimeout(() => document
            .getElementById(inputFocus).focus(), 100);

        Log.Warn("Server asked for credentials");
        UI.showStatus(_("Credentials are required"), "warning");
    },

    setCredentials(e) {
        // Prevent actually submitting the form
        e.preventDefault();

        let inputElemUsername = document.getElementById('noVNC_username_input');
        const username = inputElemUsername.value;

        let inputElemPassword = document.getElementById('noVNC_password_input');
        const password = inputElemPassword.value;
        // Clear the input after reading the password
        inputElemPassword.value = "";

        UI.rfb.sendCredentials({ username: username, password: password });
        UI.reconnectPassword = password;
        document.getElementById('noVNC_credentials_dlg')
            .classList.remove('noVNC_open');
    },

/* ------^-------
 *  /PASSWORD
 * ==============
 *   FULLSCREEN
 * ------v------*/

    toggleFullscreen() {
        if (document.fullscreenElement || // alternative standard method
            document.mozFullScreenElement || // currently working methods
            document.webkitFullscreenElement ||
            document.msFullscreenElement) {
            // Release keyboard lock before leaving fullscreen
            if (navigator.keyboard && navigator.keyboard.unlock) {
                navigator.keyboard.unlock();
            }
            if (document.exitFullscreen) {
                document.exitFullscreen();
            } else if (document.mozCancelFullScreen) {
                document.mozCancelFullScreen();
            } else if (document.webkitExitFullscreen) {
                document.webkitExitFullscreen();
            } else if (document.msExitFullscreen) {
                document.msExitFullscreen();
            }
        } else {
            // Keyboard Lock API requires the call to happen after fullscreen
            // is granted, so chain it on the returned Promise.  Browsers that
            // don't support the API (Firefox, Safari) silently no-op.
            const lockKeys = () => {
                if (navigator.keyboard && navigator.keyboard.lock) {
                    navigator.keyboard.lock([
                        'MetaLeft', 'MetaRight',
                        'AltLeft', 'AltRight',
                        'Escape',
                        'F1', 'F2', 'F3', 'F4', 'F5', 'F6',
                        'F7', 'F8', 'F9', 'F10', 'F11', 'F12',
                    ]).catch(() => {});
                }
            };
            let fsPromise;
            if (document.documentElement.requestFullscreen) {
                fsPromise = document.documentElement.requestFullscreen();
            } else if (document.documentElement.mozRequestFullScreen) {
                document.documentElement.mozRequestFullScreen();
            } else if (document.documentElement.webkitRequestFullscreen) {
                document.documentElement.webkitRequestFullscreen(Element.ALLOW_KEYBOARD_INPUT);
            } else if (document.body.msRequestFullscreen) {
                document.body.msRequestFullscreen();
            }
            if (fsPromise) {
                fsPromise.then(lockKeys).catch(() => {});
            }
        }
        UI.updateFullscreenButton();
    },

    updateFullscreenButton() {
        if (document.fullscreenElement || // alternative standard method
            document.mozFullScreenElement || // currently working methods
            document.webkitFullscreenElement ||
            document.msFullscreenElement ) {
            document.getElementById('noVNC_fullscreen_button')
                .classList.add("noVNC_selected");
        } else {
            document.getElementById('noVNC_fullscreen_button')
                .classList.remove("noVNC_selected");
        }
    },

/* ------^-------
 *  /FULLSCREEN
 * ==============
 *     RESIZE
 * ------v------*/

    // Apply remote resizing or local scaling
    applyResizeMode() {
        if (!UI.rfb) return;

        UI.rfb.scaleViewport = UI.getSetting('resize') === 'scale';
        UI.rfb.resizeSession = UI.getSetting('resize') === 'remote';
    },

/* ------^-------
 *    /RESIZE
 * ==============
 * VIEW CLIPPING
 * ------v------*/

    // Update viewport clipping property for the connection. The normal
    // case is to get the value from the setting. There are special cases
    // for when the viewport is scaled or when a touch device is used.
    updateViewClip() {
        if (!UI.rfb) return;

        const scaling = UI.getSetting('resize') === 'scale';

        // Some platforms have overlay scrollbars that are difficult
        // to use in our case, which means we have to force panning
        // FIXME: Working scrollbars can still be annoying to use with
        //        touch, so we should ideally be able to have both
        //        panning and scrollbars at the same time

        let brokenScrollbars = false;

        if (!hasScrollbarGutter) {
            if (isIOS() || isAndroid() || isMac() || isChromeOS()) {
                brokenScrollbars = true;
            }
        }

        if (scaling) {
            // Can't be clipping if viewport is scaled to fit
            UI.forceSetting('view_clip', false);
            UI.rfb.clipViewport  = false;
        } else if (brokenScrollbars) {
            UI.forceSetting('view_clip', true);
            UI.rfb.clipViewport = true;
        } else {
            UI.enableSetting('view_clip');
            UI.rfb.clipViewport = UI.getSetting('view_clip');
        }

        // Changing the viewport may change the state of
        // the dragging button
        UI.updateViewDrag();
    },

/* ------^-------
 * /VIEW CLIPPING
 * ==============
 *    VIEWDRAG
 * ------v------*/

    toggleViewDrag() {
        if (!UI.rfb) return;

        UI.rfb.dragViewport = !UI.rfb.dragViewport;
        UI.updateViewDrag();
    },

    updateViewDrag() {
        if (!UI.connected) return;

        const viewDragButton = document.getElementById('noVNC_view_drag_button');

        if ((!UI.rfb.clipViewport || !UI.rfb.clippingViewport) &&
            UI.rfb.dragViewport) {
            // We are no longer clipping the viewport. Make sure
            // viewport drag isn't active when it can't be used.
            UI.rfb.dragViewport = false;
        }

        if (UI.rfb.dragViewport) {
            viewDragButton.classList.add("noVNC_selected");
        } else {
            viewDragButton.classList.remove("noVNC_selected");
        }

        if (UI.rfb.clipViewport) {
            viewDragButton.classList.remove("noVNC_hidden");
        } else {
            viewDragButton.classList.add("noVNC_hidden");
        }

        viewDragButton.disabled = !UI.rfb.clippingViewport;
    },

/* ------^-------
 *   /VIEWDRAG
 * ==============
 *    QUALITY
 * ------v------*/

    updateQuality() {
        if (!UI.rfb) return;

        UI.rfb.qualityLevel = parseInt(UI.getSetting('quality'));
    },

/* ------^-------
 *   /QUALITY
 * ==============
 *  COMPRESSION
 * ------v------*/

    updateCompression() {
        if (!UI.rfb) return;

        UI.rfb.compressionLevel = parseInt(UI.getSetting('compression'));
    },

/* ------^-------
 *  /COMPRESSION
 * ==============
 *    KEYBOARD
 * ------v------*/

    showVirtualKeyboard() {
        if (!isTouchDevice) return;

        const input = document.getElementById('noVNC_keyboardinput');

        if (document.activeElement == input) return;

        input.focus();

        try {
            const l = input.value.length;
            // Move the caret to the end
            input.setSelectionRange(l, l);
        } catch (err) {
            // setSelectionRange is undefined in Google Chrome
        }
    },

    hideVirtualKeyboard() {
        if (!isTouchDevice) return;

        const input = document.getElementById('noVNC_keyboardinput');

        if (document.activeElement != input) return;

        input.blur();
    },

    toggleVirtualKeyboard() {
        if (document.getElementById('noVNC_keyboard_button')
            .classList.contains("noVNC_selected")) {
            UI.hideVirtualKeyboard();
        } else {
            UI.showVirtualKeyboard();
        }
    },

    onfocusVirtualKeyboard(event) {
        document.getElementById('noVNC_keyboard_button')
            .classList.add("noVNC_selected");
        if (UI.rfb) {
            UI.rfb.focusOnClick = false;
        }
    },

    onblurVirtualKeyboard(event) {
        document.getElementById('noVNC_keyboard_button')
            .classList.remove("noVNC_selected");
        if (UI.rfb) {
            UI.rfb.focusOnClick = true;
        }
    },

    keepVirtualKeyboard(event) {
        const input = document.getElementById('noVNC_keyboardinput');

        // Only prevent focus change if the virtual keyboard is active
        if (document.activeElement != input) {
            return;
        }

        // Only allow focus to move to other elements that need
        // focus to function properly
        if (event.target.form !== undefined) {
            switch (event.target.type) {
                case 'text':
                case 'email':
                case 'search':
                case 'password':
                case 'tel':
                case 'url':
                case 'textarea':
                case 'select-one':
                case 'select-multiple':
                    return;
            }
        }

        event.preventDefault();
    },

    keyboardinputReset() {
        const kbi = document.getElementById('noVNC_keyboardinput');
        kbi.value = new Array(UI.defaultKeyboardinputLen).join("_");
        UI.lastKeyboardinput = kbi.value;
    },

    keyEvent(keysym, code, down) {
        if (!UI.rfb) return;

        UI.rfb.sendKey(keysym, code, down);
    },

    // When normal keyboard events are left uncought, use the input events from
    // the keyboardinput element instead and generate the corresponding key events.
    // This code is required since some browsers on Android are inconsistent in
    // sending keyCodes in the normal keyboard events when using on screen keyboards.
    keyInput(event) {

        if (!UI.rfb) return;

        const newValue = event.target.value;

        if (!UI.lastKeyboardinput) {
            UI.keyboardinputReset();
        }
        const oldValue = UI.lastKeyboardinput;

        let newLen;
        try {
            // Try to check caret position since whitespace at the end
            // will not be considered by value.length in some browsers
            newLen = Math.max(event.target.selectionStart, newValue.length);
        } catch (err) {
            // selectionStart is undefined in Google Chrome
            newLen = newValue.length;
        }
        const oldLen = oldValue.length;

        let inputs = newLen - oldLen;
        let backspaces = inputs < 0 ? -inputs : 0;

        // Compare the old string with the new to account for
        // text-corrections or other input that modify existing text
        for (let i = 0; i < Math.min(oldLen, newLen); i++) {
            if (newValue.charAt(i) != oldValue.charAt(i)) {
                inputs = newLen - i;
                backspaces = oldLen - i;
                break;
            }
        }

        // Send the key events
        for (let i = 0; i < backspaces; i++) {
            UI.rfb.sendKey(KeyTable.XK_BackSpace, "Backspace");
        }
        for (let i = newLen - inputs; i < newLen; i++) {
            UI.rfb.sendKey(keysyms.lookup(newValue.charCodeAt(i)));
        }

        // Control the text content length in the keyboardinput element
        if (newLen > 2 * UI.defaultKeyboardinputLen) {
            UI.keyboardinputReset();
        } else if (newLen < 1) {
            // There always have to be some text in the keyboardinput
            // element with which backspace can interact.
            UI.keyboardinputReset();
            // This sometimes causes the keyboard to disappear for a second
            // but it is required for the android keyboard to recognize that
            // text has been added to the field
            event.target.blur();
            // This has to be ran outside of the input handler in order to work
            setTimeout(event.target.focus.bind(event.target), 0);
        } else {
            UI.lastKeyboardinput = newValue;
        }
    },

/* ------^-------
 *   /KEYBOARD
 * ==============
 *   EXTRA KEYS
 * ------v------*/

    openExtraKeys() {
        UI.closeAllPanels();
        UI.openControlbar();

        document.getElementById('noVNC_modifiers')
            .classList.add("noVNC_open");
        document.getElementById('noVNC_toggle_extra_keys_button')
            .classList.add("noVNC_selected");
    },

    closeExtraKeys() {
        document.getElementById('noVNC_modifiers')
            .classList.remove("noVNC_open");
        document.getElementById('noVNC_toggle_extra_keys_button')
            .classList.remove("noVNC_selected");
    },

    toggleExtraKeys() {
        if (document.getElementById('noVNC_modifiers')
            .classList.contains("noVNC_open")) {
            UI.closeExtraKeys();
        } else  {
            UI.openExtraKeys();
        }
    },

    sendEsc() {
        UI.sendKey(KeyTable.XK_Escape, "Escape");
    },

    sendTab() {
        UI.sendKey(KeyTable.XK_Tab, "Tab");
    },

    toggleCtrl() {
        const btn = document.getElementById('noVNC_toggle_ctrl_button');
        if (btn.classList.contains("noVNC_selected")) {
            UI.sendKey(KeyTable.XK_Control_L, "ControlLeft", false);
            btn.classList.remove("noVNC_selected");
        } else {
            UI.sendKey(KeyTable.XK_Control_L, "ControlLeft", true);
            btn.classList.add("noVNC_selected");
        }
    },

    toggleWindows() {
        const btn = document.getElementById('noVNC_toggle_windows_button');
        if (btn.classList.contains("noVNC_selected")) {
            UI.sendKey(KeyTable.XK_Super_L, "MetaLeft", false);
            btn.classList.remove("noVNC_selected");
        } else {
            UI.sendKey(KeyTable.XK_Super_L, "MetaLeft", true);
            btn.classList.add("noVNC_selected");
        }
    },

    toggleAlt() {
        const btn = document.getElementById('noVNC_toggle_alt_button');
        if (btn.classList.contains("noVNC_selected")) {
            UI.sendKey(KeyTable.XK_Alt_L, "AltLeft", false);
            btn.classList.remove("noVNC_selected");
        } else {
            UI.sendKey(KeyTable.XK_Alt_L, "AltLeft", true);
            btn.classList.add("noVNC_selected");
        }
    },

    sendCtrlAltDel() {
        UI.rfb.sendCtrlAltDel();
        // See below
        UI.rfb.focus();
        UI.idleControlbar();
    },

    applyMacKeyLabels() {
        const ctrlBtn = document.getElementById('noVNC_toggle_ctrl_button');
        ctrlBtn.src = "app/images/ctrl.svg";
        ctrlBtn.alt = "Ctrl";
        ctrlBtn.title = "Toggle Control";

        const altBtn = document.getElementById('noVNC_toggle_alt_button');
        altBtn.src = "app/images/opt.svg";
        altBtn.alt = "Opt";
        altBtn.title = "Toggle Option";

        const winBtn = document.getElementById('noVNC_toggle_windows_button');
        winBtn.src = "app/images/cmd.svg";
        winBtn.alt = "Cmd";
        winBtn.title = "Toggle Command";
    },

    sendKey(keysym, code, down) {
        UI.rfb.sendKey(keysym, code, down);

        // Move focus to the screen in order to be able to use the
        // keyboard right after these extra keys.
        // The exception is when a virtual keyboard is used, because
        // if we focus the screen the virtual keyboard would be closed.
        // In this case we focus our special virtual keyboard input
        // element instead.
        if (document.getElementById('noVNC_keyboard_button')
            .classList.contains("noVNC_selected")) {
            document.getElementById('noVNC_keyboardinput').focus();
        } else {
            UI.rfb.focus();
        }
        // fade out the controlbar to highlight that
        // the focus has been moved to the screen
        UI.idleControlbar();
    },

/* ------^-------
 *   /EXTRA KEYS
 * ==============
 *  DISPLAY SELECT
 * ------v------*/

    addDisplaySelectHandlers() {
        document.getElementById('noVNC_display_select_button')
            .addEventListener('click', UI.toggleDisplaySelect);
    },

    addClipboardButtonHandlers() {
        document.getElementById('noVNC_clipboard_send_button')
            .addEventListener('click', async () => {
                if (!UI.rfb) return;
                let text;
                try {
                    text = await navigator.clipboard.readText();
                } catch (e) {
                    // Clipboard API unavailable or permission denied — fall back
                    text = document.getElementById('noVNC_clipboard_text').value;
                }
                UI.rfb.forceClipboardPaste(text);
            });
        document.getElementById('noVNC_clipboard_get_button')
            .addEventListener('click', () => {
                if (UI.rfb) UI.rfb.requestRemoteClipboard();
            });
        document.getElementById('noVNC_clipboard_sync_button')
            .addEventListener('click', UI.toggleClipboardSync);
    },

    _clipboardSyncEnabled: true,
    _ardCurtainMessage: '',  // empty = use placeholder default on send

    addCurtainHandlers() {
        document.getElementById('noVNC_curtain_button')
            .addEventListener('click', () => {
                if (!UI.rfb) return;
                if (UI.rfb.ardCurtainActive) {
                    // Currently locked — unlock immediately, no panel needed
                    UI.rfb.ardCurtainUnlock();
                } else {
                    // About to lock — open panel for message confirmation
                    UI.toggleCurtainPanel();
                }
            });
        document.getElementById('noVNC_curtain_lock_button')
            .addEventListener('click', UI.engageCurtain);
        document.getElementById('noVNC_curtain_message')
            .addEventListener('keydown', (e) => {
                if (e.key === 'Enter') { e.preventDefault(); UI.engageCurtain(); }
                if (e.key === 'Escape') { UI.closeCurtainPanel(); }
            });
    },

    openCurtainPanel() {
        UI.closeAllPanels();
        UI.openControlbar();
        const input = document.getElementById('noVNC_curtain_message');
        // Show stored custom message as editable value; if none yet, leave
        // empty so the placeholder (default message in gray) is visible.
        input.value = UI._ardCurtainMessage;
        document.getElementById('noVNC_curtain_panel').classList.add('noVNC_open');
        document.getElementById('noVNC_curtain_button').classList.add('noVNC_selected');
    },

    closeCurtainPanel() {
        document.getElementById('noVNC_curtain_panel').classList.remove('noVNC_open');
        document.getElementById('noVNC_curtain_button').classList.remove('noVNC_selected');
    },

    toggleCurtainPanel() {
        if (document.getElementById('noVNC_curtain_panel')
                .classList.contains('noVNC_open')) {
            UI.closeCurtainPanel();
        } else {
            UI.openCurtainPanel();
        }
    },

    engageCurtain() {
        if (!UI.rfb) return;
        const input = document.getElementById('noVNC_curtain_message');
        const typed = input.value.trim();
        // If user typed something, store it for next time; otherwise keep
        // whatever was stored (or fall back to the placeholder default).
        if (typed) UI._ardCurtainMessage = typed;
        const msg = UI._ardCurtainMessage ||
                    input.placeholder; // placeholder = built-in default
        UI.closeCurtainPanel();
        UI.rfb.ardCurtainLock(msg);
    },

    curtainStateChanged(e) {
        UI.updateCurtainButton(!!(UI.rfb && UI.rfb.isAppleARD));
    },

    ardUserInfoChanged(e) {
        UI.updateCurtainButton(!!(UI.rfb && UI.rfb.isAppleARD));

        // Update user avatar in sidebar
        const avatarDiv = document.getElementById('noVNC_ard_user_avatar');
        const avatarImg = document.getElementById('noVNC_ard_user_avatar_img');
        if (UI.rfb && UI.rfb._ardUserAvatarPng) {
            // ARD sends raw BGRA pixel data (not PNG despite encoding=6)
            // Typical 32x32 = 4096 bytes
            const data = UI.rfb._ardUserAvatarPng;
            const size = Math.sqrt(data.length / 4); // width = height for square avatar

            if (size % 1 === 0) { // Valid square dimensions
                const canvas = document.createElement('canvas');
                canvas.width = size;
                canvas.height = size;
                const ctx = canvas.getContext('2d', { alpha: true });

                // Clear canvas to fully transparent
                ctx.clearRect(0, 0, size, size);

                const imageData = ctx.createImageData(size, size);

                // Copy RGBA directly (no channel swap needed, force opaque)
                // Note: Alpha channel exists but can't be used reliably, so force opaque
                for (let i = 0; i < data.length; i += 4) {
                    imageData.data[i]     = data[i];     // R
                    imageData.data[i + 1] = data[i + 1]; // G
                    imageData.data[i + 2] = data[i + 2]; // B
                    imageData.data[i + 3] = 255;         // Force fully opaque
                }

                ctx.putImageData(imageData, 0, 0);
                avatarImg.src = canvas.toDataURL('image/png');
                avatarDiv.style.display = 'block';
                avatarDiv.title = (UI.rfb.ardUsername || 'User') + ' is signed in';
            } else {
                console.error("ARD avatar: invalid dimensions, data length=" + data.length);
                avatarDiv.style.display = 'none';
            }
        } else {
            avatarDiv.style.display = 'none';
            avatarImg.src = '';
            avatarDiv.title = '';
        }
    },

    ardConsoleStateChanged(e) {
        UI.updateCurtainButton(!!(UI.rfb && UI.rfb.isAppleARD));
    },

    updateCurtainButton(isARD) {
        const btn = document.getElementById('noVNC_curtain_button');
        btn.classList.toggle('noVNC_hidden', !isARD);
        if (!isARD) {
            btn.disabled = true;
            UI.closeCurtainPanel();
            return;
        }
        const active = UI.rfb && UI.rfb.ardCurtainActive;
        const consoleActive = UI.rfb && UI.rfb.ardConsoleActive;

        // Disable curtain when remote is at lock/login screen — server will reject it
        btn.disabled = !consoleActive;

        // Swap icon: lock-open when inactive, lock when active
        const svgOpen = '<rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/>';
        const svgLock = '<rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>';
        btn.querySelector('svg').innerHTML = active ? svgLock : svgOpen;
        btn.classList.toggle('noVNC_selected', !!active);

        if (!consoleActive) {
            btn.title = 'Screen lock unavailable — remote Mac is at the login or lock screen';
        } else if (active) {
            btn.title = 'Unlock remote screen';
        } else {
            btn.title = 'Lock remote screen';
        }
    },

    toggleClipboardSync() {
        UI._clipboardSyncEnabled = !UI._clipboardSyncEnabled;
        const syncActive = UI._clipboardSyncEnabled;
        Log.Info("Clipboard sync toggled: " + (syncActive ? "ON" : "OFF"));
        const btn = document.getElementById('noVNC_clipboard_sync_button');
        btn.classList.toggle('noVNC_selected', syncActive);
        btn.title = syncActive ? 'Disable clipboard auto-sync' : 'Enable clipboard auto-sync';
        // Send/get only usable when sync is off
        document.getElementById('noVNC_clipboard_send_button').disabled = syncActive;
        document.getElementById('noVNC_clipboard_get_button').disabled = syncActive;
        if (UI.rfb) UI.rfb.enableClipboardSync(syncActive);
    },

    updateClipboardButtons(connected) {
        const isARD = connected && UI.rfb && UI.rfb.isAppleARD;
        const syncBtn   = document.getElementById('noVNC_clipboard_sync_button');
        const sendBtn   = document.getElementById('noVNC_clipboard_send_button');
        const getBtn    = document.getElementById('noVNC_clipboard_get_button');

        // Only show the ARD clipboard buttons when connected to macOS;
        // hide the legacy clipboard panel button when ARD takes over.
        syncBtn.classList.toggle('noVNC_hidden', !isARD);
        sendBtn.classList.toggle('noVNC_hidden', !isARD);
        getBtn.classList.toggle('noVNC_hidden', !isARD);
        document.getElementById('noVNC_clipboard_button')
            .classList.toggle('noVNC_hidden', !!isARD);

        syncBtn.disabled = !isARD;
        if (isARD) {
            // Sync is always ON at connect (init sends AutoPasteboard(1))
            syncBtn.classList.toggle('noVNC_selected', UI._clipboardSyncEnabled);
        }
        const sendGetEnabled = isARD && !UI._clipboardSyncEnabled;
        sendBtn.disabled = !sendGetEnabled;
        getBtn.disabled = !sendGetEnabled;
        if (!connected) {
            UI._clipboardSyncEnabled = true;  // matches init default
            syncBtn.classList.remove('noVNC_selected');
        }
    },

    // Set ARD control mode and enforce radio-button exclusivity across the
    // three access-mode toggles (Shared / View only / Exclusive control).
    // mode: 0=Observe, 1=Control, 2=Exclusive
    setArdControlModeUI(mode) {
        document.getElementById('noVNC_setting_shared').checked           = (mode === 1);
        UI.saveSetting('shared', mode === 1);
        document.getElementById('noVNC_setting_view_only').checked        = (mode === 0);
        UI.saveSetting('view_only', mode === 0);
        document.getElementById('noVNC_setting_exclusive_control').checked = (mode === 2);

        if (UI.rfb) UI.rfb.ardControlMode = mode;
        // rfb.ardControlMode setter drives rfb.viewOnly which handles
        // keyboard/clipboard grab.  Update toolbar visibility here.
        UI.updateBeforeUnload();
        const inputHidden = (mode === 0);
        document.getElementById('noVNC_keyboard_button')
            .classList.toggle('noVNC_hidden', inputHidden);
        document.getElementById('noVNC_toggle_extra_keys_button')
            .classList.toggle('noVNC_hidden', inputHidden);
        // Legacy clipboard button is always hidden on ARD (ARD has its own
        // clipboard buttons); only toggle it for non-ARD view-only changes.
        if (!UI.rfb || !UI.rfb.isAppleARD) {
            document.getElementById('noVNC_clipboard_button')
                .classList.toggle('noVNC_hidden', inputHidden);
        }
    },

    // Show or hide ARD-specific control mode settings and set the initial
    // mode based on the current Shared mode / View only toggle state.
    updateArdControlSettings(isARD) {
        document.getElementById('noVNC_ard_exclusive_row')
            .classList.toggle('noVNC_hidden', !isARD);

        if (isARD) {
            // Shared mode is normally disabled once connected; re-enable it
            // for ARD so the user can switch between modes mid-session.
            UI.enableSetting('shared');

            // Map pre-connect toggle state to initial ARD control mode:
            //   Shared ON, View only OFF → Control (1)
            //   View only ON (or both OFF / both ON) → Observe (0)
            const sharedOn   = UI.getSetting('shared');
            const viewOnlyOn = UI.getSetting('view_only');
            const initialMode = (sharedOn && !viewOnlyOn) ? 1 : 0;
            UI.setArdControlModeUI(initialMode);
        } else {
            document.getElementById('noVNC_setting_exclusive_control').checked = false;
        }
    },

    // Double-tap backtick (` `) triggers a full framebuffer refresh.
    // First tap passes through normally; second tap within 300 ms is
    // intercepted (not forwarded to the remote) and fires requestFullUpdate.
    _ardDisplaySwitchPending: false,
    _ardDisplaySwitchTimer: null,

    _lastBacktickMs: 0,

    addKeyboardShortcutHandlers() {
        document.addEventListener('keydown', (e) => {
            if (e.key !== '`') return;
            const now = Date.now();
            const elapsed = now - UI._lastBacktickMs;
            UI._lastBacktickMs = now;
            if (elapsed < 300 && UI.rfb) {
                e.stopPropagation();
                e.preventDefault();
                UI._lastBacktickMs = 0; // reset so triple-tap doesn't re-fire
                UI.rfb.requestFullUpdate();
            }
        }, true); // capture phase — fires before rfb canvas handler
    },

    openDisplaySelect() {
        UI.closeAllPanels();
        UI.openControlbar();
        document.getElementById('noVNC_display_select')
            .classList.add("noVNC_open");
        document.getElementById('noVNC_display_select_button')
            .classList.add("noVNC_selected");
        // Reflect the currently active display selection in the flyout
        if (UI.rfb) {
            const combineAll = UI.rfb.ardCombineAllDisplays;
            const displayId  = UI.rfb.ardSelectedDisplayId;
            document.getElementById('noVNC_display_select_buttons')
                .querySelectorAll('.noVNC_button').forEach((b) => {
                    const ca = parseInt(b.dataset.combineAll);
                    const id = parseInt(b.dataset.displayId);
                    const active = ca === combineAll &&
                                   (combineAll === 1 || id === displayId);
                    b.classList.toggle('noVNC_selected', active);
                });
        }
    },

    closeDisplaySelect() {
        document.getElementById('noVNC_display_select')
            .classList.remove("noVNC_open");
        document.getElementById('noVNC_display_select_button')
            .classList.remove("noVNC_selected");
    },

    toggleDisplaySelect() {
        const btn = document.getElementById('noVNC_display_select_button');
        if (btn.disabled) return;
        if (document.getElementById('noVNC_display_select')
            .classList.contains("noVNC_open")) {
            UI.closeDisplaySelect();
        } else {
            UI.openDisplaySelect();
        }
    },

    ardDisplayListUpdated(e) {
        const displays = e.detail.displays;

        const container = document.getElementById('noVNC_display_select_buttons');
        const btn = document.getElementById('noVNC_display_select_button');

        // Gray out when there is nothing to switch between
        if (!displays || displays.length <= 1) {
            btn.disabled = true;
            container.innerHTML = '';
            return;
        }
        btn.disabled = false;

        // Clear any pending switch lock — server has responded
        clearTimeout(UI._ardDisplaySwitchTimer);
        UI._ardDisplaySwitchPending = false;

        // Rebuild button list: "All" first, then sorted by display ID
        container.innerHTML = '';
        const sorted = displays.slice().sort((a, b) => a.id - b.id);

        const makeBtn = (label, combineAll, displayId) => {
            const el = document.createElement('button');
            el.className = 'noVNC_button';
            el.dataset.displayId = displayId;
            el.dataset.combineAll = combineAll;

            const icon = document.createElement('img');
            icon.src = 'app/images/monitor.svg';
            icon.alt = '';

            const text = document.createElement('span');
            text.textContent = label;

            el.appendChild(icon);
            el.appendChild(text);
            el.addEventListener('click', () => {
                if (UI._ardDisplaySwitchPending) return;
                UI._ardDisplaySwitchPending = true;
                // Fallback: unlock after 3s if server never responds
                clearTimeout(UI._ardDisplaySwitchTimer);
                UI._ardDisplaySwitchTimer = setTimeout(() => {
                    UI._ardDisplaySwitchPending = false;
                }, 3000);
                UI.rfb.selectDisplay(combineAll, displayId);
                // Mark active button
                container.querySelectorAll('.noVNC_button')
                    .forEach(b => b.classList.remove('noVNC_selected'));
                el.classList.add('noVNC_selected');
                UI.rfb.focus();
            });
            return el;
        };

        container.appendChild(makeBtn('All', 1, 0));
        sorted.forEach((d, i) => {
            container.appendChild(makeBtn(String(i + 1), 0, d.id));
        });
    },

/* ------^-------
 *  /DISPLAY SELECT
 * ==============
 *  QUALITY SELECT
 * ------v------*/

    addQualitySelectHandlers() {
        document.getElementById('noVNC_quality_button')
            .addEventListener('click', UI.toggleQualitySelect);
        const track = document.getElementById('noVNC_quality_track');
        track.addEventListener('pointerdown', UI.qualityDragStart);
    },

    openQualitySelect() {
        UI.closeAllPanels();
        UI.openControlbar();
        document.getElementById('noVNC_quality_panel')
            .classList.add("noVNC_open");
        document.getElementById('noVNC_quality_button')
            .classList.add("noVNC_selected");
        UI.syncQualityStops();
    },

    closeQualitySelect() {
        document.getElementById('noVNC_quality_panel')
            .classList.remove("noVNC_open");
        document.getElementById('noVNC_quality_button')
            .classList.remove("noVNC_selected");
    },

    toggleQualitySelect() {
        if (document.getElementById('noVNC_quality_panel')
            .classList.contains("noVNC_open")) {
            UI.closeQualitySelect();
        } else {
            UI.openQualitySelect();
        }
    },

    syncQualityStops() {
        const preset = UI.rfb ? UI.rfb.qualityPreset : 'thousands';
        UI.showQualityPreview(preset);
    },

    // Map a pointer Y position to the nearest quality preset
    qualityFromY(track, clientY) {
        const rect = track.getBoundingClientRect();
        const ratio = (clientY - rect.top) / rect.height;
        const clamped = Math.max(0, Math.min(1, ratio));
        // Top=millions(0), bottom=halftone(3) — 4 zones
        const presets = ['millions', 'thousands', 'gray', 'halftone'];
        const idx = Math.min(presets.length - 1, Math.floor(clamped * presets.length));
        return presets[idx];
    },

    qualityDragStart(e) {
        e.preventDefault();
        e.stopPropagation();
        const track = document.getElementById('noVNC_quality_track');
        track.setPointerCapture(e.pointerId);

        // Show visual preview immediately, but don't send to server yet
        let pending = UI.qualityFromY(track, e.clientY);
        UI.showQualityPreview(pending);

        const onMove = (ev) => {
            ev.preventDefault();
            pending = UI.qualityFromY(track, ev.clientY);
            UI.showQualityPreview(pending);
        };
        const onUp = (ev) => {
            pending = UI.qualityFromY(track, ev.clientY);
            // Send to server only on release
            if (UI.rfb) {
                UI.rfb.qualityPreset = pending;
            }
            UI.syncQualityStops();
            track.releasePointerCapture(ev.pointerId);
            track.removeEventListener('pointermove', onMove);
            track.removeEventListener('pointerup', onUp);
            track.removeEventListener('lostpointercapture', onUp);
        };

        track.addEventListener('pointermove', onMove);
        track.addEventListener('pointerup', onUp);
        track.addEventListener('lostpointercapture', onUp);
    },

    // Visual-only preview during drag (no server communication)
    showQualityPreview(preset) {
        document.querySelectorAll('.noVNC_quality_stop')
            .forEach((s) => {
                s.classList.toggle('noVNC_active',
                                   s.dataset.preset === preset);
            });
    },

/* ------^-------
 *  /QUALITY SELECT
 * ==============
 *     MISC
 * ------v------*/

    updateViewOnly() {
        if (!UI.rfb) return;

        if (UI.rfb.isAppleARD) {
            // For ARD: view_only toggle → Observe (mode 0).
            // Turning it off while in Observe falls back to Control (mode 1).
            // setArdControlModeUI handles rfb.ardControlMode + toolbar visibility.
            if (UI.getSetting('view_only')) {
                UI.setArdControlModeUI(0);
            } else if (UI.rfb.ardControlMode === 0) {
                UI.setArdControlModeUI(1);
            }
            return;
        }

        // Non-ARD: existing behaviour unchanged
        UI.rfb.viewOnly = UI.getSetting('view_only');
        UI.updateBeforeUnload();

        // Hide input related buttons in view only mode
        if (UI.rfb.viewOnly) {
            document.getElementById('noVNC_keyboard_button')
                .classList.add('noVNC_hidden');
            document.getElementById('noVNC_toggle_extra_keys_button')
                .classList.add('noVNC_hidden');
            document.getElementById('noVNC_clipboard_button')
                .classList.add('noVNC_hidden');
        } else {
            document.getElementById('noVNC_keyboard_button')
                .classList.remove('noVNC_hidden');
            document.getElementById('noVNC_toggle_extra_keys_button')
                .classList.remove('noVNC_hidden');
            document.getElementById('noVNC_clipboard_button')
                .classList.remove('noVNC_hidden');
        }
    },

    updateClipboard() {
        browserAsyncClipboardSupport()
            .then((support) => {
                if (support === 'unsupported') {
                    // Use fallback clipboard panel
                    return;
                }
                if (support === 'denied' || support === 'available') {
                    UI.closeClipboardPanel();
                    document.getElementById('noVNC_clipboard_button')
                        .classList.add('noVNC_hidden');
                    document.getElementById('noVNC_clipboard_button')
                        .removeEventListener('click', UI.toggleClipboardPanel);
                    document.getElementById('noVNC_clipboard_text')
                        .removeEventListener('change', UI.clipboardSend);
                    if (UI.rfb) {
                        UI.rfb.removeEventListener('clipboard', UI.clipboardReceive);
                    }
                }
            })
            .catch(() => {
                // Treat as unsupported
            });
    },

    updateShowDotCursor() {
        if (!UI.rfb) return;
        UI.rfb.showDotCursor = UI.getSetting('show_dot');
    },

    updateLogging() {
        WebUtil.initLogging(UI.getSetting('logging'));
    },

    updateDesktopName(e) {
        UI.desktopName = e.detail.name;
        // Display the desktop name in the document title
        document.title = e.detail.name + " - " + PAGE_TITLE;
    },

    updateRequestWakelock() {
        if (!UI.rfb) return;
        if (UI.getSetting('keep_device_awake')) {
            UI.wakeLockManager.acquire();
        } else {
            UI.wakeLockManager.release();
        }
    },


    bell(e) {
        if (UI.getSetting('bell') === 'on') {
            const promise = document.getElementById('noVNC_bell').play();
            // The standards disagree on the return value here
            if (promise) {
                promise.catch((e) => {
                    if (e.name === "NotAllowedError") {
                        // Ignore when the browser doesn't let us play audio.
                        // It is common that the browsers require audio to be
                        // initiated from a user action.
                    } else {
                        Log.Error("Unable to play bell: " + e);
                    }
                });
            }
        }
    },

    //Helper to add options to dropdown.
    addOption(selectbox, text, value) {
        const optn = document.createElement("OPTION");
        optn.text = text;
        optn.value = value;
        selectbox.options.add(optn);
    },

/* ------^-------
 *    /MISC
 * ==============
 */
};

export default UI;
