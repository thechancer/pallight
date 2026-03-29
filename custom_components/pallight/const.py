"""Constants for the PalLight integration — based on confirmed pcap analysis."""
# fmt: off
# ── File version ──────────────────────────────────────────────────────────────
__version__ = "0.9.0"
# Changelog:
#   0.9.0  Added INTEGRATION_VERSION, EFFECT_* constants, RESTORE_EFFECT*,
#          MSG_DISCOVERY_RESP, DISCOVERY_RETRY_SECS, corrected ATTR_EFFECT (0xA7)
#   0.8.0  Initial effect/mode support stubs
#   0.7.0  Transport handshake constants (CONNECT_TIMEOUT raised to 15s)
#   0.6.0  Config flow friendly-name and broadcast IP constants
#   0.5.0  Initial release
# ─────────────────────────────────────────────────────────────────────────────

INTEGRATION_VERSION = "1.0.0"   # Single source of truth — bump here only

DOMAIN = "pallight"

# ── Frontend / Lovelace card ──────────────────────────────────────────────────
# The card JS is served from inside custom_components/pallight/ via a static
# HTTP path registered in async_setup_entry. The version query string forces
# the browser to reload the card when the integration is updated.
# Frontend resource constants
URL_BASE      = "/pallight-frontend"
CARD_FILENAME = "pallight-card.js"
CARD_URL      = f"{URL_BASE}/{CARD_FILENAME}?v={INTEGRATION_VERSION}"
JSMODULES     = [
    {"name": "PalLight Card", "filename": CARD_FILENAME, "version": INTEGRATION_VERSION},
]

# ── Debug flag ────────────────────────────────────────────────────────────────
# Set to True to enable byte-level TX/RX packet logging at INFO level.
# These logs appear in the normal HA log without needing global debug mode.
# Flip back to False once the integration is working correctly.
PALLIGHT_DEBUG = False

# ── Network ───────────────────────────────────────────────────────────────────
# Confirmed from pcap: ALL communication is UDP port 5987, not TCP/48899/8899
UDP_PORT         = 5987
DISCOVERY_PORT   = 5987
DISCOVERY_MSG    = b"HF-A11ASSISTHREAD"   # kept for reference / fallback
DISCOVERY_TIMEOUT = 3.0

# Xlink local protocol port — confirmed from three pcaps
XLINK_PORT = 5987

# Timeouts
# CONNECT_TIMEOUT covers the full 0x13→0x18→0x23→0x28 cycle including retransmits.
# Pcap shows the device ignores the first 0x13 and only responds to the second,
# ~8 seconds after the first attempt. 15s gives two full retry cycles of headroom.
CONNECT_TIMEOUT       = 15.0  # seconds: total budget for handshake incl. 0x13 retransmits
ACK_TIMEOUT           = 2.0   # seconds to wait for 0x8B ack
DISCOVERY_RETRY_SECS  = 6.0   # seconds between 0x13 retransmit attempts (pcap: ~6-8s)
DRAIN_SECS            = 0.35  # kept for any remaining legacy uses

# ── Config entry keys ─────────────────────────────────────────────────────────
CONF_MANUAL_IP      = "manual_ip"
CONF_MANUAL_MAC     = "manual_mac"
CONF_DEVICE_ID      = "device_id"      # 32-char Xlink cloud device ID (from SZiRain app)
CONF_PASSWORD_HEX   = "password_hex"
CONF_SCAN_INTERVAL  = "scan_interval"
CONF_DEVICE_TYPE    = "device_type"
CONF_BROADCAST_IP   = "broadcast_ip"
CONF_FRIENDLY_NAME  = "friendly_name"
CONF_RESTORE_MODE   = "restore_mode"   # what state to apply when HA restarts

DEFAULT_PASSWORD_HEX  = "0000"
DEFAULT_SCAN_INTERVAL = 60
DEFAULT_BROADCAST_IP  = ""

# ── Restore mode choices ──────────────────────────────────────────────────────
# Shown as a radio button during setup and in options.
RESTORE_MODE_LAST    = "last"     # restore last known colour/effect (default)
RESTORE_MODE_DEFAULT = "default"  # always start at static cyan on HA restart

# ── Device types (from ControllerFragment.java) ───────────────────────────────
DEVICE_TYPE_TOUCH1   = "TOUCH-1"    # RGB colour wheel, your device
DEVICE_TYPE_PCT3D    = "PCT-3D"     # 3-ch direct RGB
DEVICE_TYPE_PCT3     = "PCT-3"      # 3-ch CCT warm/cool
DEVICE_TYPE_TOUCH9   = "TOUCH-9"    # 8-zone RGB
DEVICE_TYPE_TOUCH5   = "TOUCH-5"    # 5-ch RGBCCT
DEVICE_TYPE_REMOTE   = "REMOTE"     # 8-zone remote
DEVICE_TYPE_UNIVERSAL = "UNIVERSAL" # Pool lights (PAL/Pentair/Jandy/Hayward)

DEVICE_TYPE_CHOICES = [
    DEVICE_TYPE_TOUCH1,
    DEVICE_TYPE_PCT3D,
    DEVICE_TYPE_PCT3,
    DEVICE_TYPE_TOUCH9,
    DEVICE_TYPE_TOUCH5,
    DEVICE_TYPE_REMOTE,
]

# ── Xlink local protocol message types (confirmed from pcap) ──────────────────
MSG_DISCOVERY      = 0x13   # phone → 255.255.255.255:5987  (find device by MAC)
MSG_DISCOVERY_RESP = 0x18   # device → phone  (response to 0x13, signals device is ready)
MSG_CONNECT_REQ    = 0x23   # phone → device  (session open request)
MSG_CONNECT_RESP   = 0x28   # device → phone  (session accept, carries session token)
MSG_CONFIRM        = 0x33   # phone → device  (echo session token back)
MSG_PROBE_RESP     = 0x50   # device → phone  (handshake complete)
MSG_COMMAND        = 0x83   # phone → device  (control command)
MSG_ACK            = 0x8B   # device → phone  (ack, echoes sequence)
MSG_STATE_PUSH     = 0x80   # device → phone  (unsolicited state notification)
MSG_QUERY          = 0x83   # same type, attr=A3 = state query
# ── HF-A11 AT command interface (port 48899) ──────────────────────────────
# Used for diagnostics — WiFi signal strength query.
# Entirely independent of the Xlink session on port 5987.
AT_PORT           = 48899
AT_ENTER          = b'+ok'      # enter AT command mode (no \r needed — not an AT command)
AT_WIFI_SIGNAL    = b'AT+WSLQ\r'  # query WiFi signal level (\r required by HF module)
AT_EXIT           = b'AT+Q\r'     # exit AT command mode (\r required by HF module)
AT_TIMEOUT        = 3.0         # seconds to wait for response after AT+WSLQ
WIFI_SCAN_INTERVAL = 300        # seconds between WiFi signal polls (5 min)

MSG_KEEPALIVE      = 0xD3   # phone → device  (session keepalive ping, every ~30s)
MSG_KEEPALIVE_RESP = 0xD8   # device → phone  (keepalive pong, contains MAC)

# ── Attribute IDs ─────────────────────────────────────────────────────────────
ATTR_CONTROL = 0xA1   # all on/off/brightness/colour commands
ATTR_QUERY   = 0xA3   # query current state (value all zeros)
ATTR_STATE   = 0xA4   # state report from device (in 0x80 push)
ATTR_EFFECT  = 0xA7   # effect/mode selection — confirmed from pcap 19-Mar

# ── Command mode bytes (byte[14] in 0x83 payload) ─────────────────────────────
MODE_CONTROL = 0x01   # on/off/brightness
MODE_COLOUR  = 0x02   # colour wheel

# ── Action bytes (byte[15] when mode=MODE_CONTROL) ────────────────────────────
ACTION_ON           = 0x01
ACTION_OFF          = 0x02
ACTION_BRIGHT_UP    = 0x03
ACTION_BRIGHT_DOWN  = 0x04

# ── Effect (0xA7) frame constants ─────────────────────────────────────────────
# Confirmed from pcap 19-Mar: 0x83 frame with attr=0xA7
#   [10]=0xA7 [11]=0x00 [12]=0x00 [13]=0x10
#   [14]=0x00 [15]=0x00 [16]=0x00 [17]=0x04
#   [18]=effect_index [19]=speed_hi [20]=speed_lo
#   [21]=checksum
EFFECT_SUB_CMD     = 0x10   # byte[13] for 0xA7 frames (differs from 0xA1's 0x01)
EFFECT_FIXED_B17   = 0x04   # byte[17] always 0x04 in 0xA7 frames

# Effect speed range: 0x0000 (fastest) - 0xFFFF (slowest)
# Confirmed values from pcap: 0x3a2f, 0x3b00, 0x0000
# HA brightness (0-255) maps linearly: 255=fastest (0x0000), 0=slowest (0xFFFF)
EFFECT_SPEED_MIN     = 0x0000   # fastest
EFFECT_SPEED_MAX     = 0xFFFF   # slowest
EFFECT_SPEED_DEFAULT = 0x3B00   # mid-speed observed in pcap

# ── Built-in effect index table (from APK ModeFragment analysis) ──────────────
# Index values are the byte[18] values sent in the 0xA7 frame.
# Names match the app UI. Index 0x06 and 0x07 confirmed from pcap 19-Mar.
EFFECT_INDEX_STATIC         = 0x00   # static colour (no effect - use 0xA1 instead)
EFFECT_INDEX_GRADIENT       = 0x01   # slow colour gradient
EFFECT_INDEX_STROBE         = 0x02   # strobe flash
EFFECT_INDEX_JUMP           = 0x03   # colour jump
EFFECT_INDEX_FADE           = 0x04   # fade in/out
EFFECT_INDEX_FLASH          = 0x05   # colour flash sequence
EFFECT_INDEX_RAINBOW        = 0x06   # rainbow cycle  <- confirmed in pcap
EFFECT_INDEX_RAINBOW_STROBE = 0x07   # rainbow strobe <- confirmed in pcap

# Human-readable names exposed to HA as effect_list
EFFECT_NAMES: dict[str, int] = {
    "Gradient":       EFFECT_INDEX_GRADIENT,
    "Strobe":         EFFECT_INDEX_STROBE,
    "Jump":           EFFECT_INDEX_JUMP,
    "Fade":           EFFECT_INDEX_FADE,
    "Flash":          EFFECT_INDEX_FLASH,
    "Rainbow":        EFFECT_INDEX_RAINBOW,
    "Rainbow Strobe": EFFECT_INDEX_RAINBOW_STROBE,
}
# Reverse lookup: index -> name
EFFECT_INDEX_TO_NAME: dict[int, str] = {v: k for k, v in EFFECT_NAMES.items()}

# ── Fixed frame fields ────────────────────────────────────────────────────────
FRAME_INNER_LEN = 0x11   # always 17
FRAME_CMD_TYPE  = 0x00   # always 0x00 (SET)
FRAME_SUB_CMD   = 0x01   # always 0x01

# ── Restore keys ──────────────────────────────────────────────────────────────
RESTORE_IS_ON        = "is_on"
RESTORE_BRIGHTNESS   = "brightness"
RESTORE_HUE          = "hue"
RESTORE_EFFECT       = "effect"
RESTORE_EFFECT_SPEED = "effect_speed"
