"""
PalLight protocol — packet builders and parsers.

All structures confirmed from four pcap captures:
  PCAPdroid_16_Mar_21_17_05.pcap  — on/off, brightness (step)
  PCAPdroid_17_Mar_05_46_41.pcap  — colour wheel drag
  PCAPdroid_17_Mar_05_47_22.pcap  — brightness up/down, on/off
  PCAPdroid_19_Mar_06_58_33.pcap  — effects / mode / speed

═══════════════════════════════════════════════════════════
  0x83 COMMAND FRAME  (22 bytes, UDP port 5987)
═══════════════════════════════════════════════════════════
  [0]     0x83            msg_type
  [1-3]   00 00 00        reserved
  [4]     0x11            inner payload length (always 17)
  [5]     session_token_hi  byte[19] from 0x28 response
  [6]     session_token_lo  byte[20] from 0x28 response
  [7]     seq_hi          sequence number high byte
  [8]     seq_lo          sequence number low byte
  [9]     0x00            reserved
  --- attr=0xA1 (on/off/brightness/colour) ---
  [10]    0xA1            attr_id
  [11]    0x00            reserved
  [12]    0x00            reserved
  [13]    0x01            sub_cmd
  [14]    mode            0x01=control  0x02=colour
  [15]    action/hue[0]   control: 01=ON 02=OFF 03=BRT_UP 04=BRT_DN
                          colour: hue byte (0x00–0xFF)
  [16]    0x00/hue[1]     control: 0x00  colour: hue byte (same value)
  [17]    0x00/hue[2]     control: 0x00  colour: hue byte (same value)
  [18]    0x00/hue[3]     control: 0x00  colour: hue byte (same value)
  [19]    0x00            reserved
  [20]    0x00            reserved
  [21]    checksum        sum(bytes[10:21]) & 0xFF
  --- attr=0xA7 (effect selection + speed) ---
  [10]    0xA7            attr_id
  [11]    0x00            reserved
  [12]    0x00            reserved
  [13]    0x10            sub_cmd (0x10 for 0xA7, differs from 0xA1's 0x01)
  [14]    0x00            reserved
  [15]    0x00            reserved
  [16]    0x00            reserved
  [17]    0x04            fixed (always 0x04 in all 0xA7 frames)
  [18]    effect_index    0x01=Gradient 0x02=Strobe 0x03=Jump 0x04=Fade
                          0x05=Flash 0x06=Rainbow 0x07=Rainbow Strobe
  [19]    speed_hi        speed MSB (0x00=fastest, 0xFF=slowest)
  [20]    speed_lo        speed LSB
  [21]    checksum        sum(bytes[10:21]) & 0xFF

  Confirmed effect indices from pcap 19-Mar:
    0x06 (Rainbow) with speed=0x3A2F and 0x3B00
    0x07 (Rainbow Strobe) with speed=0x0000

Checksum confirmed: sum(bytes[10:21]) & 0xFF — covers only the
attribute payload, deliberately excludes the session token.
"""
# ── File version ──────────────────────────────────────────────────────────────
# Changelog:
#   0.9.0  build_confirm() fixed to 18 bytes (was 8), build_discovery_search()
#          (41-byte wildcard 0x13), build_discovery() fixed to 18 bytes (was 15),
#          cmd_set_effect(), ha_brightness_to_effect_speed(), ATTR_EFFECT frame
#   0.8.0  cmd_set_effect stubs
#   0.5.0  Initial release
# ─────────────────────────────────────────────────────────────────────────────


from __future__ import annotations

from .const import INTEGRATION_VERSION
__version__ = INTEGRATION_VERSION

import logging
import os
import struct

from .const import (
    ACTION_BRIGHT_DOWN,
    ACTION_BRIGHT_UP,
    ACTION_OFF,
    ACTION_ON,
    ATTR_CONTROL,
    ATTR_EFFECT,
    ATTR_QUERY,
    EFFECT_FIXED_B17,
    EFFECT_SPEED_MAX,
    EFFECT_SUB_CMD,
    FRAME_CMD_TYPE,
    FRAME_INNER_LEN,
    FRAME_SUB_CMD,
    MODE_COLOUR,
    MODE_CONTROL,
    MSG_ACK,
    MSG_COMMAND,
    MSG_CONFIRM,
    MSG_CONNECT_REQ,
    MSG_CONNECT_RESP,
    MSG_DISCOVERY,
    MSG_KEEPALIVE,
    MSG_PROBE_RESP,
    MSG_STATE_PUSH,
    XLINK_PORT,
)

_LOGGER = logging.getLogger(__name__)


# ── Checksum ──────────────────────────────────────────────────────────────────

def _checksum(frame: bytearray) -> int:
    """
    sum(frame[10:21]) & 0xFF

    Covers attr_id through last value byte.
    Confirmed across all 101 command packets in three pcaps.
    """
    return sum(frame[10:21]) & 0xFF


# ── Core command builder ──────────────────────────────────────────────────────

def build_command(
    session_token_hi: int,
    session_token_lo: int,
    sequence: int,
    mode: int,
    byte15: int,
    byte16: int = 0,
    byte17: int = 0,
    byte18: int = 0,
) -> bytes:
    """
    Build a 22-byte 0x83 command frame.

    session_token_hi: 0x28[19] → frame byte[5]
    session_token_lo: 0x28[20] → frame byte[6]  NOT always 0x00.
      Confirmed from pcap cross-reference:
        pcap1: [19]=0x43 [20]=0x00 → 0x83: byte[5]=0x43 byte[6]=0x00
        pcap3: [19]=0xAE [20]=0x03 → 0x83: byte[5]=0xAE byte[6]=0x03
        pcap4: [19]=0x22 [20]=0x00 → 0x83: byte[5]=0x22 byte[6]=0x00
      Device rejects commands (ACK result=0x01) if either byte is wrong.
    """
    frame = bytearray(22)
    frame[0]  = MSG_COMMAND
    frame[1]  = 0x00
    frame[2]  = 0x00
    frame[3]  = 0x00
    frame[4]  = FRAME_INNER_LEN
    frame[5]  = session_token_hi & 0xFF
    frame[6]  = session_token_lo & 0xFF
    frame[7]  = (sequence >> 8) & 0xFF
    frame[8]  = sequence & 0xFF
    frame[9]  = 0x00
    frame[10] = ATTR_CONTROL
    frame[11] = 0x00
    frame[12] = 0x00
    frame[13] = FRAME_SUB_CMD
    frame[14] = mode & 0xFF
    frame[15] = byte15 & 0xFF
    frame[16] = byte16 & 0xFF
    frame[17] = byte17 & 0xFF
    frame[18] = byte18 & 0xFF
    frame[19] = 0x00
    frame[20] = 0x00
    frame[21] = _checksum(frame)
    return bytes(frame)


# ── High-level command builders ───────────────────────────────────────────────

def cmd_on(token_hi: int, token_lo: int, sequence: int) -> bytes:
    """Turn the light on. attr=A1 mode=01 action=01."""
    return build_command(token_hi, token_lo, sequence, MODE_CONTROL, ACTION_ON)


def cmd_off(token_hi: int, token_lo: int, sequence: int) -> bytes:
    """Turn the light off. attr=A1 mode=01 action=02."""
    return build_command(token_hi, token_lo, sequence, MODE_CONTROL, ACTION_OFF)


def cmd_brightness_up(token_hi: int, token_lo: int, sequence: int) -> bytes:
    """Step brightness up. attr=A1 mode=01 action=03."""
    return build_command(token_hi, token_lo, sequence, MODE_CONTROL, ACTION_BRIGHT_UP)


def cmd_brightness_down(token_hi: int, token_lo: int, sequence: int) -> bytes:
    """Step brightness down. attr=A1 mode=01 action=04."""
    return build_command(token_hi, token_lo, sequence, MODE_CONTROL, ACTION_BRIGHT_DOWN)


def cmd_colour(token_hi: int, token_lo: int, sequence: int, hue_byte: int) -> bytes:
    """
    Set colour via hue wheel. hue_byte 0x00–0xFF sent in all 4 positions.
    Convert from HA hue (0.0–360.0°): hue_byte = round(ha_hue / 360.0 * 255)
    """
    h = hue_byte & 0xFF
    return build_command(token_hi, token_lo, sequence, MODE_COLOUR, h, h, h, h)


def cmd_query(token_hi: int, token_lo: int, sequence: int) -> bytes:
    """Query current state. attr=A3, all-zero value."""
    frame = bytearray(22)
    frame[0]  = MSG_COMMAND
    frame[4]  = FRAME_INNER_LEN
    frame[5]  = token_hi & 0xFF
    frame[6]  = token_lo & 0xFF
    frame[7]  = (sequence >> 8) & 0xFF
    frame[8]  = sequence & 0xFF
    frame[10] = ATTR_QUERY
    frame[21] = _checksum(frame)
    return bytes(frame)


def cmd_set_effect(
    token_hi: int,
    token_lo: int,
    sequence: int,
    effect_index: int,
    speed: int = 0x3B00,
) -> bytes:
    """
    Select a built-in effect (0xA7 frame).

    Confirmed layout from pcap 19-Mar:
      [10]=0xA7 [11]=0x00 [12]=0x00 [13]=0x10
      [14]=0x00 [15]=0x00 [16]=0x00 [17]=0x04
      [18]=effect_index [19]=speed_hi [20]=speed_lo
      [21]=checksum

    effect_index: use EFFECT_INDEX_* constants from const.py
    speed: 0x0000=fastest, 0xFFFF=slowest; default 0x3B00 (mid, from pcap)
    """
    frame = bytearray(22)
    frame[0]  = MSG_COMMAND
    frame[1]  = 0x00
    frame[2]  = 0x00
    frame[3]  = 0x00
    frame[4]  = FRAME_INNER_LEN
    frame[5]  = token_hi & 0xFF
    frame[6]  = token_lo & 0xFF
    frame[7]  = (sequence >> 8) & 0xFF
    frame[8]  = sequence & 0xFF
    frame[9]  = 0x00
    frame[10] = ATTR_EFFECT        # 0xA7
    frame[11] = 0x00
    frame[12] = 0x00
    frame[13] = EFFECT_SUB_CMD     # 0x10
    frame[14] = 0x00
    frame[15] = 0x00
    frame[16] = 0x00
    frame[17] = EFFECT_FIXED_B17   # 0x04
    frame[18] = effect_index & 0xFF
    frame[19] = (speed >> 8) & 0xFF
    frame[20] = speed & 0xFF
    frame[21] = _checksum(frame)
    return bytes(frame)


def cmd_set_effect_speed(
    token_hi: int,
    token_lo: int,
    sequence: int,
    effect_index: int,
    speed: int,
) -> bytes:
    """
    Update the speed of the currently running effect.

    This is the same 0xA7 frame as cmd_set_effect — the device uses the
    effect_index to know which effect to apply the new speed to.
    Confirmed from pcap: app sends 0xA7 with same index + new speed when
    the speed slider is dragged, then follows with a 0xA1 mode=01 speed byte.

    speed: ha_brightness_to_effect_speed() converts HA brightness (0-255)
           to the device speed range (0x0000-0xFFFF).
    """
    return cmd_set_effect(token_hi, token_lo, sequence, effect_index, speed)


def ha_brightness_to_effect_speed(brightness: int) -> int:
    """
    Convert HA brightness (0-255) to device effect speed (0x0000-0xFFFF).

    Device speed is inverted: low value = fast, high value = slow.
    HA brightness: 255=brightest maps to fastest (0x0000)
                     0=darkest  maps to slowest  (0xFFFF)
    """
    b = max(0, min(255, brightness))
    return round((255 - b) / 255 * 0xFFFF) & 0xFFFF


def effect_speed_to_ha_brightness(speed: int) -> int:
    """Inverse of ha_brightness_to_effect_speed."""
    s = max(0, min(0xFFFF, speed))
    return round((1.0 - s / 0xFFFF) * 255) & 0xFF


# Lookup table: HA hue (0–359°) → canvas degree used by the colour wheel card.
# Derived from HUE_TO_CANVAS in pallight-card.js — same table ensures the
# handle position and the sent device byte always agree visually.
_HA_HUE_TO_DEVICE: list[int] = [
    173,172,171,170,170,169,168,167,166,165,164,164,163,162,161,160,159,159,
    158,157,156,155,154,153,153,152,151,150,149,148,148,147,146,145,144,143,
    142,142,141,140,139,138,137,136,136,135,134,133,132,131,130,130,129,128,
    127,126,125,125,124,123,122,121,120,119,119,118,117,116,115,114,114,113,
    112,111,110,109,108,108,107,106,105,104,103,102,102,101,100,99,98,97,
    96,95,94,94,93,92,91,90,89,88,88,87,86,85,84,83,82,81,
    80,80,79,78,77,76,75,74,74,73,72,71,70,68,67,65,63,62,
    60,58,57,55,53,52,50,48,47,45,43,42,40,38,36,35,33,31,
    30,28,26,25,23,21,20,18,16,15,13,11,10,8,6,5,3,3,
    2,2,1,1,0,0,0,255,255,254,254,253,253,253,252,252,251,251,
    250,250,250,249,249,248,248,248,247,247,246,246,245,245,245,244,244,243,
    243,242,242,242,241,241,240,240,239,239,239,238,238,237,237,236,236,236,
    235,235,234,234,234,233,233,232,232,231,231,231,230,230,229,229,228,228,
    228,227,227,226,226,225,225,225,224,224,223,223,222,222,222,221,221,220,
    220,219,219,219,218,218,217,217,216,216,216,215,215,214,214,214,213,213,
    212,212,211,211,211,210,210,209,209,208,208,208,207,207,206,206,205,205,
    205,204,204,203,203,202,202,202,201,201,200,200,200,199,199,198,198,197,
    197,197,196,196,195,195,194,194,194,193,193,192,192,191,191,191,190,190,
    189,189,188,188,187,187,186,186,186,185,185,184,184,183,183,182,182,182,
    181,181,180,180,179,179,178,178,178,177,177,176,176,175,175,174,174,173,
]


def ha_hue_to_device(ha_hue: float) -> int:
    """
    Colour mapping problems persist. Redid full clock, degrees, mapping to hue, hex and RGB.
    AI analysis of colours based off screengrab from app. Converted to colour match.
    
    Convert HA hue (0.0–360.0°) to device wheel byte (0x00–0xFF).

    Uses the same HUE_TO_CANVAS lookup table as the Lovelace card so the
    handle position and the actual device colour always agree.

    Formula: direct lookup — _HA_HUE_TO_DEVICE[ha_hue]

    Calibrated from 9-point physical device observations (March 2026):
      HA   0° → dev 0xAD → RED
      HA  40° → dev 0x8B → YELLOW
      HA  80° → dev 0x69 → GREEN
      HA 120° → dev 0x46 → CYAN/TEAL
      HA 160° → dev 0x03 → BLUE
      HA 200° → dev 0xF2 → BLUE-PURPLE
      HA 240° → dev 0xE1 → PURPLE/VIOLET
      HA 280° → dev 0xD0 → PURPLE
      HA 320° → dev 0xBF → PINK/MAGENTA

    Validated colour wheel — half-hour clock positions (clockwise from 12):
      12:00   HA 240.0°  0xE1  BLUE/PURPLE
      12:30   HA 220.0°  0xEC  PURPLE
       1:00   HA 200.0°  0xF2  BLUE-PURPLE
       1:30   HA 180.0°  0xFA  CYAN/TEAL transition
       2:00   HA 160.0°  0x03  BLUE
       2:30   HA 140.0°  0x1D  BLUE transition
       3:00   HA 120.0°  0x46  CYAN/TEAL
       3:30   HA 110.0°  0x58  CYAN-GREEN
       4:00   HA 100.0°  0x69  GREEN
       4:30   HA  90.0°  0x74  LIME-GREEN
       5:00   HA  80.0°  0x80  YELLOW-GREEN
       5:30   HA  70.0°  0x85  YELLOW-GREEN
       6:00   HA  60.0°  0x8B  YELLOW
       6:30   HA  50.0°  0x91  AMBER
       7:00   HA  40.0°  0x96  ORANGE
       7:30   HA  30.0°  0x9C  ORANGE-RED
       8:00   HA  20.0°  0xA2  RED-ORANGE
       8:30   HA  10.0°  0xA7  RED-ORANGE
       9:00   HA   0.0°  0xAD  RED
       9:30   HA 340.0°  0xB3  RED-PINK
      10:00   HA 320.0°  0xBF  PINK/MAGENTA
      10:30   HA 300.0°  0xC8  MAGENTA transition
      11:00   HA 280.0°  0xD0  PURPLE
      11:30   HA 260.0°  0xD9  PURPLE/VIOLET

    Calibrated from device observations (March 2026) and validated
    against the PAL_R/G/B colour tables in pallight-card.js.

    Validated colour wheel — half-hour clock positions (clockwise from 12):
      12:00   HA 240.0°  0xE1  BLUE            RGB(  0,  0,255)
      12:30   HA 220.0°  0xEA  AZURE           RGB(  0, 85,255)
       1:00   HA 200.0°  0xF2  AZURE           RGB(  0,170,255)
       1:30   HA 180.0°  0xFB  CYAN            RGB(  0,255,255)
       2:00   HA 160.0°  0x03  SEAFOAM         RGB(  0,255,176)
       2:30   HA 140.0°  0x0C  SPRING GREEN    RGB(  0,255, 85)
       3:00   HA 120.0°  0x46  GREEN           RGB(  0,255,  0)
       3:30   HA 110.0°  0x4E  LIME            RGB( 42,255,  0)
       4:00   HA 100.0°  0x57  LIME            RGB( 85,255,  0)
       4:30   HA  90.0°  0x60  LIME            RGB(121,255,  0)
       5:00   HA  80.0°  0x69  LIME            RGB(163,255,  0)
       5:30   HA  70.0°  0x70  YELLOW-GREEN    RGB(212,255,  0)
       6:00   HA  60.0°  0x7A  YELLOW          RGB(255,255,  0)
       6:30   HA  50.0°  0x82  AMBER           RGB(255,212,  0)
       7:00   HA  40.0°  0x8B  ORANGE          RGB(255,170,  0)
       7:30   HA  30.0°  0x94  ORANGE          RGB(255,127,  0)
       8:00   HA  20.0°  0x9C  DEEP ORANGE     RGB(255, 85,  0)
       8:30   HA  10.0°  0xA5  RED-ORANGE      RGB(255, 42,  0)
       9:00   HA   0.0°  0xAD  RED             RGB(255,  0,  0)
       9:30   HA 340.0°  0xB6  HOT PINK        RGB(255,  0, 85)
      10:00   HA 320.0°  0xBF  HOT PINK        RGB(255,  0,170)
      10:30   HA 300.0°  0xC7  MAGENTA         RGB(255,  0,255)
      11:00   HA 280.0°  0xD0  PURPLE          RGB(170,  0,255)
      11:30   HA 260.0°  0xD9  BLUE-PURPLE     RGB( 84,  0,255)
    """
    return _HA_HUE_TO_DEVICE[int(ha_hue) % 360]


# Lookup table: device byte (0x00–0xFF) → HA hue (0–359°).
# Exact inverse of _HA_HUE_TO_CANVAS + ha_hue_to_device formula.
# Generated from the forward mapping — ensures perfect round-trip consistency.
_DEVICE_TO_HA_HUE: list[int] = [
    166,164,162,160,160,159,158,158,157,156,156,155,154,154,154,153,
    152,152,151,150,150,149,148,148,148,147,146,146,145,144,144,143,
    142,142,142,141,140,140,139,138,138,138,137,136,136,135,134,134,
    133,132,132,132,131,130,130,129,128,128,127,126,126,126,125,124,
    124,123,122,122,121,120,120,119,118,117,115,114,113,112,111,110,
    108,107,106,105,104,103,102,101,99,98,97,96,95,94,92,91,
    90,89,88,87,86,85,83,82,81,80,79,78,76,75,74,73,
    72,71,69,68,67,66,65,63,62,61,60,59,58,56,55,54,
    53,52,50,49,48,47,46,45,43,42,41,40,39,38,36,35,
    34,33,32,31,29,28,27,26,25,23,22,21,20,19,18,16,
    15,14,13,12,10,9,8,7,6,5,3,2,1,0,357,355,
    353,351,348,346,344,342,339,337,335,333,330,328,326,324,322,319,
    317,315,312,310,308,305,303,301,298,296,293,291,289,286,284,282,
    279,277,275,272,270,268,265,263,260,258,256,253,251,249,246,244,
    242,239,237,235,232,230,228,225,223,221,218,216,213,211,209,206,
    204,202,199,197,195,192,190,188,185,183,180,178,176,173,171,169,
]


def device_hue_to_ha(hue_byte: int) -> float:
    """
    Convert device wheel byte (0x00–0xFF) back to HA hue degrees.

    Uses _DEVICE_TO_HA_HUE lookup table — the exact inverse of ha_hue_to_device.
    Ensures the card handle position is always consistent with the sent byte.

    Key reverse mappings:
      0xAD →   0° (RED)
      0x7A →  60° (YELLOW)
      0x46 → 120° (GREEN)
      0xFB → 180° (CYAN)
      0xE1 → 240° (BLUE)
      0xC7 → 300° (MAGENTA)
    """
    return float(_DEVICE_TO_HA_HUE[hue_byte & 0xFF])


# ── Handshake frame builders ──────────────────────────────────────────────────

def build_discovery(target_mac_bytes: bytes) -> bytes:
    """
    Build a 0x13 discovery broadcast frame.

    Confirmed from Wireshark capture (selected_packets.pcap):
      18 bytes total — NOT 15 as previously assumed from PCAPdroid.
      PCAPdroid's VPN layer was truncating or mangling the frame.

      [0]     0x13
      [1-3]   00 00 00
      [4]     0x0A  (inner len = 10, covers bytes [5:15])
      [5]     0x03
      [6-7]   nonce (2 random bytes, echoed in 0x23)
      [8]     0x11
      [9-14]  target device MAC (6 bytes) — MUST be real MAC, not zeros
              Device ignores 0x13 frames with zero MAC.
      [15-17] 00 00 00  (padding — device validates total frame length)

    target_mac_bytes: 6-byte MAC, e.g. bytes.fromhex("98D863E3CF80")
    """
    nonce = os.urandom(2)
    frame = bytearray(18)
    frame[0]  = MSG_DISCOVERY
    frame[1]  = 0x00
    frame[2]  = 0x00
    frame[3]  = 0x00
    frame[4]  = 0x0A
    frame[5]  = 0x03
    frame[6]  = nonce[0]
    frame[7]  = nonce[1]
    frame[8]  = 0x11
    frame[9:15] = target_mac_bytes[:6]
    frame[15] = 0x00
    frame[16] = 0x00
    frame[17] = 0x00
    return bytes(frame), nonce


def build_connect_request(nonce: bytes) -> bytes:
    """
    Build a 0x23 connect request.

    Confirmed layout (27 bytes) from four pcap captures:
      [0]    0x23
      [1-3]  00 00 00
      [4]    0x16  (inner len = 22)
      [5]    0x02  (protocol version, fixed)
      [6-21] FIXED 16-byte device credential (same across all sessions)
             623AD5EDA301AE082D466141A7F6DCAF
             This is NOT random — it is a fixed app/device credential
             embedded in the Xlink SDK. Sending random bytes causes the
             device to silently ignore the 0x23 and never send 0x28.
      [22-23] nonce from 0x13 (echoed back, 2 bytes, changes per session)
      [24]   0x00
      [25]   0x00
      [26]   0x64  (100 — session TTL hint, fixed)
    """
    # Fixed credential confirmed identical across all four pcap sessions
    DEVICE_CREDENTIAL = bytes.fromhex("623AD5EDA301AE082D466141A7F6DCAF")

    frame = bytearray(27)
    frame[0]  = MSG_CONNECT_REQ
    frame[1]  = 0x00
    frame[2]  = 0x00
    frame[3]  = 0x00
    frame[4]  = 0x16
    frame[5]  = 0x02
    frame[6:22] = DEVICE_CREDENTIAL
    frame[22] = nonce[0]
    frame[23] = nonce[1]
    frame[24] = 0x00
    frame[25] = 0x00
    frame[26] = 0x64
    return bytes(frame)


def build_confirm(token_hi: int, token_lo: int = 0x00) -> bytes:
    """
    Build a 0x33 confirm frame.

    Confirmed from pcap initial_setup: 18 bytes (was wrongly 8).
      [0]    0x33
      [1-3]  00 00 00
      [4]    0x03  inner_len
      [5]    token_hi  (session_token_hi from 0x28[19])
      [6]    token_lo  (session_token_lo from 0x28[20] — NOT always 0x00)
      [7-17] 00 * 11  (trailing zero bytes)
    """
    frame = bytearray(18)
    frame[0] = MSG_CONFIRM
    frame[4] = 0x03
    frame[5] = token_hi & 0xFF
    frame[6] = token_lo & 0xFF
    # [7-17] already zero
    return bytes(frame)


def build_keepalive(token_hi: int, token_lo: int) -> bytes:
    """
    Build a 0xD3 keepalive ping frame.

    Confirmed from pcap (pkt#34): D3 00 00 00 02 [token_hi] [token_lo]
    Device responds with 0xD8 containing MAC.

    Equivalent to LimitlessLED 0xD0 keepalive (opcode offset +3).
    Must be sent periodically to keep the session alive — the device
    drops unresponsive sessions after ~30s.
    """
    frame = bytearray(7)
    frame[0] = MSG_KEEPALIVE
    frame[1] = 0x00
    frame[2] = 0x00
    frame[3] = 0x00
    frame[4] = 0x02
    frame[5] = token_hi & 0xFF
    frame[6] = token_lo & 0xFF
    return bytes(frame)


def build_discovery_search(device_id: bytes | None = None) -> tuple[bytes, bytes]:
    """
    Build a 41-byte 0x13 search-by-device-ID frame for initial discovery.

    Confirmed from pcap initial_setup: the app sends this FIRST before the
    18-byte targeted 0x13. The device responds with a 0x18 containing its
    MAC, which the app then uses in the subsequent 18-byte 0x13.

    Layout (41 bytes):
      [0]    0x13
      [1-3]  00 00 00
      [4]    0x24  (inner_len = 36)
      [5]    0x03
      [6-7]  nonce (2 random bytes)
      [8]    0x02  (differs from 18-byte version's 0x11)
      [9-40] 32-byte device ID (ASCII hex string from Xlink cloud)
             Send 32 zero bytes for wildcard discovery (find any device).

    device_id: 32-byte ASCII device ID, or None for wildcard (zeros).
    Returns (frame, nonce).
    """
    nonce = os.urandom(2)
    frame = bytearray(41)
    frame[0] = MSG_DISCOVERY
    frame[1] = 0x00
    frame[2] = 0x00
    frame[3] = 0x00
    frame[4] = 0x24
    frame[5] = 0x03
    frame[6] = nonce[0]
    frame[7] = nonce[1]
    frame[8] = 0x02
    if device_id and len(device_id) >= 32:
        frame[9:41] = device_id[:32]
    # else: bytes 9-40 remain zero (wildcard)
    return bytes(frame), nonce


# ── Inbound frame parsers ─────────────────────────────────────────────────────

def parse_connect_response(data: bytes) -> dict | None:
    """
    Parse a 0x28 connect response.

    Returns dict with:
      mac:              "XX:XX:XX:XX:XX:XX"
      response_code:    int
      session_token_hi: int  — 0x28[19], byte[5] of every 0x83
      session_token_lo: int  — 0x28[20], byte[6] of every 0x83
                               (NOT always 0x00 — confirmed from pcap3: 0x03)

    Confirmed layout (22 bytes):
      [0]    0x28
      [1-3]  00 00 00
      [4]    0x11  inner_len=17
      [5]    response_code_hi
      [6]    response_code_lo
      [7-12] device MAC (6 bytes)
      [13-18] session data
      [19]   session_token_hi  ← byte[5] of 0x83
      [20]   session_token_lo  ← byte[6] of 0x83 (was wrongly hardcoded 0x00)
      [21]   0x00
    """
    if len(data) < 22 or data[0] != MSG_CONNECT_RESP:
        return None
    response_code = (data[5] << 8) | data[6]
    mac = ":".join(f"{b:02X}" for b in data[7:13])
    return {
        "response_code":    response_code,
        "mac":              mac,
        "session_token_hi": data[19],
        "session_token_lo": data[20],
        # Keep backward-compat alias
        "capability_byte":  data[19],
    }


def parse_probe_response(data: bytes) -> dict | None:
    """
    Parse a 0x50 probe response (handshake complete signal).

    Returns dict with mac and device_info byte, or None.

    Confirmed layout (12 bytes):
      [0]    0x50
      [1-3]  00 00 00
      [4]    0x07
      [5-10] device MAC
      [11]   device_info (0x0E observed — firmware/type?)
    """
    if len(data) < 12 or data[0] != MSG_PROBE_RESP:
        return None
    mac = ":".join(f"{b:02X}" for b in data[5:11])
    return {
        "mac": mac,
        "device_info": data[11],
    }


def parse_ack(data: bytes) -> tuple[int, int] | None:
    """
    Parse a 0x8B ACK frame.

    Returns (sequence, result) or None if not a valid 0x8B frame.
      sequence: 16-bit sequence number being acknowledged
      result:   0x00 = command accepted/executed
                0x01 = command rejected (auth failure / bad session state)

    Confirmed layout (8 bytes):
      [0]    0x8B
      [1-3]  00 00 00
      [4]    0x03
      [5]    seq_hi
      [6]    seq_lo
      [7]    result  (0x00=OK, 0x01=REJECTED)
    """
    if len(data) < 8 or data[0] != MSG_ACK:
        return None
    return (data[5] << 8) | data[6], data[7]


def parse_state_push(data: bytes) -> dict | None:
    """
    Parse a 0x80 unsolicited state push from device.

    Confirmed layout (26 bytes):
      [0]    0x80
      [1-3]  00 00 00
      [4]    0x15  (inner len = 21)
      [5-10] device MAC
      [11]   0x05
      [12]   0x02
      [13]   0x00
      [14]   attr_id (0xA4 = state, 0xA7 = systime)
      [15-24] attr value (10 bytes)
      [25]   checksum

    For attr=A4: value[2] = current brightness byte
    """
    if len(data) < 26 or data[0] != MSG_STATE_PUSH:
        return None
    mac = ":".join(f"{b:02X}" for b in data[5:11])
    attr_id = data[14]
    value = data[15:25]
    return {
        "mac": mac,
        "attr_id": attr_id,
        "value": bytes(value),
        "brightness_raw": value[2] if len(value) > 2 else None,
    }


def mac_str_to_bytes(mac: str) -> bytes:
    """Convert 'XX:XX:XX:XX:XX:XX' or 'XXXXXXXXXXXX' to 6 bytes."""
    clean = mac.replace(":", "").replace("-", "").upper()
    if len(clean) != 12:
        raise ValueError(f"Invalid MAC: {mac!r}")
    return bytes.fromhex(clean)
