# PalLight LED Controller

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://github.com/hacs/integration)
[![HA Version](https://img.shields.io/badge/Home%20Assistant-2024.1%2B-blue.svg)](https://www.home-assistant.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Local-control Home Assistant integration for **PalLighting** Wi-Fi LED controllers — tested with the **PCR-4**, and potential use with compatible devices using the HF-LPB100 / HF-A11 Wi-Fi module. This is an older driver, please raise an issue if your device doesn't work or isn't discovered.

No cloud. No vendor app. Full local control over UDP.

---

## Features

| Feature | Status |
|---|---|
| On / Off | ✅ |
| Colour wheel (full RGB spectrum) | ✅ |
| Streaming drag — smooth colour sweep matching native app | ✅ |
| Brightness step up / down | ✅ |
| Built-in effects (Fade, Strobe, Flash, and more) | ✅ |
| Effect speed control | ✅ |
| Wi-Fi signal strength sensor | ✅ |
| Custom Lovelace colour wheel card | ✅ |
| Auto-discovery on local network | ✅ |
| State restore on HA restart | ✅ |
| No cloud dependency | ✅ |

---

## Supported Devices

| Device | Tested | Notes |
|---|---|---|
| PalLighting PCR-4 | ✅ | Primary development device |
| 8CH | ⚠️ | Same protocol, untested |
| Any HF-LPB100 / HF-A11 based controller | ⚠️ | Protocol compatible |

The integration uses the **Xlink local UDP protocol** on port 5987, reverse-engineered from pcap captures of the native PalLighting Android app and a bit of app reverse engineering..

---

## Requirements

- Home Assistant 2024.1 or later
- Device and HA on the same local subnet (LAN/VLAN)
- Device IP either via DHCP reservation or static assignment (recommended)

---

## Installation

### Via HACS (recommended)

1. Open HACS → Integrations
2. Click the three-dot menu → **Custom repositories**
3. Add: `https://github.com/thechancer/pallight` — Category: **Integration**
4. Click **Download**
5. Restart Home Assistant

### Manual

1. Copy the `custom_components/pallight/` folder to your HA `config/custom_components/` directory
2. Restart Home Assistant

---

## Setup

1. Settings → Integrations → **Add Integration** → search **PalLight**
2. Choose **Auto-discover** or **Enter IP manually**
3. Give your light a friendly name (e.g. "Pool Light" → `light.pallight_pool_light`)
4. Select your controller type (TOUCH-1 for most users)
5. Select restore mode: **Last known colour** or **Default cyan on startup**

### Finding your device IP

If auto-discover doesn't find the device, check your router's DHCP table for a device named `HF-LPB100` and enter the IP manually.

---

## Lovelace Card

The integration includes a custom colour wheel card that mirrors the native app experience, including smooth streaming colour drag.

Add to your dashboard via YAML:

```yaml
type: custom:pallight-card
entity: light.pallight_pool_light
name: Pool Light
```

The card auto-registers — no manual resource entry needed.

### Card controls

| Control | Function |
|---|---|
| Colour wheel drag | Streams colour continuously while dragging |
| Colour wheel tap | Sets colour immediately on touch |
| ON / OFF buttons | Toggle light |
| BRIGHT UP / DOWN | Step brightness |

---

## Options

After setup, go to **Settings → Integrations → PalLight → Configure** to adjust:

| Option | Default | Description |
|---|---|---|
| Friendly name | (set at install) | Renames the entity |
| Scan interval | 60s | How often to verify connectivity |
| Interface IP | (auto) | Set if HA has multiple NICs on different subnets |
| Controller type | TOUCH-1 | Device type override |
| Restore mode | Last known | State on HA restart |

---

## Debug Logging

To enable verbose packet-level logging:

```yaml
# configuration.yaml
logger:
  default: warning
  logs:
    custom_components.pallight: debug
```

Alternatively, set `PALLIGHT_DEBUG = True` in `const.py` for byte-level TX/RX logging without needing a full HA debug mode.

---

## How It Works

The integration uses two protocols:

**Discovery** — UDP broadcast of `HF-A11ASSISTHREAD` to port 48899. The device responds with its IP, MAC, and model string.

**Control** — Xlink local UDP on port 5987. A 5-step handshake (0x13 → 0x23 → 0x28 → 0x33 → 0x50) establishes a session with a per-session token. All subsequent commands are 22-byte `0x83` frames carrying the token, a sequence number, and the command payload. The device acknowledges each command with a `0x8B` ACK.

During colour wheel drag, commands are streamed at ~50ms intervals without waiting for ACK (matching native app behaviour), with a final ACK-confirmed command on release.

---

## Known Limitations

- **Brightness is step-only** — the device has no absolute brightness command, only step up/down. The integration approximates HA brightness levels using step counts.
- **Single saturation level** — the device colour wheel operates at full saturation only. Sending any saturation value produces the same result as 100%.
- **No white/CCT mode** — whilst the remote can generate a white, I have only managed RGB so far...

---

## Troubleshooting

**Device not found during auto-discover**
- Confirm the device is on the same subnet as HA
- Check your router's DHCP table for `HF-LPB100`
- Try manual IP entry
- If HA has multiple network interfaces, set the Interface IP in Options to the IP of the NIC on the device's subnet

**Entity shows Unavailable**
- Check device is powered on and responding to the native app
- Check HA logs for handshake errors
- Try reloading the integration (Settings → Integrations → PalLight → Reload)

**Colours don't match the wheel position**
- The colour mapping was calibrated on a specific TOUCH-1 unit. If your device shows shifted colours, open an issue with photos of the device at HA hue values 0°, 40°, 80°, 120°, 160°, 200°, 240°, 280°, 320°.

**Commands work but ACK is REJECTED (0x01)**
- This indicates a session token mismatch. Reload the integration to re-handshake.

---

## Contributing

Pull requests welcome. For significant changes, open an issue first.

When reporting bugs, please include:
- HA version and integration version
- Device model and firmware (if known)
- Relevant log output with debug logging enabled
- pcap capture if the issue is protocol-related (PCAPdroid on Android works well)

---

## License

MIT — see [LICENSE](LICENSE)

---

## Credits

Protocol reverse-engineered from pcap captures of the PalLighting Android app (SZiRain / iRainxun). The Xlink SDK embedded in the app provided the credential bytes and frame structure. All implementation is original.
