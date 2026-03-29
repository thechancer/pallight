"""PalLight coordinator — manages Xlink UDP sessions per device."""
# ── File version ──────────────────────────────────────────────────────────────
# Changelog:
#   0.9.0  set_effect(), set_effect_speed(), DeviceEntry.effect/effect_speed
#   0.8.0  brightness_up/down, set_colour
#   0.5.0  Initial release
# ─────────────────────────────────────────────────────────────────────────────


from __future__ import annotations

from .const import INTEGRATION_VERSION
__version__ = INTEGRATION_VERSION

import logging
from datetime import timedelta
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import (
    CONF_BROADCAST_IP,
    CONF_DEVICE_TYPE,
    CONF_FRIENDLY_NAME,
    CONF_MANUAL_IP,
    CONF_MANUAL_MAC,
    CONF_PASSWORD_HEX,
    CONF_SCAN_INTERVAL,
    DEFAULT_BROADCAST_IP,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_PASSWORD_HEX,
    DEVICE_TYPE_TOUCH1,
    DOMAIN,
    EFFECT_NAMES,
    PALLIGHT_DEBUG,
)
from .protocol import (
    cmd_brightness_down,
    cmd_brightness_up,
    cmd_colour,
    cmd_off,
    cmd_on,
    cmd_set_effect,
    ha_brightness_to_effect_speed,
    ha_hue_to_device,
)
from .transport import XlinkSession, discover_devices

_LOGGER = logging.getLogger(__name__)


def _dlog(msg: str) -> None:
    """Log at INFO when PALLIGHT_DEBUG is on."""
    if PALLIGHT_DEBUG:
        _LOGGER.info("PalLight coordinator: %s", msg)


class DeviceEntry:
    """Runtime state for one PalLight device."""

    def __init__(self, mac: str, ip: str, device_type: str) -> None:
        self.mac         = mac
        self.ip          = ip
        self.device_type = device_type
        self.available   = False
        self.is_on       = False
        self.brightness  = 255
        self.hue: float  = 0.0
        self.effect: str | None = None          # current effect name, or None for static
        self.effect_speed: int  = 0x3B00        # device speed value (0x0000=fast, 0xFFFF=slow)
        self.session: XlinkSession | None = None


class PalLightCoordinator(DataUpdateCoordinator[dict[str, DeviceEntry]]):
    """Coordinator for PalLight LED controllers."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.entry   = entry
        self._devices: dict[str, DeviceEntry] = {}

        scan_interval = entry.data.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=scan_interval),
        )

    # ── Poll ──────────────────────────────────────────────────────────────────

    async def _async_update_data(self) -> dict[str, DeviceEntry]:
        manual_ip  = self.entry.data.get(CONF_MANUAL_IP, "").strip()
        manual_mac = self.entry.data.get(CONF_MANUAL_MAC, "").strip().upper()

        if manual_ip and manual_mac:
            _dlog(f"poll: manual device {manual_mac} at {manual_ip}")
            await self._ensure_device(manual_mac, manual_ip)
        else:
            bind_ip = self.entry.data.get(CONF_BROADCAST_IP, DEFAULT_BROADCAST_IP).strip()
            _dlog(f"poll: running UDP discovery (bind_ip={bind_ip!r})")
            try:
                found = await discover_devices(bind_ip=bind_ip)
            except Exception as exc:
                raise UpdateFailed(f"Discovery failed: {exc}") from exc
            for dev in found:
                await self._ensure_device(dev["mac"], dev["ip"])

        available_count = sum(1 for d in self._devices.values() if d.available)
        _LOGGER.info(
            "PalLight poll: %d/%d device(s) available",
            available_count, len(self._devices),
        )
        return dict(self._devices)

    async def _ensure_device(self, mac: str, ip: str) -> None:
        if mac not in self._devices:
            device_type = self.entry.data.get(CONF_DEVICE_TYPE, DEVICE_TYPE_TOUCH1)
            entry = DeviceEntry(mac=mac, ip=ip, device_type=device_type)
            self._devices[mac] = entry
            _LOGGER.info(
                "PalLight: registered device MAC=%s IP=%s type=%s", mac, ip, device_type
            )

        entry = self._devices[mac]

        if entry.ip != ip:
            _LOGGER.info(
                "PalLight: device %s IP changed %s → %s", mac, entry.ip, ip
            )
            entry.ip = ip
            if entry.session:
                await entry.session.disconnect()
                entry.session = None

        if entry.session is None or not entry.session.available:
            _dlog(f"device {mac} needs (re)connect — session={entry.session} "
                  f"available={entry.session.available if entry.session else 'n/a'}")
            await self._connect_device(entry)

    async def _connect_device(self, entry: DeviceEntry) -> None:
        if entry.session:
            await entry.session.disconnect()

        session = XlinkSession(
            device_ip=entry.ip,
            device_mac=entry.mac,
            on_state_push=lambda state: self._on_state_push(entry.mac, state),
            on_availability_changed=lambda avail: self._on_availability_changed(entry.mac, avail),
        )
        entry.session = session
        # Always skip 0x13/0x18 — IP and MAC are known from config entry,
        # and the device ignores 0x13 when already in an active session.
        success = await session.connect()
        if not success:
            _LOGGER.warning(
                "PalLight: failed to connect to %s (%s) — will retry next poll",
                entry.mac, entry.ip,
            )

    def _on_availability_changed(self, mac: str, available: bool) -> None:
        entry = self._devices.get(mac)
        if entry:
            entry.available = available
            self.async_set_updated_data(dict(self._devices))

    def _on_state_push(self, mac: str, state: dict) -> None:
        entry = self._devices.get(mac)
        if not entry:
            return
        # 0xA7 is ATTR_SYSTIME — a 60s clock heartbeat from the device.
        # It carries no useful state; ignore it to avoid spurious coordinator
        # updates and unwanted restore-state triggers in the light entity.
        if state.get("attr_id") == 0xA7:
            _dlog(f"ignoring 0xA7 SysTime push for {mac}")
            return
        _dlog(f"state push for {mac}: {state}")
        if state.get("brightness_raw") is not None:
            entry.brightness = state["brightness_raw"]
        self.async_set_updated_data(dict(self._devices))

    # ── Command dispatch ──────────────────────────────────────────────────────

    async def turn_on(self, mac: str) -> bool:
        entry = self._devices.get(mac)
        if not entry or not entry.session:
            _LOGGER.warning(
                "PalLight turn_on(%s): no session (entry=%s)", mac, entry is not None
            )
            return False
        if not entry.session.available:
            _LOGGER.warning(
                "PalLight turn_on(%s): session not available", mac
            )
            return False
        seq   = entry.session.next_sequence()
        token_hi = entry.session.session_token_hi
        token_lo = entry.session.session_token_lo
        _dlog(f"turn_on({mac}) token=[0x{token_hi:02X},0x{token_lo:02X}] seq=0x{seq:04X}")
        result = await entry.session.send_command(cmd_on(token_hi, token_lo, seq), label="turn_on")
        if result:
            entry.is_on = True
        else:
            _LOGGER.warning("PalLight turn_on(%s): send_command returned False", mac)
        return result

    async def turn_off(self, mac: str) -> bool:
        entry = self._devices.get(mac)
        if not entry or not entry.session:
            _LOGGER.warning(
                "PalLight turn_off(%s): no session (entry=%s)", mac, entry is not None
            )
            return False
        if not entry.session.available:
            _LOGGER.warning(
                "PalLight turn_off(%s): session not available", mac
            )
            return False
        seq   = entry.session.next_sequence()
        token_hi = entry.session.session_token_hi
        token_lo = entry.session.session_token_lo
        _dlog(f"turn_off({mac}) token=[0x{token_hi:02X},0x{token_lo:02X}] seq=0x{seq:04X}")
        result = await entry.session.send_command(cmd_off(token_hi, token_lo, seq), label="turn_off")
        if result:
            entry.is_on = False
        else:
            _LOGGER.warning("PalLight turn_off(%s): send_command returned False", mac)
        return result

    async def brightness_up(self, mac: str) -> bool:
        entry = self._devices.get(mac)
        if not entry or not entry.session or not entry.session.available:
            _LOGGER.warning("PalLight brightness_up(%s): no available session", mac)
            return False
        seq   = entry.session.next_sequence()
        token_hi = entry.session.session_token_hi
        token_lo = entry.session.session_token_lo
        _dlog(f"brightness_up({mac}) token=[0x{token_hi:02X},0x{token_lo:02X}] seq=0x{seq:04X}")
        result = await entry.session.send_command(
            cmd_brightness_up(token_hi, token_lo, seq), label="brightness_up"
        )
        if result:
            entry.brightness = min(255, entry.brightness + 16)
        return result

    async def brightness_down(self, mac: str) -> bool:
        entry = self._devices.get(mac)
        if not entry or not entry.session or not entry.session.available:
            _LOGGER.warning("PalLight brightness_down(%s): no available session", mac)
            return False
        seq   = entry.session.next_sequence()
        token_hi = entry.session.session_token_hi
        token_lo = entry.session.session_token_lo
        _dlog(f"brightness_down({mac}) token=[0x{token_hi:02X},0x{token_lo:02X}] seq=0x{seq:04X}")
        result = await entry.session.send_command(
            cmd_brightness_down(token_hi, token_lo, seq), label="brightness_down"
        )
        if result:
            entry.brightness = max(0, entry.brightness - 16)
        return result

    async def set_colour(self, mac: str, hue: float) -> bool:
        entry = self._devices.get(mac)
        if not entry or not entry.session or not entry.session.available:
            _LOGGER.warning("PalLight set_colour(%s): no available session", mac)
            return False
        hue_byte = ha_hue_to_device(hue)
        seq      = entry.session.next_sequence()
        token_hi = entry.session.session_token_hi
        token_lo = entry.session.session_token_lo
        _dlog(
            f"set_colour({mac}) hue={hue:.1f}° → hue_byte=0x{hue_byte:02X} "
            f"token=[0x{token_hi:02X},0x{token_lo:02X}] seq=0x{seq:04X}"
        )
        result = await entry.session.send_command(
            cmd_colour(token_hi, token_lo, seq, hue_byte), label="set_colour"
        )
        if result:
            entry.hue = hue
            entry.effect = None   # leaving effect mode when colour is set directly
        else:
            _LOGGER.warning("PalLight set_colour(%s): send_command returned False", mac)
        return result

    async def set_colour_streaming(self, mac: str, hue: float) -> bool:
        """
        Set colour without waiting for ACK — used during continuous drag.

        The native app streams colour commands while the user drags around
        the wheel without waiting for each ACK. The device processes them
        in sequence and the last one wins. State is NOT updated here since
        intermediate drag positions are transient — the final release calls
        set_colour() which updates state properly.
        """
        entry = self._devices.get(mac)
        if not entry or not entry.session or not entry.session.available:
            return False
        hue_byte = ha_hue_to_device(hue)
        seq      = entry.session.next_sequence()
        token_hi = entry.session.session_token_hi
        token_lo = entry.session.session_token_lo
        return await entry.session.send_command_nowait(
            cmd_colour(token_hi, token_lo, seq, hue_byte), label="drag_colour"
        )


        """
        Activate a built-in effect by name.

        Sends a 0xA7 frame with the effect index and speed.
        If speed is None, uses the device entry's current effect_speed.

        After the 0xA7 frame the app also sends a 0xA1 ON command — we do
        the same to make sure the device is on.
        """
        entry = self._devices.get(mac)
        if not entry or not entry.session or not entry.session.available:
            _LOGGER.warning("PalLight set_effect(%s): no available session", mac)
            return False

        effect_index = EFFECT_NAMES.get(effect_name)
        if effect_index is None:
            _LOGGER.warning(
                "PalLight set_effect(%s): unknown effect %r", mac, effect_name
            )
            return False

        use_speed = speed if speed is not None else entry.effect_speed
        token_hi  = entry.session.session_token_hi
        token_lo  = entry.session.session_token_lo

        # 1. Send 0xA7 effect selection frame
        seq = entry.session.next_sequence()
        _dlog(
            f"set_effect({mac}) effect={effect_name!r} index=0x{effect_index:02X} "
            f"speed=0x{use_speed:04X} token=[0x{token_hi:02X},0x{token_lo:02X}] seq=0x{seq:04X}"
        )
        result = await entry.session.send_command(
            cmd_set_effect(token_hi, token_lo, seq, effect_index, use_speed),
            label="set_effect",
        )
        if not result:
            _LOGGER.warning("PalLight set_effect(%s): 0xA7 command failed", mac)
            return False

        # 2. Follow with 0xA1 ON to confirm device is running the effect
        seq = entry.session.next_sequence()
        result = await entry.session.send_command(
            cmd_on(token_hi, token_lo, seq), label="set_effect/on"
        )

        if result:
            entry.effect       = effect_name
            entry.effect_speed = use_speed
            entry.is_on        = True
        return result

    async def set_effect_speed(self, mac: str, speed: int) -> bool:
        """
        Update the speed of the currently active effect without changing it.

        Sends a new 0xA7 frame with the same effect index and new speed.
        No-op if no effect is currently active.
        """
        entry = self._devices.get(mac)
        if not entry or not entry.session or not entry.session.available:
            _LOGGER.warning("PalLight set_effect_speed(%s): no available session", mac)
            return False

        if entry.effect is None:
            _LOGGER.debug(
                "PalLight set_effect_speed(%s): no active effect — ignoring", mac
            )
            return False

        return await self.set_effect(mac, entry.effect, speed=speed)

    # ── Accessors ─────────────────────────────────────────────────────────────

    def get_device(self, mac: str) -> DeviceEntry | None:
        return self._devices.get(mac)

    @property
    def devices(self) -> dict[str, DeviceEntry]:
        return dict(self._devices)

    async def async_shutdown(self) -> None:
        for entry in self._devices.values():
            if entry.session:
                await entry.session.disconnect()
        self._devices.clear()

    async def suspend_session(self, mac: str) -> bool:
        """
        Temporarily disconnect the Xlink session for a device.

        Required before querying AT commands on port 48899 — the HF-LPB100
        ignores AT commands while an Xlink session is active on port 5987.
        Call resume_session() afterwards to reconnect.

        Returns True if a session was active and has been suspended.
        """
        entry = self._devices.get(mac)
        if not entry or not entry.session:
            return False
        _LOGGER.info("PalLight [%s] suspending Xlink session for AT command query", mac)
        await entry.session.disconnect()
        entry.session = None
        return True

    async def resume_session(self, mac: str) -> bool:
        """
        Reconnect the Xlink session after an AT command query.

        Returns True if reconnection succeeded.
        """
        entry = self._devices.get(mac)
        if not entry:
            return False
        _LOGGER.info("PalLight [%s] resuming Xlink session after AT command query", mac)
        await self._connect_device(entry)
        return entry.session is not None and entry.session.available