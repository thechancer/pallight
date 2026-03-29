"""Config flow for PalLight — device ID discovery or manual entry."""
from __future__ import annotations

from .const import INTEGRATION_VERSION
__version__ = INTEGRATION_VERSION
# Changelog:
#   0.9.0  Device ID discovery (41-byte 0x13), manual fallback on failure,
#          restore mode radio button, interface selector from HA adapters
#   0.8.0  OptionsFlow() fix for HA 2024.8+
#   0.5.0  Initial release
# ─────────────────────────────────────────────────────────────────────────────

import logging
import re
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import callback

try:
    from homeassistant.config_entries import ConfigFlowResult as FlowResult
except ImportError:
    from homeassistant.data_entry_flow import FlowResult  # type: ignore[no-redef]

from .const import (
    CONF_BROADCAST_IP,
    CONF_DEVICE_ID,
    CONF_DEVICE_TYPE,
    CONF_FRIENDLY_NAME,
    CONF_MANUAL_IP,
    CONF_MANUAL_MAC,
    CONF_PASSWORD_HEX,
    CONF_RESTORE_MODE,
    CONF_SCAN_INTERVAL,
    DEFAULT_BROADCAST_IP,
    DEFAULT_PASSWORD_HEX,
    DEFAULT_SCAN_INTERVAL,
    DEVICE_TYPE_CHOICES,
    DOMAIN,
    RESTORE_MODE_DEFAULT,
    RESTORE_MODE_LAST,
)
from .transport import discover_devices, discover_by_device_id

_LOGGER = logging.getLogger(__name__)


def _slugify(name: str) -> str:
    slug = name.strip().lower()
    slug = re.sub(r"[^a-z0-9]+", "_", slug)
    return slug.strip("_") or "light"


def _normalise_mac(mac: str) -> str:
    clean = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(clean) != 12:
        raise ValueError(f"Invalid MAC: {mac!r}")
    return ":".join(clean[i:i+2].upper() for i in range(0, 12, 2))


def _normalise_device_id(device_id: str) -> str:
    clean = re.sub(r"[^0-9a-fA-F]", "", device_id).lower()
    if len(clean) != 32:
        raise ValueError(f"Invalid device ID: {device_id!r}")
    return clean


class PalLightConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Config flow for PalLight."""

    VERSION = 1

    def __init__(self) -> None:
        self._discovered: list[dict[str, str]] = []
        self._selected: dict[str, str] | None = None   # {ip, mac}
        self._friendly_name: str = ""
        self._broadcast_ip: str = ""
        self._device_id: str = ""
        self._restore_mode: str = RESTORE_MODE_LAST

    # ── Step 1: Device ID + interface ────────────────────────────────────────

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """
        Select network interface and run HF-A11ASSISTHREAD discovery.

        Broadcasts 'HF-A11ASSISTHREAD' on port 48899 — the device responds
        with 'ip,mac,model'. No device ID or MAC needed in advance.
        Confirmed working from limitlessled_discovery.pcap.

        If discovery finds nothing, the form re-shows with an option to
        enter the device ID (from SZiRain app Settings → About Device)
        which uses the 41-byte 0x13 search as an alternative.
        """
        errors: dict[str, str] = {}

        if user_input is not None:
            self._broadcast_ip = user_input.get(CONF_BROADCAST_IP, "")
            if self._broadcast_ip == "auto":
                self._broadcast_ip = ""

            raw_id = user_input.get(CONF_DEVICE_ID, "").strip()

            if raw_id:
                # Device ID provided — use targeted 0x13 search
                try:
                    self._device_id = _normalise_device_id(raw_id)
                except ValueError:
                    errors[CONF_DEVICE_ID] = "invalid_device_id"

                if not errors:
                    found = await discover_by_device_id(
                        device_id=self._device_id,
                        bind_ip=self._broadcast_ip,
                    )
                    if found:
                        self._selected = found
                        return await self.async_step_name()
                    else:
                        errors["base"] = "no_devices_found"
            else:
                # No device ID — use HF-A11ASSISTHREAD broadcast discovery
                devices = await discover_devices(bind_ip=self._broadcast_ip)
                if devices:
                    if len(devices) == 1:
                        self._selected = {"ip": devices[0]["ip"], "mac": devices[0]["mac"]}
                        return await self.async_step_name()
                    else:
                        # Multiple devices found — let user pick
                        self._discovered = devices
                        return await self.async_step_pick_device()
                else:
                    errors["base"] = "no_devices_found"

        interface_choices = await self._get_interface_choices()

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema({
                vol.Required(CONF_BROADCAST_IP, default="auto"): vol.In(interface_choices),
                vol.Optional(CONF_DEVICE_ID, default=""): str,
            }),
            description_placeholders={
                "id_hint": "Leave blank to auto-discover. Or enter the 32-char Device ID from SZiRain app Settings → About Device.",
            },
            errors=errors,
        )

    # ── Step 1b: pick device when multiple found ──────────────────────────────

    async def async_step_pick_device(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Shown only when multiple devices respond to discovery."""
        if user_input is not None:
            idx = int(user_input.get("device_index", 0))
            dev = self._discovered[idx]
            self._selected = {"ip": dev["ip"], "mac": dev["mac"]}
            return await self.async_step_name()

        choices = {
            str(i): f"{d['ip']}  ({d['mac']})"
            for i, d in enumerate(self._discovered)
        }
        return self.async_show_form(
            step_id="pick_device",
            data_schema=vol.Schema({
                vol.Required("device_index", default="0"): vol.In(choices),
            }),
        )

    # ── Step 1b: manual fallback (shown when discovery fails) ─────────────────

    async def async_step_manual(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Manual entry — shown as a fallback when discovery fails."""
        errors: dict[str, str] = {}

        if user_input is not None:
            ip  = user_input.get(CONF_MANUAL_IP, "").strip()
            raw_mac = user_input.get(CONF_MANUAL_MAC, "").strip()

            if not ip:
                errors[CONF_MANUAL_IP] = "invalid_ip"
            try:
                mac = _normalise_mac(raw_mac)
            except ValueError:
                errors[CONF_MANUAL_MAC] = "invalid_mac"
                mac = ""

            if not errors:
                self._selected = {"ip": ip, "mac": mac}
                return await self.async_step_name()

        return self.async_show_form(
            step_id="manual",
            data_schema=vol.Schema({
                vol.Required(CONF_MANUAL_IP): str,
                vol.Required(CONF_MANUAL_MAC): str,
            }),
            description_placeholders={
                "device_id": self._device_id or "unknown",
            },
            errors=errors,
        )

    # ── Step 2: friendly name ─────────────────────────────────────────────────

    async def async_step_name(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        assert self._selected is not None
        errors: dict[str, str] = {}

        if user_input is not None:
            name = user_input.get(CONF_FRIENDLY_NAME, "").strip()
            if not name or not _slugify(name):
                errors[CONF_FRIENDLY_NAME] = "name_required"
            else:
                self._friendly_name = name
                return await self.async_step_restore_mode()

        mac = self._selected["mac"]
        ip  = self._selected["ip"]
        return self.async_show_form(
            step_id="name",
            data_schema=vol.Schema({
                vol.Required(CONF_FRIENDLY_NAME): str,
            }),
            description_placeholders={
                "device":  f"{ip} ({mac})",
                "example": "e.g. Living Room, Pool Light, Garden Spots",
            },
            errors=errors,
        )

    # ── Step 3: restore mode ──────────────────────────────────────────────────

    async def async_step_restore_mode(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """
        Choose what state the light comes on in when HA restarts.

          Last known  — restores the colour/effect that was active before shutdown
          Default     — always turns on at static cyan (a safe neutral starting point)
        """
        if user_input is not None:
            self._restore_mode = user_input.get(CONF_RESTORE_MODE, RESTORE_MODE_LAST)
            return await self.async_step_device_type()

        return self.async_show_form(
            step_id="restore_mode",
            data_schema=vol.Schema({
                vol.Required(CONF_RESTORE_MODE, default=RESTORE_MODE_LAST): vol.In({
                    RESTORE_MODE_LAST:    "Last known state (colour/effect before shutdown)",
                    RESTORE_MODE_DEFAULT: "Default — static cyan on every restart",
                }),
            }),
        )

    # ── Step 4: device type ───────────────────────────────────────────────────

    async def async_step_device_type(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        assert self._selected is not None

        if user_input is not None:
            mac = self._selected["mac"]
            ip  = self._selected["ip"]

            await self.async_set_unique_id(mac.replace(":", "").upper())
            self._abort_if_unique_id_configured(updates={CONF_MANUAL_IP: ip})

            return self.async_create_entry(
                title=f"PalLight {self._friendly_name}",
                data={
                    CONF_MANUAL_IP:     ip,
                    CONF_MANUAL_MAC:    mac,
                    CONF_DEVICE_ID:     self._device_id,
                    CONF_FRIENDLY_NAME: self._friendly_name,
                    CONF_RESTORE_MODE:  self._restore_mode,
                    CONF_DEVICE_TYPE:   user_input.get(CONF_DEVICE_TYPE, DEVICE_TYPE_CHOICES[0]),
                    CONF_SCAN_INTERVAL: DEFAULT_SCAN_INTERVAL,
                    CONF_BROADCAST_IP:  self._broadcast_ip,
                    CONF_PASSWORD_HEX:  DEFAULT_PASSWORD_HEX,
                },
            )

        return self.async_show_form(
            step_id="device_type",
            data_schema=vol.Schema({
                vol.Required(
                    CONF_DEVICE_TYPE,
                    default=DEVICE_TYPE_CHOICES[0],
                ): vol.In(DEVICE_TYPE_CHOICES),
            }),
            description_placeholders={
                "device": f"{self._selected['ip']} ({self._selected['mac']})",
                "name":   self._friendly_name,
            },
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def _get_interface_choices(self) -> dict[str, str]:
        choices: dict[str, str] = {"auto": "Auto — let the OS decide (single NIC only)"}
        try:
            from homeassistant.components.network import async_get_adapters
            adapters = await async_get_adapters(self.hass)
            for adapter in adapters:
                if not adapter["enabled"]:
                    continue
                for ipv4 in adapter["ipv4"]:
                    addr = ipv4["address"]
                    if addr.startswith("127.") or addr.startswith("172."):
                        continue
                    label = f"{adapter['name']} — {addr}"
                    choices[addr] = label
        except Exception as err:  # noqa: BLE001
            _LOGGER.warning("PalLight: could not enumerate network adapters: %s", err)
        return choices

    # ── Options flow ──────────────────────────────────────────────────────────

    @staticmethod
    @callback
    def async_get_options_flow(entry: config_entries.ConfigEntry) -> PalLightOptionsFlow:
        return PalLightOptionsFlow()


class PalLightOptionsFlow(config_entries.OptionsFlow):
    """Allow editing name, scan interval, interface, restore mode and device type."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            name = user_input.get(CONF_FRIENDLY_NAME, "").strip()
            if not name or not _slugify(name):
                errors[CONF_FRIENDLY_NAME] = "name_required"
            else:
                data = dict(user_input)
                if data.get(CONF_BROADCAST_IP) == "auto":
                    data[CONF_BROADCAST_IP] = ""
                return self.async_create_entry(title="", data=data)

        current = self.config_entry.data
        current_ip = current.get(CONF_BROADCAST_IP, "") or "auto"
        choices = await self._get_interface_choices()

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema({
                vol.Required(
                    CONF_FRIENDLY_NAME,
                    default=current.get(CONF_FRIENDLY_NAME, ""),
                ): str,
                vol.Required(
                    CONF_SCAN_INTERVAL,
                    default=current.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
                ): vol.All(int, vol.Range(min=10, max=3600)),
                vol.Required(
                    CONF_BROADCAST_IP,
                    default=current_ip,
                ): vol.In(choices),
                vol.Required(
                    CONF_RESTORE_MODE,
                    default=current.get(CONF_RESTORE_MODE, RESTORE_MODE_LAST),
                ): vol.In({
                    RESTORE_MODE_LAST:    "Last known state",
                    RESTORE_MODE_DEFAULT: "Default — static cyan on restart",
                }),
                vol.Optional(
                    CONF_DEVICE_TYPE,
                    default=current.get(CONF_DEVICE_TYPE, DEVICE_TYPE_CHOICES[0]),
                ): vol.In(DEVICE_TYPE_CHOICES),
            }),
            errors=errors,
        )

    async def _get_interface_choices(self) -> dict[str, str]:
        choices: dict[str, str] = {"auto": "Auto — let the OS decide (single NIC only)"}
        try:
            from homeassistant.components.network import async_get_adapters
            adapters = await async_get_adapters(self.hass)
            for adapter in adapters:
                if not adapter["enabled"]:
                    continue
                for ipv4 in adapter["ipv4"]:
                    addr = ipv4["address"]
                    if addr.startswith("127.") or addr.startswith("172."):
                        continue
                    label = f"{adapter['name']} — {addr}"
                    choices[addr] = label
        except Exception as err:  # noqa: BLE001
            _LOGGER.warning("PalLight: could not enumerate network adapters: %s", err)
        return choices
