"""
PalLight sensor platform — diagnostic sensors per device.

Sensors:
  - WiFi Signal Strength (%)   — polled every WIFI_SCAN_INTERVAL seconds
                                  via AT+WSLQ on port 48899
"""
from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
    DataUpdateCoordinator,
    UpdateFailed,
)

from .const import (
    CONF_BROADCAST_IP,
    DOMAIN,
    INTEGRATION_VERSION,
    WIFI_SCAN_INTERVAL,
)
from .coordinator import DeviceEntry, PalLightCoordinator
from .wifi_signal import query_wifi_signal

__version__ = INTEGRATION_VERSION
# Changelog:
#   0.9.0  Initial — WiFi signal strength diagnostic sensor
# ─────────────────────────────────────────────────────────────────────────────

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up PalLight diagnostic sensors."""
    coordinator: PalLightCoordinator = hass.data[DOMAIN][entry.entry_id]
    bind_ip = entry.data.get(CONF_BROADCAST_IP, "") or ""

    added_macs: set[str] = set()

    def _add_new_sensors() -> None:
        new = []
        for mac, dev in coordinator.devices.items():
            if mac not in added_macs:
                wifi_coord = WifiSignalCoordinator(hass, coordinator, dev.ip, mac, bind_ip)
                new.append(WifiSignalSensor(coordinator, wifi_coord, mac))
                added_macs.add(mac)
        if new:
            async_add_entities(new, update_before_add=True)

    _add_new_sensors()
    coordinator.async_add_listener(_add_new_sensors)


class WifiSignalCoordinator(DataUpdateCoordinator[dict[str, Any] | None]):
    """Polls WiFi signal strength via AT+WSLQ on port 48899."""

    def __init__(
        self,
        hass: HomeAssistant,
        light_coordinator: PalLightCoordinator,
        device_ip: str,
        device_mac: str,
        bind_ip: str,
    ) -> None:
        self.light_coordinator = light_coordinator
        self.device_ip  = device_ip
        self.device_mac = device_mac
        self.bind_ip    = bind_ip
        super().__init__(
            hass,
            _LOGGER,
            name=f"pallight_wifi_{device_mac}",
            update_interval=timedelta(seconds=WIFI_SCAN_INTERVAL),
        )

    async def _async_update_data(self) -> dict[str, Any] | None:
        # Device ignores AT commands while Xlink session active —
        # suspend session, query, then resume.
        import asyncio as _asyncio
        _LOGGER.info("PalLight WiFi: suspending Xlink session for AT query")
        suspended = await self.light_coordinator.suspend_session(self.device_mac)
        try:
            await _asyncio.sleep(0.5)  # allow device to register session drop
            result = await query_wifi_signal(
                device_ip=self.device_ip,
                bind_ip=self.bind_ip,
            )
        finally:
            if suspended:
                _LOGGER.info("PalLight WiFi: resuming Xlink session")
                await self.light_coordinator.resume_session(self.device_mac)
        if result is None:
            raise UpdateFailed(f"No WiFi signal response from {self.device_ip}")
        return result


class WifiSignalSensor(
    CoordinatorEntity[WifiSignalCoordinator], SensorEntity
):
    """WiFi signal strength for one PalLight device."""

    _attr_device_class   = SensorDeviceClass.SIGNAL_STRENGTH
    _attr_state_class    = SensorStateClass.MEASUREMENT
    _attr_native_unit_of_measurement = "%"
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_icon           = "mdi:wifi"
    _attr_suggested_display_precision = 0

    def __init__(
        self,
        light_coordinator: PalLightCoordinator,
        wifi_coordinator: WifiSignalCoordinator,
        mac: str,
    ) -> None:
        super().__init__(wifi_coordinator)
        self._light_coordinator = light_coordinator
        self._mac = mac
        self._attr_unique_id = f"pallight_{mac.replace(':', '').lower()}_wifi_signal"
        self._attr_name = "WiFi Signal"

    @property
    def _device(self) -> DeviceEntry | None:
        return self._light_coordinator.get_device(self._mac)

    @property
    def device_info(self) -> DeviceInfo:
        d = self._device
        return DeviceInfo(
            identifiers={(DOMAIN, self._mac)},
            name=d.device_type if d else "PalLight",
            manufacturer="SZiRain / iRainxun",
            model=d.device_type if d else "TOUCH-1",
        )

    @property
    def native_value(self) -> int | None:
        if self.coordinator.data is None:
            return None
        return self.coordinator.data.get("percentage")

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        if self.coordinator.data is None:
            return {}
        return {"quality": self.coordinator.data.get("quality")}
