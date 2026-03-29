"""PalLight LED Controller integration for Home Assistant."""
# ── File version ──────────────────────────────────────────────────────────────
# Changelog:
#   0.9.0  Lovelace registration via JSModuleRegistration in frontend/
#          registration.py. Uses async_setup + EVENT_HOMEASSISTANT_STARTED
#          pattern. Diagnostic WARNING logging throughout for troubleshooting.
#          Platform.SENSOR added alongside Platform.LIGHT.
#   0.8.0  OptionsFlow() fix for HA 2024.8+ (removed __init__ entry arg)
#   0.5.0  Initial release
# ─────────────────────────────────────────────────────────────────────────────
from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import CoreState, EVENT_HOMEASSISTANT_STARTED, HomeAssistant

from .const import DOMAIN, INTEGRATION_VERSION
from .coordinator import PalLightCoordinator
from .frontend.registration import JSModuleRegistration

__version__ = INTEGRATION_VERSION

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.LIGHT, Platform.SENSOR]


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Register static HTTP path and schedule Lovelace resource registration."""
    _LOGGER.info("PalLight: async_setup called — hass.state=%s", hass.state)

    async def _register_frontend(_event=None) -> None:
        _LOGGER.info("PalLight: _register_frontend called (event=%s)", _event)
        try:
            registrar = JSModuleRegistration(hass)
            await registrar.async_register()
        except Exception as err:
            _LOGGER.warning("PalLight: frontend registration error: %s", err, exc_info=True)

    if hass.state == CoreState.running:
        _LOGGER.info("PalLight: HA already running — registering frontend immediately")
        await _register_frontend()
    else:
        _LOGGER.info("PalLight: HA not running yet (%s) — waiting for STARTED event", hass.state)
        hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STARTED, _register_frontend)

    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up PalLight from a config entry."""
    _LOGGER.debug(
        "PalLight: async_setup_entry called — async_setup was called: %s",
        DOMAIN in hass.data or True,  # just to confirm we reach here
    )
    _LOGGER.info(
        "PalLight: loading entry %s — IP=%s MAC=%s type=%s",
        entry.entry_id,
        entry.data.get("manual_ip", "auto"),
        entry.data.get("manual_mac", "auto"),
        entry.data.get("device_type", "?"),
    )

    coordinator = PalLightCoordinator(hass, entry)
    await coordinator.async_config_entry_first_refresh()

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    entry.async_on_unload(entry.add_update_listener(_async_options_updated))

    _LOGGER.info(
        "PalLight: loaded — %d device(s) registered", len(coordinator.devices)
    )
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a PalLight config entry."""
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        coordinator: PalLightCoordinator = hass.data[DOMAIN].pop(entry.entry_id)
        await coordinator.async_shutdown()
    return unloaded


async def _async_options_updated(hass: HomeAssistant, entry: ConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)
