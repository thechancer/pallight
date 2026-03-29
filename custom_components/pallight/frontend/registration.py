"""PalLight frontend — JavaScript module registration."""
# ── File version ──────────────────────────────────────────────────────────────
from __future__ import annotations

from ..const import INTEGRATION_VERSION
__version__ = INTEGRATION_VERSION
# Changelog:
#   0.9.0  Initial — JSModuleRegistration class; serves card from frontend/
#          directory via /pallight-frontend static path. Uses async_call_later
#          retry loop waiting for lovelace.resources.loaded. Full diagnostic
#          logging at WARNING level for troubleshooting.
# ─────────────────────────────────────────────────────────────────────────────

import logging
from pathlib import Path
from typing import Any

from homeassistant.components.http import StaticPathConfig
from homeassistant.core import HomeAssistant
from homeassistant.helpers.event import async_call_later

from ..const import CARD_FILENAME, INTEGRATION_VERSION, JSMODULES, URL_BASE

_LOGGER = logging.getLogger(__name__)

_FRONTEND_DIR = Path(__file__).parent


class JSModuleRegistration:
    """Registers PalLight JavaScript modules in Home Assistant Lovelace."""

    def __init__(self, hass: HomeAssistant) -> None:
        self.hass = hass
        self.lovelace = hass.data.get("lovelace")
        _LOGGER.debug(
            "PalLight JSModuleRegistration.__init__: "
            "lovelace=%s  hass.data keys=%s",
            self.lovelace,
            [k for k in hass.data if "lovelace" in str(k).lower()],
        )

    async def async_register(self) -> None:
        """Register static path and Lovelace resources."""
        _LOGGER.debug("PalLight: async_register called")
        await self._async_register_path()

        if self.lovelace is None:
            _LOGGER.warning("PalLight: Lovelace not available — cannot register card resource")
            return

        _LOGGER.debug(
            "PalLight: lovelace found — type=%s  mode=%s  has_resources=%s",
            type(self.lovelace),
            getattr(self.lovelace, "resource_mode", "NO_RESOURCE_MODE_ATTR"),
            hasattr(self.lovelace, "resources"),
        )

        if getattr(self.lovelace, "resource_mode", None) != "storage":
            _LOGGER.warning(
                "PalLight: Lovelace mode is %r not 'storage' — manual resource required:\n"
                "  url: %s/%s?v=%s\n  type: module",
                getattr(self.lovelace, "resource_mode", None),
                URL_BASE, CARD_FILENAME, INTEGRATION_VERSION,
            )
            return

        await self._async_wait_for_lovelace_resources()

    async def _async_register_path(self) -> None:
        _LOGGER.info(
            "PalLight: registering static path %s → %s",
            URL_BASE, _FRONTEND_DIR,
        )
        try:
            await self.hass.http.async_register_static_paths([
                StaticPathConfig(
                    url_path=URL_BASE,
                    path=str(_FRONTEND_DIR),
                    cache_headers=False,
                )
            ])
            _LOGGER.info("PalLight: static path registered OK")
        except RuntimeError as e:
            _LOGGER.debug("PalLight: static path already registered (%s)", e)

    async def _async_wait_for_lovelace_resources(self) -> None:
        async def _check_loaded(_now: Any = None) -> None:
            loaded = getattr(self.lovelace.resources, "loaded", None)
            _LOGGER.debug(
                "PalLight: checking resources.loaded = %s", loaded
            )
            if loaded:
                await self._async_register_modules()
            else:
                _LOGGER.debug("PalLight: resources not loaded yet — retry in 5s")
                async_call_later(self.hass, 5, _check_loaded)

        await _check_loaded()

    async def _async_register_modules(self) -> None:
        _LOGGER.debug("PalLight: _async_register_modules called")
        existing = list(self.lovelace.resources.async_items())
        _LOGGER.debug("PalLight: existing resources = %s", existing)

        existing_ours = [
            r for r in existing
            if r.get("url", "").startswith(URL_BASE)
        ]

        for module in JSMODULES:
            url_path = f"{URL_BASE}/{module['filename']}"
            versioned_url = f"{url_path}?v={module['version']}"
            matched = next(
                (r for r in existing_ours if r.get("url", "").split("?")[0] == url_path),
                None,
            )

            if matched is None:
                _LOGGER.info("PalLight: creating resource %s", versioned_url)
                await self.lovelace.resources.async_create_item(
                    {"res_type": "module", "url": versioned_url}
                )
                _LOGGER.info("PalLight: resource created OK")
            elif matched["url"] != versioned_url:
                _LOGGER.info("PalLight: updating resource %s → %s", matched["url"], versioned_url)
                await self.lovelace.resources.async_update_item(
                    matched["id"],
                    {"res_type": "module", "url": versioned_url},
                )
            else:
                _LOGGER.debug("PalLight: resource already at correct URL %s", versioned_url)

    async def async_unregister(self) -> None:
        if self.lovelace is None or getattr(self.lovelace, "resource_mode", None) != "storage":
            return
        for module in JSMODULES:
            url_path = f"{URL_BASE}/{module['filename']}"
            for resource in list(self.lovelace.resources.async_items()):
                if resource.get("url", "").startswith(url_path):
                    await self.lovelace.resources.async_delete_item(resource["id"])
