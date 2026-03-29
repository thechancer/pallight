"""
PalLight light platform — sprint scope:
  • On / Off
  • Colour wheel (HS mode, hue 0–360°)
  • Brightness step up / down
  • Built-in effects (Rainbow, Strobe, Fade, etc.) via effect list
  • Effect speed via HA brightness slider when an effect is active

State is optimistically updated on command and restored across HA restarts.
The device sends unsolicited 0x80 state pushes after every command which
update the coordinator cache — entities react via the coordinator listener.
"""
# ── File version ──────────────────────────────────────────────────────────────
# Changelog:
#   0.9.0  effect_list, effect property, LightEntityFeature.EFFECT,
#          brightness-as-speed in effect mode, effect restore
#   0.8.0  brightness step, hs_color, RestoreEntity
#   0.5.0  Initial release
# ─────────────────────────────────────────────────────────────────────────────


from __future__ import annotations

from .const import INTEGRATION_VERSION
__version__ = INTEGRATION_VERSION

import asyncio
import logging
from typing import Any

from homeassistant.components.light import (
    ColorMode,
    LightEntity,
    LightEntityFeature,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback

try:
    from homeassistant.const import ATTR_BRIGHTNESS, ATTR_EFFECT, ATTR_HS_COLOR
except ImportError:
    ATTR_BRIGHTNESS = "brightness"
    ATTR_EFFECT     = "effect"
    ATTR_HS_COLOR   = "hs_color"

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.restore_state import RestoreEntity
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import (
    CONF_FRIENDLY_NAME,
    CONF_RESTORE_MODE,
    DOMAIN,
    EFFECT_NAMES,
    PALLIGHT_DEBUG,
    RESTORE_BRIGHTNESS,
    RESTORE_EFFECT,
    RESTORE_EFFECT_SPEED,
    RESTORE_HUE,
    RESTORE_IS_ON,
    RESTORE_MODE_DEFAULT,
    RESTORE_MODE_LAST,
)
from .coordinator import DeviceEntry, PalLightCoordinator
from .protocol import ha_brightness_to_effect_speed, effect_speed_to_ha_brightness

_LOGGER = logging.getLogger(__name__)

# Number of brightness steps to move per HA brightness unit.
# Device has an unknown number of steps — we use relative commands.
# HA sends 0-255; we translate to step count.
STEPS_PER_255 = 16   # confirmed: device step size = 16 raw units (255/16 ≈ 16 steps full range)


def _slugify(name: str) -> str:
    """Slugify a friendly name for use in entity IDs."""
    import re
    slug = name.strip().lower()
    slug = re.sub(r"[^a-z0-9]+", "_", slug)
    return slug.strip("_") or "light"


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: PalLightCoordinator = hass.data[DOMAIN][entry.entry_id]

    added_macs: set[str] = set()

    def _add_new_entities() -> None:
        new = [
            PalLightEntity(coordinator, mac)
            for mac in coordinator.devices
            if mac not in added_macs
        ]
        if new:
            for e in new:
                added_macs.add(e.mac)
            async_add_entities(new, update_before_add=True)

    _add_new_entities()
    coordinator.async_add_listener(_add_new_entities)


class PalLightEntity(CoordinatorEntity[PalLightCoordinator], LightEntity, RestoreEntity):
    """PalLight TOUCH-1 — colour wheel + brightness step."""

    def __init__(self, coordinator: PalLightCoordinator, mac: str) -> None:
        super().__init__(coordinator)
        self._mac = mac

        # Derive name and unique_id from the friendly name stored in config entry
        friendly = coordinator.entry.data.get(CONF_FRIENDLY_NAME, "").strip()
        if not friendly:
            # Fallback for entries created before the friendly name step existed
            friendly = mac

        slug = _slugify(friendly)
        self._attr_unique_id = f"pallight_{slug}"
        self._attr_name      = friendly

        # Optimistic state
        self._is_on:    bool  = False
        self._hue:      float = 0.0    # 0.0–360.0°
        self._sat:      float = 100.0  # always full saturation for colour wheel
        self._brightness: int = 255    # 0-255 (HA scale, optimistic only)
        self._effect: str | None = None          # active effect name, or None
        self._effect_speed: int  = 0x3B00        # device speed (0x0000=fast, 0xFFFF=slow)

        # Restore pending flag
        self._restore_done = False

    @property
    def mac(self) -> str:
        return self._mac

    @property
    def _device(self) -> DeviceEntry | None:
        return self.coordinator.get_device(self._mac)

    # ── Entity metadata ───────────────────────────────────────────────────────

    @property
    def name(self) -> str:
        return self._attr_name

    @property
    def unique_id(self) -> str:
        return self._attr_unique_id

    @property
    def available(self) -> bool:
        d = self._device
        return d is not None and d.available

    @property
    def device_info(self) -> DeviceInfo:
        d = self._device
        return DeviceInfo(
            identifiers={(DOMAIN, self._mac)},
            name=self._attr_name,
            manufacturer="SZiRain / iRainxun",
            model=d.device_type if d else "TOUCH-1",
        )

    # ── Light capability ──────────────────────────────────────────────────────

    @property
    def color_mode(self) -> ColorMode:
        return ColorMode.HS

    @property
    def supported_color_modes(self) -> set[ColorMode]:
        return {ColorMode.HS}

    @property
    def supported_features(self) -> LightEntityFeature:
        return LightEntityFeature.EFFECT

    @property
    def effect_list(self) -> list[str]:
        return list(EFFECT_NAMES.keys())

    @property
    def effect(self) -> str | None:
        return self._effect

    # ── State ─────────────────────────────────────────────────────────────────

    @property
    def is_on(self) -> bool:
        return self._is_on

    @property
    def brightness(self) -> int:
        if self._effect is not None:
            # In effect mode the brightness slider controls speed.
            # Convert device speed (0x0000=fast, 0xFFFF=slow) → HA brightness (255=fast, 0=slow)
            return effect_speed_to_ha_brightness(self._effect_speed)
        return self._brightness

    @property
    def hs_color(self) -> tuple[float, float]:
        return (self._hue, self._sat)

    # ── Restore ───────────────────────────────────────────────────────────────

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {
            RESTORE_IS_ON:        self._is_on,
            RESTORE_BRIGHTNESS:   self._brightness,
            RESTORE_HUE:          self._hue,
            RESTORE_EFFECT:       self._effect,
            RESTORE_EFFECT_SPEED: self._effect_speed,
        }

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()

        restore_mode = self.coordinator.entry.data.get(
            CONF_RESTORE_MODE, RESTORE_MODE_LAST
        )
        if restore_mode == RESTORE_MODE_DEFAULT:
            self._is_on = False
            self._hue = 180.0
            self._sat = 100.0
            self._brightness = 255
            _LOGGER.debug("PalLight [%s] restore mode=DEFAULT_CYAN", self._mac)
        else:
            last = await self.async_get_last_state()
            if last and last.attributes:
                attrs = last.attributes
                if RESTORE_IS_ON in attrs:
                    self._is_on = bool(attrs[RESTORE_IS_ON])
                if RESTORE_BRIGHTNESS in attrs:
                    self._brightness = int(attrs[RESTORE_BRIGHTNESS])
                if RESTORE_HUE in attrs:
                    self._hue = float(attrs[RESTORE_HUE])
            if RESTORE_EFFECT in attrs and attrs[RESTORE_EFFECT] is not None:
                self._effect = str(attrs[RESTORE_EFFECT])
            if RESTORE_EFFECT_SPEED in attrs:
                self._effect_speed = int(attrs[RESTORE_EFFECT_SPEED])
            _LOGGER.debug(
                "PalLight [%s] restored — on=%s bright=%s hue=%.1f° effect=%s speed=0x%04X",
                self._mac, self._is_on, self._brightness, self._hue,
                self._effect, self._effect_speed,
            )

        # Push restored state to device once it comes online, then unregister.
        # Store the cancel function so _push_restored_state_once can remove itself.
        self._cancel_restore_listener: callable = lambda: None

        def _register() -> None:
            self._cancel_restore_listener = self.coordinator.async_add_listener(
                self._push_restored_state_once
            )

        _register()
        # Also register for cleanup on entity removal
        self.async_on_remove(lambda: self._cancel_restore_listener())

    @callback
    def _push_restored_state_once(self) -> None:
        if self._restore_done:
            return
        d = self._device
        if not d or not d.available:
            return
        self._restore_done = True
        # Unregister this listener — no need to keep checking after first fire
        self._cancel_restore_listener()

        async def _push() -> None:
            _LOGGER.info(
                "PalLight [%s] pushing restored state (on=%s effect=%s hue=%.1f°)",
                self._mac, self._is_on, self._effect, self._hue,
            )
            if self._is_on:
                if self._effect is not None:
                    await self.coordinator.set_effect(
                        self._mac, self._effect, speed=self._effect_speed
                    )
                else:
                    await self.coordinator.turn_on(self._mac)
                    if self._hue > 0:
                        await self.coordinator.set_colour(self._mac, self._hue)
            else:
                await self.coordinator.turn_off(self._mac)

        asyncio.create_task(_push())

    # ── Commands ──────────────────────────────────────────────────────────────

    async def async_turn_on(self, **kwargs: Any) -> None:
        hs         = kwargs.get(ATTR_HS_COLOR)
        brightness = kwargs.get(ATTR_BRIGHTNESS)
        effect     = kwargs.get(ATTR_EFFECT)

        if PALLIGHT_DEBUG:
            _LOGGER.info(
                "PalLight light [%s] async_turn_on called — "
                "kwargs=%s is_on=%s available=%s",
                self._mac, kwargs, self._is_on, self.available,
            )

        if not self.available:
            _LOGGER.warning(
                "PalLight light [%s] async_turn_on: entity not available", self._mac
            )
            return

        # ── Effect mode ───────────────────────────────────────────────────────
        if effect is not None:
            # Convert brightness to speed if also provided
            speed = None
            if brightness is not None:
                speed = ha_brightness_to_effect_speed(brightness)
                self._effect_speed = speed

            if PALLIGHT_DEBUG:
                _LOGGER.info(
                    "PalLight light [%s] setting effect=%r speed=0x%04X",
                    self._mac, effect, speed if speed is not None else self._effect_speed,
                )

            if await self.coordinator.set_effect(self._mac, effect, speed=speed):
                self._effect  = effect
                self._is_on   = True
            self.async_write_ha_state()
            return

        # ── Static colour / brightness mode ───────────────────────────────────

        # If we're switching out of an effect, clear it
        if self._effect is not None and (hs is not None or brightness is not None):
            self._effect = None

        # Turn on first if currently off
        if not self._is_on:
            if not await self.coordinator.turn_on(self._mac):
                _LOGGER.warning(
                    "PalLight light [%s] turn_on command failed", self._mac
                )
                return
            self._is_on = True

        # Set colour if HS provided
        if hs is not None:
            hue = float(hs[0])
            self._hue = hue
            self._sat = float(hs[1])
            if PALLIGHT_DEBUG:
                _LOGGER.info(
                    "PalLight light [%s] setting colour hue=%.1f° sat=%.1f%%",
                    self._mac, hue, self._sat,
                )
            # Use streaming (no-ACK-wait) when ONLY hs_color is provided with
            # no brightness/effect — this is the card drag path. The card sends
            # the same call on drag-release as the final position, so the device
            # always ends on the correct colour even if mid-drag packets are lost.
            if brightness is None and effect is None and self._is_on:
                await self.coordinator.set_colour_streaming(self._mac, hue)
            else:
                await self.coordinator.set_colour(self._mac, hue)

        # Brightness: if an effect is active use as speed, otherwise step
        if brightness is not None:
            if self._effect is not None:
                speed = ha_brightness_to_effect_speed(brightness)
                if PALLIGHT_DEBUG:
                    _LOGGER.info(
                        "PalLight light [%s] effect speed update brightness=%d → speed=0x%04X",
                        self._mac, brightness, speed,
                    )
                if await self.coordinator.set_effect_speed(self._mac, speed):
                    self._effect_speed = speed
            else:
                if PALLIGHT_DEBUG:
                    _LOGGER.info(
                        "PalLight light [%s] brightness requested=%d current=%d",
                        self._mac, brightness, self._brightness,
                    )
                await self._apply_brightness(brightness)

        # Plain turn-on with no other kwargs — just make sure it's on
        if not kwargs:
            if not self._is_on:
                if not await self.coordinator.turn_on(self._mac):
                    _LOGGER.warning(
                        "PalLight light [%s] plain turn_on command failed", self._mac
                    )
                    return
                self._is_on = True

        self.async_write_ha_state()

    async def async_turn_off(self, **kwargs: Any) -> None:
        if PALLIGHT_DEBUG:
            _LOGGER.info(
                "PalLight light [%s] async_turn_off called — available=%s",
                self._mac, self.available,
            )

        if not self.available:
            _LOGGER.warning(
                "PalLight light [%s] async_turn_off: entity not available", self._mac
            )
            return

        if await self.coordinator.turn_off(self._mac):
            self._is_on = False
            self._effect = None   # effect stops when light is off
        self.async_write_ha_state()

    async def _apply_brightness(self, target: int) -> None:
        """
        Translate HA brightness (0–255) to step commands.

        The device has no absolute brightness set and sends no 0xA4 readback
        after brightness steps — so we can never know its true position.

        Strategy: map the 0–255 HA scale directly to 0–STEPS_PER_255 steps,
        always relative to the CURRENT HA-cached value. Accept that the device
        position will drift if the physical remote is used, but keep HA's
        slider self-consistent. When an 0xA4 push does arrive (e.g. on
        connect) it resets the cached value.
        """
        current = self._brightness
        delta   = target - current

        if delta == 0:
            return

        step_fn = (
            self.coordinator.brightness_up
            if delta > 0
            else self.coordinator.brightness_down
        )
        # Scale delta to steps — clamp to at least 1 step per interaction
        steps = max(1, round(abs(delta) / 255 * STEPS_PER_255))

        _LOGGER.info(
            "PalLight [%s] brightness %d→%d  delta=%+d  steps=%d %s",
            self._mac, current, target, delta, steps,
            "▲ UP" if delta > 0 else "▼ DOWN",
        )

        for _ in range(steps):
            if not await step_fn(self._mac):
                break

        # Update cached value — this is optimistic and will drift from reality
        # if the physical remote is used, but keeps the HA slider consistent
        self._brightness = target

    # ── Coordinator update ────────────────────────────────────────────────────

    @callback
    def _handle_coordinator_update(self) -> None:
        d = self._device
        if d:
            if d.brightness is not None:
                self._brightness = d.brightness
            if d.effect is not None:
                self._effect       = d.effect
                self._effect_speed = d.effect_speed
        self.async_write_ha_state()
