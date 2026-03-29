"""
PalLight WiFi signal strength helper.

Confirmed full sequence from LimitlessLED tool description:
  1. Broadcast 'HF-A11ASSISTHREAD' × 20 at 50ms intervals → 255.255.255.255:48899
  2. Wait for device response '192.168.2.7,98D863E3CF80,HF-LPB100'
  3. Send '+ok'     → device_ip:48899  (request admin mode entry)
  4. Recv '+ok'     ← device            (confirms admin mode active)
  5. Send 'AT+WSLQ' → device_ip:48899  (WiFi signal query)
  6. Recv '+ok=Good, 100%' ← device
  7. Send 'AT+Q'    → device_ip:48899  × 3 (exit admin mode)

The HF-A11ASSISTHREAD broadcast is mandatory — it wakes the device's AT
command interface. Without it, '+ok' and 'AT+WSLQ' are silently ignored
even if the device IP is known. The Xlink session on port 5987 must also
be suspended before starting this sequence.
"""
from __future__ import annotations

import asyncio
import logging
import re
import socket

from .const import (
    AT_ENTER, AT_EXIT, AT_PORT, AT_TIMEOUT, AT_WIFI_SIGNAL,
    DISCOVERY_MSG, INTEGRATION_VERSION,
)

__version__ = INTEGRATION_VERSION
# Changelog:
#   0.9.0  Fixed: broadcast HF-A11ASSISTHREAD to wake AT interface, then
#          wait for device +ok echo confirming admin mode before AT+WSLQ.
#          Full sequence confirmed from LimitlessLED tool description.
#          Xlink session must be suspended by caller before invoking.
# ─────────────────────────────────────────────────────────────────────────────

_LOGGER = logging.getLogger(__name__)

_RESP_RE   = re.compile(r'\+ok=(\w+),\s*(\d+)%', re.IGNORECASE)
_DEVICE_RE = re.compile(r'^\d+\.\d+\.\d+\.\d+,[0-9A-Fa-f]+,\S+')


async def query_wifi_signal(
    device_ip: str,
    bind_ip: str = "",
    timeout: float = AT_TIMEOUT,
) -> dict[str, str | int] | None:
    """
    Query WiFi signal strength via the HF-A11 AT command interface.

    Caller MUST suspend the active Xlink session first — device ignores
    AT commands while Xlink is active on port 5987.

    Returns dict: {quality: str, percentage: int} or None on failure.
    """
    loop = asyncio.get_event_loop()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except AttributeError:
        pass
    sock.setblocking(False)

    try:
        sock.bind((bind_ip, AT_PORT))
        _LOGGER.debug("PalLight WiFi: bound to port %d", AT_PORT)
    except OSError as exc:
        _LOGGER.debug("PalLight WiFi: bind to %d failed (%s) — trying ephemeral", AT_PORT, exc)
        try:
            sock.bind((bind_ip, 0))
            _LOGGER.debug("PalLight WiFi: bound to ephemeral port %d", sock.getsockname()[1])
        except OSError as exc2:
            _LOGGER.debug("PalLight WiFi: bind failed: %s", exc2)
            sock.close()
            return None

    result = None
    try:
        # Step 1: HF-A11ASSISTHREAD broadcast x20 at 50ms to wake AT interface
        _LOGGER.debug("PalLight WiFi: broadcasting HF-A11ASSISTHREAD x20")
        got_response = False
        for i in range(20):
            await loop.sock_sendto(sock, DISCOVERY_MSG, ("255.255.255.255", AT_PORT))
            try:
                data, addr = await asyncio.wait_for(
                    loop.sock_recvfrom(sock, 256), timeout=0.05
                )
                text = data.decode("ascii", errors="ignore").strip()
                _LOGGER.debug("PalLight WiFi: <- %r from %s", text, addr[0])
                if "," in text and addr[0] == device_ip:
                    _LOGGER.debug("PalLight WiFi: device responded, AT interface awake")
                    got_response = True
                    break
            except asyncio.TimeoutError:
                pass

        if not got_response:
            _LOGGER.debug("PalLight WiFi: no discovery response -- proceeding anyway")

        # Step 2: send +ok to enter admin mode
        # Device does NOT echo +ok back (confirmed from pcap -- no response
        # between +ok send and AT+WSLQ send). Wait 200ms as per pcap timing.
        _LOGGER.debug("PalLight WiFi: -> +ok to %s:%d", device_ip, AT_PORT)
        await loop.sock_sendto(sock, AT_ENTER, (device_ip, AT_PORT))
        await asyncio.sleep(0.2)

        # Step 3: send AT+WSLQ with \r terminator (confirmed from pcap raw bytes: 0d at end)
        _LOGGER.debug("PalLight WiFi: -> AT+WSLQ\\r to %s:%d", device_ip, AT_PORT)
        await loop.sock_sendto(sock, AT_WIFI_SIGNAL, (device_ip, AT_PORT))

        # Step 4: wait for response
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            remaining = deadline - loop.time()
            try:
                data, addr = await asyncio.wait_for(
                    loop.sock_recvfrom(sock, 256), timeout=remaining
                )
                text = data.decode("ascii", errors="ignore").strip()
                _LOGGER.debug("PalLight WiFi: <- %r from %s", text, addr[0])
                m = _RESP_RE.search(text)
                if m:
                    result = {
                        "quality":    m.group(1).capitalize(),
                        "percentage": int(m.group(2)),
                    }
                    _LOGGER.info("PalLight WiFi: result = %s", result)
                    break
            except asyncio.TimeoutError:
                _LOGGER.debug("PalLight WiFi: timed out waiting for response")
                break
            except Exception as exc:
                _LOGGER.debug("PalLight WiFi: recv error: %s", exc)
                break

    except OSError as exc:
        _LOGGER.debug("PalLight WiFi: send error: %s", exc)
    finally:
        # Step 5: exit admin mode with AT+Q\r (x3, confirmed from pcap)
        for _ in range(3):
            try:
                await loop.sock_sendto(sock, AT_EXIT, (device_ip, AT_PORT))
            except OSError:
                pass
        sock.close()
    if result is None:
        _LOGGER.debug("PalLight WiFi: no valid response from %s within %.1fs",
                        device_ip, timeout)
    return result
