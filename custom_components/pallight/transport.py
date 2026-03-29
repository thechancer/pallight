"""
PalLight transport layer — Xlink local UDP protocol.

Confirmed handshake from pcap:
  1. 0x13 broadcast  → 255.255.255.255:5987  (targeted by device MAC)
  2. drain ~350ms
  3. 0x23 unicast    → device_ip:5987         (fixed credential + nonce)
  4. 0x28            ← device                 (session token at byte[19])
  5. 0x33            → device_ip:5987         (echo session token)
  6. 0x50            ← device                 (handshake complete)
  7. 0x83 commands   → device_ip:5987         (control, uses session token)
  8. 0x8B            ← device                 (ACK, echoes sequence)
  9. 0x80            ← device                 (unsolicited state push)

All communication: UDP, ephemeral source port → device port 5987.
"""
# ── File version ──────────────────────────────────────────────────────────────
# Changelog:
#   0.9.0  discover_devices() rewritten: wildcard 41-byte 0x13 phase 1,
#          targeted 18-byte 0x13 phase 2, MAC extracted from 0x18 response.
#          DISCOVERY_RETRY_SECS, MSG_DISCOVERY_RESP, 0x18 in _MSG_NAMES
#   0.8.0  CONNECT_TIMEOUT=15s, retransmit loop for 0x13
#   0.7.0  XlinkSession, send_command, recv_loop
#   0.5.0  Initial release
# ─────────────────────────────────────────────────────────────────────────────


from __future__ import annotations

from .const import INTEGRATION_VERSION
__version__ = INTEGRATION_VERSION

import asyncio
import re
import logging
import socket
from collections.abc import Callable
from typing import Any

from .const import (
    ACK_TIMEOUT,
    CONNECT_TIMEOUT,
    DISCOVERY_RETRY_SECS,
    DISCOVERY_TIMEOUT,
    DISCOVERY_MSG,
    DRAIN_SECS,
    MSG_DISCOVERY_RESP,
    MSG_KEEPALIVE_RESP,
    PALLIGHT_DEBUG,
    XLINK_PORT,
)
from .protocol import (
    build_confirm,
    build_connect_request,
    build_discovery,
    build_discovery_search,
    build_keepalive,
    cmd_query,
    mac_str_to_bytes,
    parse_ack,
    parse_connect_response,
    parse_probe_response,
    parse_state_push,
)

_LOGGER = logging.getLogger(__name__)

ACK_RETRIES = 2

# ── Packet decoder for human-readable debug logs ──────────────────────────────

_MSG_NAMES = {
    0x13: "DISCOVERY",
    0x18: "DISCOVERY_RESP",
    0x23: "CONNECT_REQ",
    0x28: "CONNECT_RESP",
    0x33: "CONFIRM",
    0x50: "PROBE_RESP",
    0x80: "STATE_PUSH",
    0x83: "COMMAND",
    0x8B: "ACK",
    0xD3: "KEEPALIVE",
    0xD8: "KEEPALIVE_RESP",
}

_MODE_NAMES  = {0x01: "CONTROL", 0x02: "COLOUR"}
_ACTION_NAMES = {0x01: "ON", 0x02: "OFF", 0x03: "BRIGHT_UP", 0x04: "BRIGHT_DOWN"}


def _decode_packet(data: bytes, direction: str, addr: str = "") -> str:
    """
    Return a human-readable one-line summary of a packet for debug logging.
    Direction: '→ TX' or '← RX'
    """
    if not data:
        return f"{direction} (empty)"

    mt   = data[0]
    name = _MSG_NAMES.get(mt, f"UNKNOWN_0x{mt:02X}")
    raw  = data.hex(" ").upper()
    addr_str = f" {addr}" if addr else ""

    if mt == 0x83 and len(data) >= 22:
        token  = data[5]
        seq    = (data[7] << 8) | data[8]
        attr   = data[10]
        mode   = data[14]
        v15    = data[15]
        mode_s = _MODE_NAMES.get(mode, f"0x{mode:02X}")
        if mode == 0x01:
            act_s = _ACTION_NAMES.get(v15, f"0x{v15:02X}")
            detail = f"seq=0x{seq:04X} token=0x{token:02X} attr=0x{attr:02X} mode={mode_s} action={act_s}"
        elif mode == 0x02:
            hue = v15
            detail = f"seq=0x{seq:04X} token=0x{token:02X} attr=0x{attr:02X} mode={mode_s} hue=0x{hue:02X}({hue})"
        else:
            detail = f"seq=0x{seq:04X} token=0x{token:02X} attr=0x{attr:02X} mode={mode_s}"
        chk_computed = sum(data[10:21]) & 0xFF
        chk_actual   = data[21]
        chk_s = "chk=OK" if chk_actual == chk_computed else f"chk=BAD(got 0x{chk_actual:02X} want 0x{chk_computed:02X})"
        return f"{direction}{addr_str} {name} {detail} {chk_s} | {raw}"

    elif mt == 0x8B and len(data) >= 8:
        seq    = (data[5] << 8) | data[6]
        result = data[7]
        status = "ACCEPTED" if result == 0x00 else f"REJECTED(0x{result:02X})"
        return f"{direction}{addr_str} {name} seq=0x{seq:04X} {status} | {raw}"

    elif mt == 0x28 and len(data) >= 22:
        mac   = ":".join(f"{b:02X}" for b in data[7:13])
        token = data[19]
        return f"{direction}{addr_str} {name} mac={mac} session_token=0x{token:02X} | {raw}"

    elif mt == 0x33 and len(data) >= 8:
        token = data[5]
        return f"{direction}{addr_str} {name} echoed_token=0x{token:02X} | {raw}"

    elif mt == 0x50 and len(data) >= 12:
        mac      = ":".join(f"{b:02X}" for b in data[5:11])
        dev_info = data[11]
        return f"{direction}{addr_str} {name} mac={mac} device_info=0x{dev_info:02X} | {raw}"

    elif mt == 0x80 and len(data) >= 22:
        mac    = ":".join(f"{b:02X}" for b in data[5:11])
        attr   = data[14]
        bright = data[17]
        return f"{direction}{addr_str} {name} mac={mac} attr=0x{attr:02X} brightness_raw={bright} | {raw}"

    elif mt == 0x13 and len(data) >= 15:
        mac = ":".join(f"{b:02X}" for b in data[9:15])
        return f"{direction}{addr_str} {name} target_mac={mac} | {raw}"

    elif mt == 0x23 and len(data) >= 27:
        nonce = data[22:24].hex().upper()
        return f"{direction}{addr_str} {name} nonce={nonce} | {raw}"

    return f"{direction}{addr_str} {name} len={len(data)} | {raw}"


def _plog(mac: str, msg: str) -> None:
    """Log at INFO when PALLIGHT_DEBUG is on, otherwise swallow."""
    if PALLIGHT_DEBUG:
        _LOGGER.info("PalLight [%s] %s", mac, msg)


# ── XlinkSession ──────────────────────────────────────────────────────────────

class XlinkSession:
    """Manages a single Xlink local UDP session to one PalLight device."""

    def __init__(
        self,
        device_ip: str,
        device_mac: str,
        on_state_push: Callable[[dict], Any] | None = None,
        on_availability_changed: Callable[[bool], Any] | None = None,
    ) -> None:
        self.device_ip  = device_ip
        self.device_mac = device_mac

        self._on_state_push           = on_state_push
        self._on_availability_changed = on_availability_changed

        self._sock: socket.socket | None = None
        self._available = False
        self._closing   = False

        self._session_token_hi: int = 0x00  # 0x28[19]
        self._session_token_lo: int = 0x00  # 0x28[20] — NOT always 0x00
        # Start sequence from a random value in 0x1000-0xEFFF range.
        # The Xlink SDK persists sequence numbers between sessions — it never
        # resets to 0x0001. Devices with low seq values (< 0x1000) return
        # ACK byte[7]=0x01 (rejected) instead of 0x00 (accepted).
        self._sequence: int = int.from_bytes(__import__('os').urandom(2), 'big') | 0x1000

        self._pending_acks: dict[int, asyncio.Event] = {}
        self._recv_task: asyncio.Task | None = None

    @property
    def available(self) -> bool:
        return self._available

    @property
    def session_token_hi(self) -> int:
        return self._session_token_hi

    @property
    def session_token_lo(self) -> int:
        return self._session_token_lo

    # Keep backward-compat alias used in coordinator
    @property
    def session_token(self) -> int:
        return self._session_token_hi

    def next_sequence(self) -> int:
        seq = self._sequence
        self._sequence = (self._sequence + 1) & 0xFFFF
        return seq

    # ── Handshake ─────────────────────────────────────────────────────────────

    async def connect(self, reconnect: bool = True) -> bool:
        """Full Xlink UDP handshake. Returns True on success.

        reconnect=True (default) skips the 0x13/0x18 discovery phase.
        This is correct for all normal use — IP and MAC are already known
        from the config entry, and the device ignores 0x13 when in an
        active session. Set reconnect=False only for first-time discovery.
        """
        self._closing = False
        await self._close_socket()

        _LOGGER.info(
            "PalLight [%s] starting handshake → %s:%d",
            self.device_mac, self.device_ip, XLINK_PORT,
        )

        loop = asyncio.get_event_loop()

        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.setblocking(False)
            self._sock.bind(("", 0))
            our_port = self._sock.getsockname()[1]
            _LOGGER.info(
                "PalLight [%s] socket ready on ephemeral port %d",
                self.device_mac, our_port,
            )
        except OSError as exc:
            _LOGGER.error("PalLight [%s] socket open failed: %s", self.device_mac, exc)
            return False

        try:
            mac_bytes = mac_str_to_bytes(self.device_mac)
        except ValueError as exc:
            _LOGGER.error("PalLight [%s] bad MAC: %s", self.device_mac, exc)
            return False

        # ── Steps 2–4: 0x13/0x18 exchange (first connect only) ──────────────
        # On reconnect the device is in an active session and ignores new
        # 0x13 broadcasts — confirmed from logs. Skip straight to 0x23.
        # On first connect, send 0x13, wait for 0x18 (device ready signal),
        # retransmitting every DISCOVERY_RETRY_SECS until 0x18 arrives.
        import os as _os
        nonce = _os.urandom(2)

        if not reconnect:
            disc_frame, disc_nonce = build_discovery(mac_bytes)
            nonce = disc_nonce
            try:
                await loop.sock_sendto(self._sock, disc_frame, ("255.255.255.255", XLINK_PORT))
                _plog(self.device_mac, _decode_packet(disc_frame, "→ TX", "255.255.255.255:5987"))
            except OSError as exc:
                _LOGGER.error("PalLight [%s] 0x13 send failed: %s", self.device_mac, exc)
                return False

            _plog(self.device_mac, f"waiting for 0x18 (up to {CONNECT_TIMEOUT}s) ...")
            got_18 = False
            deadline_18 = loop.time() + CONNECT_TIMEOUT
            retransmit_at = loop.time() + DISCOVERY_RETRY_SECS

            while loop.time() < deadline_18:
                remaining = deadline_18 - loop.time()
                recv_timeout = min(remaining, max(0.05, retransmit_at - loop.time()))
                try:
                    data, addr = await asyncio.wait_for(
                        loop.sock_recvfrom(self._sock, 256), timeout=recv_timeout
                    )
                    _plog(self.device_mac,
                          _decode_packet(data, "← RX", f"{addr[0]}:{addr[1]}"))
                    if data and data[0] == MSG_DISCOVERY_RESP:
                        _LOGGER.info("PalLight [%s] 0x18 from %s — sending 0x23",
                                     self.device_mac, addr[0])
                        got_18 = True
                        break
                except asyncio.TimeoutError:
                    pass
                except Exception as exc:
                    _LOGGER.debug("PalLight [%s] recv error waiting for 0x18: %s",
                                  self.device_mac, exc)
                    break

                if loop.time() >= retransmit_at and not got_18:
                    _LOGGER.info("PalLight [%s] no 0x18 yet — retransmitting 0x13",
                                 self.device_mac)
                    try:
                        await loop.sock_sendto(self._sock, disc_frame, ("255.255.255.255", XLINK_PORT))
                    except OSError:
                        pass
                    retransmit_at = loop.time() + DISCOVERY_RETRY_SECS

            if not got_18:
                _LOGGER.warning("PalLight [%s] no 0x18 — attempting 0x23 anyway",
                                self.device_mac)
        else:
            _LOGGER.info("PalLight [%s] reconnect — skipping 0x13/0x18, going straight to 0x23",
                         self.device_mac)

        # ── Send 0x23 connect request ─────────────────────────────────────────
        connect_req = build_connect_request(nonce)
        try:
            await loop.sock_sendto(
                self._sock, connect_req, (self.device_ip, XLINK_PORT)
            )
            _plog(self.device_mac,
                  _decode_packet(connect_req, "→ TX", f"{self.device_ip}:{XLINK_PORT}"))
        except OSError as exc:
            _LOGGER.error("PalLight [%s] 0x23 send failed: %s", self.device_mac, exc)
            return False

        # ── Step 5: wait for 0x28 ─────────────────────────────────────────────
        _plog(self.device_mac, f"waiting for 0x28 (up to {CONNECT_TIMEOUT}s) ...")
        raw_28 = await self._wait_for_message(loop, 0x28, CONNECT_TIMEOUT)
        if raw_28 is None:
            _LOGGER.warning(
                "PalLight [%s] no 0x28 from %s within %.1fs — "
                "check device is on 192.168.2.x and reachable",
                self.device_mac, self.device_ip, CONNECT_TIMEOUT,
            )
            return False

        # Always log raw 0x28 bytes — essential for debugging token extraction
        _LOGGER.info(
            "PalLight [%s] RAW 0x28 (%d bytes): %s",
            self.device_mac, len(raw_28), raw_28.hex(" ").upper(),
        )
        _plog(self.device_mac, _decode_packet(raw_28, "← RX", f"{self.device_ip}:{XLINK_PORT}"))

        parsed_28 = parse_connect_response(raw_28)
        if parsed_28 is None:
            _LOGGER.warning(
                "PalLight [%s] could not parse 0x28 (len=%d) — raw: %s",
                self.device_mac, len(raw_28), raw_28.hex(" ").upper(),
            )
            return False

        self._session_token_hi = parsed_28["session_token_hi"]
        self._session_token_lo = parsed_28["session_token_lo"]
        _LOGGER.info(
            "PalLight [%s] 0x28 parsed — mac=%s response_code=0x%04X "
            "token=[0x%02X, 0x%02X] (byte[5] and byte[6] of all 0x83 commands)",
            self.device_mac,
            parsed_28["mac"],
            parsed_28["response_code"],
            self._session_token_hi,
            self._session_token_lo,
        )

        # ── Step 6: 0x33 confirm ──────────────────────────────────────────────
        confirm_frame = build_confirm(self._session_token_hi, self._session_token_lo)
        _LOGGER.info(
            "PalLight [%s] RAW 0x33 (%d bytes): %s",
            self.device_mac, len(confirm_frame), confirm_frame.hex(" ").upper(),
        )
        try:
            await loop.sock_sendto(
                self._sock, confirm_frame, (self.device_ip, XLINK_PORT)
            )
            _plog(self.device_mac,
                  _decode_packet(confirm_frame, "→ TX", f"{self.device_ip}:{XLINK_PORT}"))
        except OSError as exc:
            _LOGGER.error("PalLight [%s] 0x33 send failed: %s", self.device_mac, exc)
            return False

        # ── Step 7: wait for 0x50 (optional) ─────────────────────────────────
        raw_50 = await self._wait_for_message(loop, 0x50, 1.5)
        if raw_50:
            _LOGGER.info(
                "PalLight [%s] RAW 0x50 (%d bytes): %s",
                self.device_mac, len(raw_50), raw_50.hex(" ").upper(),
            )
            _plog(self.device_mac,
                  _decode_packet(raw_50, "← RX", f"{self.device_ip}:{XLINK_PORT}"))
        else:
            _LOGGER.warning(
                "PalLight [%s] no 0x50 received — proceeding without probe confirmation",
                self.device_mac,
            )

        # ── Step 8: ready ─────────────────────────────────────────────────────
        self._recv_task = asyncio.create_task(
            self._recv_loop(), name=f"pallight_recv_{self.device_mac}"
        )
        self._set_available(True)

        # Query state immediately
        q = cmd_query(self._session_token_hi, self._session_token_lo, self.next_sequence())
        await self._send_raw(q, label="initial state query")

        return True

    # ── Command send with ACK tracking ────────────────────────────────────────

    async def send_command_nowait(self, packet: bytes, label: str = "") -> bool:
        """
        Send a command without waiting for ACK — used for streaming colour drag.

        The native app sends colour commands continuously during wheel drag
        without waiting for acknowledgement. The device processes them in
        order and the last one wins. Not retried on failure.

        Returns True if the packet was sent, False if not connected.
        """
        if not self._available or self._sock is None:
            return False
        desc = _decode_packet(packet, "→ TX", f"{self.device_ip}:{XLINK_PORT}")
        if label:
            desc = f"[{label}] {desc}"
        _plog(self.device_mac, desc)
        await self._send_raw(packet)
        return True

    async def send_command(self, packet: bytes, label: str = "") -> bool:
        """Send a command and wait for 0x8B ACK. Retries ACK_RETRIES times."""
        if not self._available or self._sock is None:
            _LOGGER.warning(
                "PalLight [%s] send_command called but not connected "
                "(available=%s, sock=%s)",
                self.device_mac, self._available, self._sock is not None,
            )
            return False

        seq = (packet[7] << 8) | packet[8]
        ack_event  = asyncio.Event()
        ack_result = [0xFF]   # mutable container so recv_loop can set it

        # Register a waiter that also captures the result byte
        self._pending_acks[seq] = ack_event
        # Store a result slot keyed by seq so recv_loop can write result byte
        self._pending_results = getattr(self, '_pending_results', {})
        self._pending_results[seq] = ack_result

        desc = _decode_packet(packet, "→ TX", f"{self.device_ip}:{XLINK_PORT}")
        if label:
            desc = f"[{label}] {desc}"

        try:
            for attempt in range(1, ACK_RETRIES + 2):
                _plog(self.device_mac, f"attempt {attempt}: {desc}")
                await self._send_raw(packet)
                try:
                    await asyncio.wait_for(
                        asyncio.shield(ack_event.wait()), timeout=ACK_TIMEOUT
                    )
                    result = ack_result[0]
                    if result == 0x00:
                        _plog(self.device_mac,
                              f"ACK ACCEPTED seq=0x{seq:04X} (attempt {attempt})")
                        return True
                    else:
                        _LOGGER.warning(
                            "PalLight [%s] ACK REJECTED seq=0x%04X result=0x%02X "
                            "— device refused command (bad session/seq?)",
                            self.device_mac, seq, result,
                        )
                        return False
                except asyncio.TimeoutError:
                    if attempt <= ACK_RETRIES:
                        _LOGGER.warning(
                            "PalLight [%s] no ACK for seq=0x%04X — retry %d/%d",
                            self.device_mac, seq, attempt, ACK_RETRIES,
                        )
                        ack_event.clear()
                    else:
                        _LOGGER.warning(
                            "PalLight [%s] no ACK for seq=0x%04X after %d attempts — "
                            "marking unavailable",
                            self.device_mac, seq, ACK_RETRIES + 1,
                        )
                        self._set_available(False)
                        return False
        finally:
            self._pending_acks.pop(seq, None)
            self._pending_results.pop(seq, None)

        return False

    async def disconnect(self) -> None:
        self._closing = True
        if self._recv_task and not self._recv_task.done():
            self._recv_task.cancel()
            try:
                await self._recv_task  # wait for it to actually stop
            except asyncio.CancelledError:
                pass
        self._recv_task = None
        await self._close_socket()
        self._set_available(False)

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def _wait_for_message(
        self,
        loop: asyncio.AbstractEventLoop,
        expected_type: int,
        timeout: float,
    ) -> bytes | None:
        """Wait for a packet with msg_type == expected_type. Returns raw bytes or None."""
        assert self._sock is not None
        deadline = loop.time() + timeout
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            try:
                data, addr = await asyncio.wait_for(
                    loop.sock_recvfrom(self._sock, 256), timeout=remaining
                )
                if not data:
                    continue
                addr_str = f"{addr[0]}:{addr[1]}"
                _plog(self.device_mac,
                      _decode_packet(data, "← RX", addr_str)
                      + f"  (want 0x{expected_type:02X})")
                if data[0] == expected_type:
                    return data
                # Not the message we want — keep waiting, already logged above
            except asyncio.TimeoutError:
                break
            except Exception as exc:
                _LOGGER.debug(
                    "PalLight [%s] recv error waiting for 0x%02X: %s",
                    self.device_mac, expected_type, exc,
                )
                break
        return None

    async def _recv_loop(self) -> None:
        """Background receiver: dispatches ACKs and state pushes."""
        assert self._sock is not None
        loop = asyncio.get_event_loop()

        while not self._closing:
            try:
                data, addr = await asyncio.wait_for(
                    loop.sock_recvfrom(self._sock, 256), timeout=30.0
                )
            except asyncio.TimeoutError:
                if self._available:
                    ka = build_keepalive(self._session_token_hi, self._session_token_lo)
                    _plog(self.device_mac, "30s keepalive: " +
                          _decode_packet(ka, "→ TX", f"{self.device_ip}:{XLINK_PORT}"))
                    await self._send_raw(ka)
                continue
            except asyncio.CancelledError:
                return
            except Exception as exc:
                if not self._closing:
                    _LOGGER.warning(
                        "PalLight [%s] recv loop error: %s", self.device_mac, exc
                    )
                return

            if not data:
                continue

            mt       = data[0]
            addr_str = f"{addr[0]}:{addr[1]}"

            if mt == 0x8B:
                parsed_ack = parse_ack(data)
                if parsed_ack is not None:
                    seq, result = parsed_ack
                    _plog(self.device_mac,
                          _decode_packet(data, "← RX", addr_str))
                    if result != 0x00:
                        _LOGGER.warning(
                            "PalLight [%s] command seq=0x%04X REJECTED by device "
                            "(result=0x%02X) — session may be invalid",
                            self.device_mac, seq, result,
                        )
                    # Write result for send_command to read
                    pending_results = getattr(self, '_pending_results', {})
                    if seq in pending_results:
                        pending_results[seq][0] = result
                    event = self._pending_acks.get(seq)
                    if event:
                        event.set()
                    else:
                        _plog(self.device_mac,
                              f"  (no pending waiter for seq=0x{seq:04X})")

            elif mt == 0x80:
                _plog(self.device_mac,
                      _decode_packet(data, "← RX", addr_str))
                parsed = parse_state_push(data)
                if parsed:
                    # Always ACK the push regardless of attr_id
                    if len(data) >= 14:
                        ack = bytearray(8)
                        ack[0] = 0x8B
                        ack[4] = 0x03
                        ack[5] = data[11]
                        ack[6] = data[12]
                        await self._send_raw(bytes(ack), label="state-push ACK")
                    # Only forward non-SysTime pushes to the callback
                    if parsed.get("attr_id") == 0xA7:
                        _plog(self.device_mac,
                              f"  (0xA7 SysTime heartbeat — not forwarded)")
                    elif self._on_state_push:
                        try:
                            self._on_state_push(parsed)
                        except Exception as exc:
                            _LOGGER.error(
                                "PalLight [%s] state push callback error: %s",
                                self.device_mac, exc,
                            )

            elif mt == 0xD8:
                # Keepalive pong — just log it, no action needed
                _plog(self.device_mac,
                      _decode_packet(data, "← RX", addr_str))

            else:
                _plog(self.device_mac,
                      _decode_packet(data, "← RX (unhandled)", addr_str))

    async def _send_raw(self, data: bytes, label: str = "") -> None:
        if self._sock is None:
            return
        loop = asyncio.get_event_loop()
        try:
            await loop.sock_sendto(self._sock, data, (self.device_ip, XLINK_PORT))
            if label:
                _plog(self.device_mac,
                      f"[{label}] " +
                      _decode_packet(data, "→ TX", f"{self.device_ip}:{XLINK_PORT}"))
        except OSError as exc:
            _LOGGER.warning("PalLight [%s] send failed: %s", self.device_mac, exc)

    async def _close_socket(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def _set_available(self, value: bool) -> None:
        if value != self._available:
            self._available = value
            _LOGGER.info(
                "PalLight [%s] availability → %s", self.device_mac, value
            )
            if self._on_availability_changed:
                try:
                    self._on_availability_changed(value)
                except Exception as exc:
                    _LOGGER.error(
                        "PalLight [%s] availability callback error: %s",
                        self.device_mac, exc,
                    )


# ── Discovery ─────────────────────────────────────────────────────────────────

async def discover_devices(
    bind_ip: str = "",
    timeout: float = CONNECT_TIMEOUT,
) -> list[dict[str, str]]:
    """
    Discover PalLight devices — confirmed two-phase protocol.

    Phase 1 — Port 48899 (HF-A11 ASSISTHREAD):
      Broadcast b"HF-A11ASSISTHREAD" → 255.255.255.255:48899
      Device replies: "192.168.2.7,98D863E3CF80,HF-LPB100"
      This gives IP and MAC with zero prior knowledge.

    Phase 2 — Port 5987 (Xlink local):
      Send targeted 18-byte 0x13 with real MAC → 255.255.255.255:5987
      Device replies with 0x18, then complete 0x23/0x28 handshake.

    Confirmed from limitlessled_discovery.pcap:
      - Device (192.168.2.7) responds to HF-A11ASSISTHREAD on port 48899
      - Response format: "ip,MAC,model" e.g. "192.168.2.7,98D863E3CF80,HF-LPB100"
      - Device does NOT respond to "Link_Wi-Fi" (alternate probe, ignored)
    """
    import re as _re
    loop = asyncio.get_event_loop()
    results: list[dict[str, str]] = []
    seen_macs: set[str] = set()

    _LOGGER.info(
        "PalLight discovery: HF-A11ASSISTHREAD broadcast on port 48899 (bind_ip=%r)",
        bind_ip or "auto",
    )

    # ── Phase 1: HF-A11ASSISTHREAD on port 48899 ─────────────────────────────
    sock48 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock48.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock48.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock48.setblocking(False)
    try:
        sock48.bind((bind_ip, 48899))
        _LOGGER.info("PalLight discovery: phase 1 listening on port 48899")
    except OSError:
        # Port 48899 may be in use — fall back to ephemeral port
        try:
            sock48.bind((bind_ip, 0))
            _LOGGER.info("PalLight discovery: phase 1 on ephemeral port %d",
                         sock48.getsockname()[1])
        except OSError as exc:
            _LOGGER.error("PalLight discovery: phase 1 bind failed: %s", exc)
            sock48.close()
            return results

    candidates: list[dict[str, str]] = []
    deadline_p1 = loop.time() + min(timeout / 2, 6.0)
    retransmit_at = loop.time()  # send immediately first time

    while loop.time() < deadline_p1:
        if loop.time() >= retransmit_at:
            try:
                await loop.sock_sendto(sock48, DISCOVERY_MSG, ("255.255.255.255", 48899))
                _LOGGER.info("PalLight discovery: → TX 255.255.255.255:48899 %r", DISCOVERY_MSG)
            except OSError as exc:
                _LOGGER.error("PalLight discovery: phase 1 send failed: %s", exc)
                break
            retransmit_at = loop.time() + DISCOVERY_RETRY_SECS

        remaining = min(deadline_p1 - loop.time(), max(0.05, retransmit_at - loop.time()))
        try:
            data, addr = await asyncio.wait_for(
                loop.sock_recvfrom(sock48, 256), timeout=remaining
            )
            text = data.decode("ascii", errors="ignore").strip()
            src_ip = addr[0]
            _LOGGER.info("PalLight discovery: ← RX %s:48899 %r", src_ip, text)
            # Response format: "192.168.2.7,98D863E3CF80,HF-LPB100"
            parts = text.split(",")
            if len(parts) >= 2:
                ip  = parts[0].strip()
                raw_mac = parts[1].strip()
                clean = _re.sub(r"[^0-9a-fA-F]", "", raw_mac)
                if len(clean) == 12:
                    mac = ":".join(clean[i:i+2].upper() for i in range(0, 12, 2))
                    if mac not in seen_macs and ip not in ("0.0.0.0", ""):
                        seen_macs.add(mac)
                        model = parts[2].strip() if len(parts) > 2 else "unknown"
                        candidates.append({"ip": ip, "mac": mac, "model": model})
                        _LOGGER.info(
                            "PalLight discovery: phase 1 found IP=%s MAC=%s model=%s",
                            ip, mac, model,
                        )
        except asyncio.TimeoutError:
            pass
        except Exception as exc:
            _LOGGER.debug("PalLight discovery: phase 1 recv error: %s", exc)
            break

    sock48.close()

    if not candidates:
        _LOGGER.warning(
            "PalLight discovery: no devices responded to HF-A11ASSISTHREAD on port 48899. "
            "Check the device is powered on and the correct network interface is selected."
        )
        return results

    # ── Phase 2: targeted 0x13 handshake on port 5987 ────────────────────────
    _LOGGER.info(
        "PalLight discovery: phase 2 — confirming %d candidate(s) on port 5987",
        len(candidates),
    )

    sock57 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock57.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock57.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock57.setblocking(False)
    try:
        sock57.bind((bind_ip, 0))
    except OSError as exc:
        _LOGGER.error("PalLight discovery: phase 2 bind failed: %s", exc)
        sock57.close()
        # Still return phase 1 results — IP and MAC are known, handshake can
        # happen later when the coordinator connects
        for c in candidates:
            results.append({"ip": c["ip"], "mac": c["mac"]})
        return results

    for candidate in candidates:
        ip  = candidate["ip"]
        mac = candidate["mac"]

        try:
            mac_bytes = mac_str_to_bytes(mac)
        except ValueError:
            continue

        disc_frame, nonce = build_discovery(mac_bytes)
        try:
            await loop.sock_sendto(sock57, disc_frame, ("255.255.255.255", XLINK_PORT))
            _LOGGER.info("PalLight discovery: %s",
                         _decode_packet(disc_frame, "→ TX", "255.255.255.255:5987"))
        except OSError:
            continue

        # Wait for 0x18
        got_18 = False
        deadline_18 = loop.time() + 3.0
        retransmit_18 = loop.time() + DISCOVERY_RETRY_SECS

        while loop.time() < deadline_18:
            remaining = min(deadline_18 - loop.time(), max(0.05, retransmit_18 - loop.time()))
            try:
                data, addr = await asyncio.wait_for(
                    loop.sock_recvfrom(sock57, 256), timeout=remaining
                )
                _LOGGER.info("PalLight discovery: %s",
                             _decode_packet(data, "← RX", f"{addr[0]}:{addr[1]}"))
                if data and data[0] == MSG_DISCOVERY_RESP:
                    got_18 = True
                    break
            except asyncio.TimeoutError:
                pass
            except Exception:
                break

            if loop.time() >= retransmit_18 and not got_18:
                try:
                    await loop.sock_sendto(sock57, disc_frame, ("255.255.255.255", XLINK_PORT))
                except OSError:
                    pass
                retransmit_18 = loop.time() + DISCOVERY_RETRY_SECS

        if not got_18:
            _LOGGER.warning(
                "PalLight discovery: no 0x18 from %s (%s) — adding anyway (phase 1 confirmed)",
                ip, mac,
            )
            # Phase 1 already confirmed the device — add it even without 0x18
            results.append({"ip": ip, "mac": mac})
            continue

        # Send 0x23 and wait for 0x28
        connect_req = build_connect_request(nonce)
        try:
            await loop.sock_sendto(sock57, connect_req, (ip, XLINK_PORT))
            _LOGGER.info("PalLight discovery: %s",
                         _decode_packet(connect_req, "→ TX", f"{ip}:{XLINK_PORT}"))
        except OSError:
            results.append({"ip": ip, "mac": mac})
            continue

        deadline_28 = loop.time() + 3.0
        confirmed = False
        while loop.time() < deadline_28:
            remaining = deadline_28 - loop.time()
            if remaining <= 0: break
            try:
                data, addr = await asyncio.wait_for(
                    loop.sock_recvfrom(sock57, 256), timeout=remaining
                )
                _LOGGER.info("PalLight discovery: %s",
                             _decode_packet(data, "← RX", f"{addr[0]}:{addr[1]}"))
                if data and data[0] == 0x28:
                    _LOGGER.info("PalLight discovery: fully confirmed IP=%s MAC=%s", ip, mac)
                    results.append({"ip": ip, "mac": mac})
                    confirmed = True
                    break
            except asyncio.TimeoutError:
                break
            except Exception:
                break

        if not confirmed:
            # Phase 1 was enough — add it
            results.append({"ip": ip, "mac": mac})

    sock57.close()

    if not results:
        _LOGGER.warning("PalLight discovery: no devices confirmed.")
    return results


async def discover_by_device_id(
    device_id: str,
    bind_ip: str = "",
    timeout: float = CONNECT_TIMEOUT,
) -> dict[str, str] | None:
    """
    Discover a device by Xlink device ID (alternative to HF-A11ASSISTHREAD).

    Sends a 41-byte 0x13 containing the device ID. The device responds with
    0x18 containing its MAC. Used by the config flow as a fallback when the
    user knows their device ID from the SZiRain app.
    """
    loop = asyncio.get_event_loop()

    clean_id = device_id.strip().replace("-", "").replace(" ", "").lower()
    if len(clean_id) != 32 or not all(c in "0123456789abcdef" for c in clean_id):
        _LOGGER.error("PalLight: invalid device ID %r", device_id)
        return None

    id_bytes = clean_id.encode("ascii")
    _LOGGER.info("PalLight discovery: search by device ID %s (bind_ip=%r)", clean_id, bind_ip or "auto")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setblocking(False)
    try:
        sock.bind((bind_ip, 0))
    except OSError as exc:
        _LOGGER.error("PalLight: bind failed: %s", exc)
        sock.close()
        return None

    search_frame, nonce = build_discovery_search(id_bytes)
    try:
        await loop.sock_sendto(sock, search_frame, ("255.255.255.255", XLINK_PORT))
        _LOGGER.info("PalLight discovery: %s", _decode_packet(search_frame, "→ TX", "255.255.255.255:5987"))
    except OSError as exc:
        _LOGGER.error("PalLight: broadcast failed: %s", exc)
        sock.close()
        return None

    found = None
    deadline = loop.time() + timeout
    retransmit_at = loop.time() + DISCOVERY_RETRY_SECS

    while loop.time() < deadline:
        remaining = min(deadline - loop.time(), max(0.05, retransmit_at - loop.time()))
        try:
            data, addr = await asyncio.wait_for(
                loop.sock_recvfrom(sock, 256), timeout=remaining
            )
            _LOGGER.info("PalLight discovery: %s", _decode_packet(data, "← RX", f"{addr[0]}:{addr[1]}"))
            if data and data[0] == MSG_DISCOVERY_RESP and len(data) >= 12:
                mac = ":".join(f"{b:02X}" for b in data[6:12])
                found = {"ip": addr[0], "mac": mac}
                break
        except asyncio.TimeoutError:
            pass
        except Exception:
            break

        if loop.time() >= retransmit_at and not found:
            try:
                await loop.sock_sendto(sock, search_frame, ("255.255.255.255", XLINK_PORT))
            except OSError:
                pass
            retransmit_at = loop.time() + DISCOVERY_RETRY_SECS

    sock.close()
    if not found:
        _LOGGER.warning("PalLight: no response for device ID %s", clean_id)
    return found


async def discover_by_mac(
    mac: str,
    bind_ip: str = "",
    timeout: float = CONNECT_TIMEOUT,
) -> str | None:
    """Find the IP for a known MAC via HF-A11ASSISTHREAD discovery."""
    devices = await discover_devices(bind_ip=bind_ip, timeout=timeout)
    for dev in devices:
        if dev["mac"].upper().replace(":", "") == mac.upper().replace(":", ""):
            return dev["ip"]
    return None
