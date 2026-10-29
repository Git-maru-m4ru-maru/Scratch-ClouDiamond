"""Glue between cloud variables and :class:`SecureServer`.

``BridgeCore`` is a pure state machine (no I/O): feed it cloud-variable updates, it returns
the variable writes to perform. ``CloudBridge`` is the simple callback wrapper
(``write(name, value)``) that 0.1 users know; the asyncio runner in ``transport`` uses the core
directly so it can pace frames.

Ordering contract (same as the Scratch client): **all slots are written first, then the HDR**,
and the HDR value changes on every frame.
"""
from __future__ import annotations

import logging
import secrets
import threading
import time
from typing import Callable

from . import protocol as P
from .server import SecureServer, UnknownSession

__all__ = ["BridgeCore", "CloudBridge", "Frame"]

log = logging.getLogger("cloudiamond_scratch")

#: one frame on the wire = ordered writes ``[(variable name, value), ...]`` (slots, then HDR)


def short_name(name: str) -> str:
    """``"☁ C2S_HDR"`` / ``"C2S_HDR"`` -> ``"C2S_HDR"``."""
    return name.replace("\u2601", "").strip()


class BridgeCore:
    def __init__(self, server: SecureServer, *, prefix: str = P.CLOUD_PREFIX, seq_start: int | None = None):
        self.server = server
        self.prefix = prefix
        self._vals: dict[str, str] = {}           # last known value of each cloud variable
        self._seq = (secrets.randbelow(900_000) + 1) if seq_start is None else seq_start
        self._lock = threading.RLock()

    # -- input -------------------------------------------------------------------------
    def feed(self, name: str, value: object, *, initial: bool = False) -> list[list[tuple[str, str]]]:
        """A cloud variable changed. Returns the frames (lists of writes) to send in response.

        ``initial=True`` marks values replayed by the cloud server when we connect: they are
        remembered but not processed, so a stale ``C2S`` frame is not handled a second time.
        """
        short = short_name(name)
        if short not in P.CLOUD_VARIABLES:
            return []
        with self._lock:
            self._vals[short] = value if isinstance(value, str) else _num_to_str(value)
            if initial or short != P.VAR_C2S_HDR:
                return []
            parsed = P.parse_hdr(self._vals[short])
            if parsed is None:
                self.server.stats["drop.bad_hdr"] += 1
                return []
            _seq, n = parsed
            frame = P.slots_to_frame([self._vals.get(v, "") for v in P.VAR_C2S[:n]])
            if frame is None:
                self.server.stats["drop.bad_slots"] += 1
                return []
            out = self.server.handle_frame(frame)
            return [self._writes(out)] if out is not None else []

    def push(self, sid: bytes | str, data: bytes | str) -> list[list[tuple[str, str]]]:
        """Server-initiated message. Returns the frame to send (raises ``UnknownSession`` / ``MessageTooLarge``)."""
        with self._lock:
            return [self._writes(self.server.seal(sid, data))]

    # -- output ------------------------------------------------------------------------
    def _writes(self, frame: bytes) -> list[tuple[str, str]]:
        slots = P.frame_to_slots(frame)
        writes = [(self.prefix + P.VAR_S2C[i], s) for i, s in enumerate(slots)]
        self._seq = (self._seq + 1) % 1_000_000
        hdr = P.make_hdr(self._seq, len(slots))
        if str(hdr) == self._vals.get(P.VAR_S2C_HDR):   # must differ from what the client last saw
            self._seq = (self._seq + 1) % 1_000_000
            hdr = P.make_hdr(self._seq, len(slots))
        self._vals[P.VAR_S2C_HDR] = str(hdr)
        for i, s in enumerate(slots):
            self._vals[P.VAR_S2C[i]] = s
        writes.append((self.prefix + P.VAR_S2C_HDR, str(hdr)))
        return writes


class CloudBridge:
    """Callback-style bridge (API of 0.1).

    ``write(name, value)`` must set a cloud variable (``name`` includes the ``"☁ "`` prefix).
    Call :meth:`on_variable` for every cloud-variable update you observe.
    ``min_interval`` (seconds) spaces consecutive frames: a Scratch client that polls slowly can
    miss a frame that is overwritten too soon. 0.25 is a good value for real cloud servers.
    """

    def __init__(self, server: SecureServer, write: Callable[[str, str], None], *,
                 min_interval: float = 0.0, prefix: str = P.CLOUD_PREFIX,
                 clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep):
        self.server = server
        self.core = BridgeCore(server, prefix=prefix)
        self._write = write
        self._gap = min_interval
        self._clock, self._sleep = clock, sleep
        self._last_frame = float("-inf")
        self._out_lock = threading.Lock()

    def on_variable(self, name: str, value: object, *, initial: bool = False) -> None:
        for frame in self.core.feed(name, value, initial=initial):
            self._emit(frame)

    def push(self, sid: bytes | str, data: bytes | str) -> None:
        """Send a server-initiated message to ``sid`` (``UnknownSession`` if it is gone)."""
        for frame in self.core.push(sid, data):
            self._emit(frame)

    def _emit(self, frame: list[tuple[str, str]]) -> None:
        with self._out_lock:                       # frames must never interleave
            wait = self._gap - (self._clock() - self._last_frame)
            if wait > 0:
                self._sleep(wait)
            for name, value in frame:
                self._write(name, value)
            self._last_frame = self._clock()


def _num_to_str(v: object) -> str:
    if isinstance(v, float) and v == int(v):
        return str(int(v))
    return str(v)
