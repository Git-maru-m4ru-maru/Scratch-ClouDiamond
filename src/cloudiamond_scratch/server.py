"""``SecureServer``: the protocol state machine (no I/O, no cloud-variable knowledge).

Feed it received frames with :meth:`SecureServer.handle_frame`; it returns the frame to send
back (or ``None``). Anything invalid is dropped silently (and counted in ``stats``): the
shared cloud variables are writable by everybody, so garbage is normal and must never
produce an observable reaction.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Callable

from . import protocol as P
from .crypto import (CryptoError, READY, aead_open, aead_seal, derive_keys, fingerprint,
                     generate_secret, x25519_public, x25519_shared)
from .keys import parse_secret

__all__ = ["SecureServer", "Session", "TokenBucket", "MessageTooLarge", "UnknownSession"]

log = logging.getLogger("cloudiamond_scratch")



class MessageTooLarge(ValueError):
    """The message does not fit in one frame (max ``protocol.MAX_MESSAGE`` bytes)."""


class UnknownSession(KeyError):
    """No such session (never existed, expired, or evicted)."""


class TokenBucket:
    """Simple token bucket. ``rate`` tokens/second, up to ``burst`` stored."""

    __slots__ = ("rate", "burst", "tokens", "stamp")

    def __init__(self, rate: float, burst: float, now: float):
        self.rate, self.burst, self.tokens, self.stamp = float(rate), float(burst), float(burst), now

    def allow(self, now: float, cost: float = 1.0) -> bool:
        self.tokens = min(self.burst, self.tokens + max(0.0, now - self.stamp) * self.rate)
        self.stamp = now
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        return False


@dataclass(eq=False)
class Session:
    """One authenticated-by-key-agreement client session. Key material is excluded from ``repr``."""

    sid: bytes
    client_public: bytes = field(repr=False)
    k_c2s: bytes = field(repr=False)
    k_s2c: bytes = field(repr=False)
    reply_frame: bytes = field(repr=False)
    created: float
    last_seen: float
    bucket: TokenBucket = field(repr=False)
    recv_last: int = 0
    send_ctr: int = 0
    confirmed: bool = False     # a valid data frame was received (proves the client got our reply)
    user: Any = None            # free for the application (e.g. the logged-in user)
    data: dict = field(default_factory=dict)  # free for the application

    @property
    def sid_hex(self) -> str:
        return self.sid.hex()


class SecureServer:
    """Server side of the protocol.

    Parameters
    ----------
    static_key:
        The server's long-term X25519 secret (32 bytes / hex / base64 / ``load_or_create_static_key``).
    on_message:
        ``f(sid: bytes, data: bytes) -> bytes | str | None`` (the 0.1 style). A returned value is
        encrypted and sent back; ``None`` means no reply.
    handler:
        Alternative to ``on_message``: ``f(session: Session, data: bytes) -> bytes | str | None``.
    on_connect / on_close:
        ``on_connect(session)`` when a client's first valid message proves the handshake,
        ``on_close(session, reason)`` with reason ``"expired" | "evicted" | "closed"``.
    max_sessions, session_ttl, handshake_ttl:
        Capacity and idle timeouts in seconds. Sessions that never sent a valid message
        (``confirmed == False``) are evicted first and expire after ``handshake_ttl``.
    hello_rate / hello_burst, message_rate / message_burst, frame_rate / frame_burst:
        Token-bucket limits (per second): new handshakes (global), messages per session,
        and all incoming frames (global CPU guard).
    """

    def __init__(
        self,
        static_key: bytes | str,
        on_message: Callable[[bytes, bytes], Any] | None = None,
        *,
        handler: Callable[[Session, bytes], Any] | None = None,
        on_connect: Callable[[Session], None] | None = None,
        on_close: Callable[[Session, str], None] | None = None,
        max_sessions: int = 1000,
        session_ttl: float = 3600.0,
        handshake_ttl: float = 120.0,
        hello_rate: float = 5.0,
        hello_burst: float = 20.0,
        message_rate: float = 5.0,
        message_burst: float = 10.0,
        frame_rate: float = 200.0,
        frame_burst: float = 400.0,
        clock: Callable[[], float] = time.monotonic,
    ):
        if on_message is not None and handler is not None:
            raise ValueError("give either on_message or handler, not both")
        self._s = parse_secret(static_key)
        self.public_key = x25519_public(self._s)
        self.fingerprint = fingerprint(self.public_key)
        self._on_message = on_message
        self._handler = handler
        self._on_connect = on_connect
        self._on_close = on_close
        self.max_sessions = max_sessions
        self.session_ttl = session_ttl
        self.handshake_ttl = handshake_ttl
        self._clock = clock
        now = clock()
        self._hello_bucket = TokenBucket(hello_rate, hello_burst, now)
        self._frame_bucket = TokenBucket(frame_rate, frame_burst, now)
        self._message_rate, self._message_burst = message_rate, message_burst
        self._sessions: dict[bytes, Session] = {}
        self._lock = threading.RLock()
        self._last_sweep = now
        self.stats: Counter[str] = Counter()

    # ------------------------------------------------------------------ public
    @property
    def sessions(self) -> list[Session]:
        with self._lock:
            return list(self._sessions.values())

    def get_session(self, sid: bytes | str) -> Session | None:
        key = bytes.fromhex(sid) if isinstance(sid, str) else sid
        with self._lock:
            return self._sessions.get(key)

    def close_session(self, sid: bytes | str, reason: str = "closed") -> bool:
        key = bytes.fromhex(sid) if isinstance(sid, str) else sid
        with self._lock:
            s = self._sessions.get(key)
            if s is None:
                return False
            self._drop_session(s, reason)
            return True

    def sweep(self) -> int:
        """Remove expired sessions now. Returns how many were removed."""
        with self._lock:
            return self._sweep(self._clock(), force=True)

    def handle_frame(self, frame: bytes) -> bytes | None:
        """Process one received frame. Returns a frame to send back, or ``None``."""
        with self._lock:
            now = self._clock()
            self._sweep(now)
            if not self._frame_bucket.allow(now):
                return self._drop("frame_rate")
            if not isinstance(frame, (bytes, bytearray)) or not 9 <= len(frame) <= P.MAX_FRAME:
                return self._drop("bad_length")
            frame = bytes(frame)
            kind = frame[8]
            if kind == P.T_HELLO:
                return self._on_hello(frame, now)
            if kind == P.T_C2S:
                return self._on_data(frame, now)
            return self._drop("bad_type")

    def seal(self, sid: bytes | str, data: bytes | str) -> bytes:
        """Encrypt a server-initiated message for ``sid`` and return the frame to send."""
        key = bytes.fromhex(sid) if isinstance(sid, str) else sid
        with self._lock:
            s = self._sessions.get(key)
            if s is None:
                raise UnknownSession(key.hex())
            frame = self._seal(s, _as_bytes(data))
            self.stats["push"] += 1
            return frame

    # ----------------------------------------------------------------- internals
    def _drop(self, reason: str) -> None:
        self.stats["drop." + reason] += 1
        log.debug("dropped frame: %s", reason)
        return None

    def _drop_session(self, s: Session, reason: str) -> None:
        self._sessions.pop(s.sid, None)
        self.stats["session_" + reason] += 1
        if self._on_close is not None and s.confirmed:
            try:
                self._on_close(s, reason)
            except Exception:  # noqa: BLE001 - user callback must not break the server
                log.exception("on_close callback failed")

    def _sweep(self, now: float, force: bool = False) -> int:
        if not force and now - self._last_sweep < 1.0:
            return 0
        self._last_sweep = now
        dead = [s for s in self._sessions.values()
                if now - s.last_seen > (self.session_ttl if s.confirmed else self.handshake_ttl)]
        for s in dead:
            self._drop_session(s, "expired")
        return len(dead)

    def _make_room(self) -> bool:
        if len(self._sessions) < self.max_sessions:
            return True
        pending = [s for s in self._sessions.values() if not s.confirmed]
        pool = pending or list(self._sessions.values())
        victim = min(pool, key=lambda s: s.last_seen if s.confirmed else s.created)
        self._drop_session(victim, "evicted")
        return True

    def _on_hello(self, frame: bytes, now: float) -> bytes | None:
        if len(frame) != P.HELLO_LEN:
            return self._drop("bad_length")
        sid, e = frame[:P.SID_LEN], frame[9:41]
        if sid != e[:P.SID_LEN]:
            return self._drop("bad_sid")
        existing = self._sessions.get(sid)
        if existing is not None:
            if existing.client_public == e:       # the client retried: repeat our (public) answer
                self.stats["hello_retransmit"] += 1
                return existing.reply_frame
            return self._drop("sid_collision")     # never let a newcomer replace a live session
        if not self._hello_bucket.allow(now):
            return self._drop("hello_rate")
        try:
            dh_es = x25519_shared(self._s, e)
            r = generate_secret()                  # one-time key: not stored anywhere
            big_r = x25519_public(r)
            dh_ee = x25519_shared(r, e)
        except CryptoError:
            return self._drop("bad_point")
        _master, k_c2s, k_s2c = derive_keys(dh_es, dh_ee)
        del r, dh_es, dh_ee, _master
        aad = sid + bytes([P.T_REPLY]) + e + big_r
        reply = sid + bytes([P.T_REPLY]) + big_r + aead_seal(k_s2c, b"\0" * 12, aad, READY)
        self._make_room()
        self._sessions[sid] = Session(
            sid=sid, client_public=e, k_c2s=k_c2s, k_s2c=k_s2c, reply_frame=reply,
            created=now, last_seen=now, bucket=TokenBucket(self._message_rate, self._message_burst, now))
        self.stats["hello"] += 1
        self.stats["session_new"] += 1
        return reply

    def _on_data(self, frame: bytes, now: float) -> bytes | None:
        n = len(frame)
        if n < P.HEADER_LEN + P.BLOCK + P.TAG_LEN or (n - P.HEADER_LEN - P.TAG_LEN) % P.BLOCK:
            return self._drop("bad_length")
        s = self._sessions.get(frame[:P.SID_LEN])
        if s is None:
            return self._drop("unknown_session")
        ctr = int.from_bytes(frame[9:15], "big")
        if ctr <= s.recv_last:
            return self._drop("replay")
        plain = aead_open(s.k_c2s, P.data_nonce(ctr), frame[:P.HEADER_LEN], frame[P.HEADER_LEN:])
        if plain is None:
            return self._drop("auth")
        s.recv_last = ctr                          # only authenticated frames move the counter
        s.last_seen = now
        first = not s.confirmed
        s.confirmed = True
        msg = P.unpad_message(plain)
        if msg is None:
            return self._drop("bad_payload")
        if first and self._on_connect is not None:
            try:
                self._on_connect(s)
            except Exception:  # noqa: BLE001
                log.exception("on_connect callback failed")
        if not s.bucket.allow(now):
            return self._drop("message_rate")
        self.stats["data"] += 1
        try:
            if self._handler is not None:
                result = self._handler(s, msg)
            elif self._on_message is not None:
                result = self._on_message(s.sid, msg)
            else:
                result = None
        except Exception:  # noqa: BLE001 - a buggy handler must not kill the server
            self.stats["handler_error"] += 1
            log.exception("message handler failed")
            return None
        if result is None:
            return None
        try:
            out = self._seal(s, _as_bytes(result))
        except MessageTooLarge:
            self.stats["reply_too_large"] += 1
            log.warning("reply dropped: longer than %d bytes", P.MAX_MESSAGE)
            return None
        except TypeError:
            self.stats["handler_error"] += 1
            log.error("handler returned %s; a reply must be bytes, str or None", type(result).__name__)
            return None
        self.stats["reply"] += 1
        return out

    def _seal(self, s: Session, data: bytes) -> bytes:
        if len(data) > P.MAX_MESSAGE:
            raise MessageTooLarge(f"{len(data)} bytes > {P.MAX_MESSAGE}")
        ctr = s.send_ctr + 1
        if ctr > P.CTR_MAX:
            self._drop_session(s, "closed")
            raise UnknownSession(s.sid.hex())
        header = s.sid + bytes([P.T_S2C]) + ctr.to_bytes(6, "big")
        frame = header + aead_seal(s.k_s2c, P.data_nonce(ctr), header, P.pad_message(data))
        s.send_ctr = ctr
        return frame

    def __repr__(self) -> str:
        return f"<SecureServer fp={self.fingerprint[:19]}... sessions={len(self._sessions)}>"


def _as_bytes(x: Any) -> bytes:
    if isinstance(x, (bytes, bytearray)):
        return bytes(x)
    if isinstance(x, str):
        return x.encode("utf-8")
    raise TypeError(f"message must be bytes or str, not {type(x).__name__}")
