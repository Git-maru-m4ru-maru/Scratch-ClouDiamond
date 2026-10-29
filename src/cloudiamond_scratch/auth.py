"""Password helpers for logins over the encrypted channel.

The channel protects the password on the wire; these helpers protect it at rest and slow down guessing.
Remember what Scratch can type: lowercase letters, digits and punctuation only (see ``text``), so a
Scratch password has a smaller alphabet than usual. Make it long.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import time
from collections import defaultdict, deque
from typing import Callable, Deque

__all__ = ["hash_password", "verify_password", "LoginThrottle"]

_N, _R, _P = 2 ** 14, 8, 1


def hash_password(password: str, *, n: int = _N, r: int = _R, p: int = _P) -> str:
    """scrypt hash with a random 16-byte salt: ``scrypt$n$r$p$salt$hash`` (base64)."""
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=32, maxmem=128 * n * r * 2 + (1 << 20))
    b64 = lambda b: base64.b64encode(b).decode("ascii")  # noqa: E731
    return f"scrypt${n}${r}${p}${b64(salt)}${b64(dk)}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time check. Returns ``False`` (never raises) for a malformed ``stored`` value."""
    if not isinstance(stored, str) or not isinstance(password, str):
        return False
    try:
        scheme, n, r, p, salt, want = stored.split("$")
        if scheme != "scrypt":
            return False
        n, r, p = int(n), int(r), int(p)
        if n > 2 ** 20 or r > 32 or p > 16 or n < 2 or n & (n - 1):   # refuse absurd costs from a corrupt record
            return False
        dk = hashlib.scrypt(password.encode("utf-8"), salt=base64.b64decode(salt), n=n, r=r, p=p,
                            dklen=32, maxmem=128 * n * r * 2 + (1 << 20))
        return hmac.compare_digest(dk, base64.b64decode(want))
    except (ValueError, TypeError):
        return False


class LoginThrottle:
    """Allow at most ``max_failures`` failed logins per ``window`` seconds per key (a username, say);
    after that the key is locked for ``lockout`` seconds. Call :meth:`allowed` before checking a password."""

    def __init__(self, max_failures: int = 5, window: float = 300.0, lockout: float = 300.0,
                 clock: Callable[[], float] = time.monotonic):
        self.max_failures, self.window, self.lockout, self._clock = max_failures, window, lockout, clock
        self._fails: dict[str, Deque[float]] = defaultdict(deque)
        self._locked: dict[str, float] = {}

    def allowed(self, key: str) -> bool:
        now = self._clock()
        until = self._locked.get(key)
        if until is not None:
            if now < until:
                return False
            del self._locked[key]
            self._fails.pop(key, None)
        return True

    def failure(self, key: str) -> None:
        now = self._clock()
        q = self._fails[key]
        q.append(now)
        while q and now - q[0] > self.window:
            q.popleft()
        if len(q) >= self.max_failures:
            self._locked[key] = now + self.lockout

    def success(self, key: str) -> None:
        self._fails.pop(key, None)
        self._locked.pop(key, None)
