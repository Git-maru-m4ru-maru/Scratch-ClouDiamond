"""A tiny command router for text protocols (``"score add 10"`` -> ``handler(ctx)``).

Use it as the ``handler`` of :class:`SecureServer`::

    router = Router()

    @router.command("add")
    def add(ctx):
        return str(sum(int(x) for x in ctx.args))

    server = SecureServer(key, handler=router)

The Scratch client sends text such as ``add 1 2 3``. Replies that are ``str`` are converted with the
Scratch text table (lowercase, unsupported characters become ``?``) so what you return is what the
Scratch side will show.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable

from . import text as scratch_text
from .server import Session

__all__ = ["Router", "Context"]

log = logging.getLogger("cloudiamond_scratch")


@dataclass
class Context:
    session: Session
    command: str
    args: list[str]
    text: str                       # the whole message (decoded)
    raw: bytes = field(repr=False)  # the whole message (bytes)

    @property
    def user(self):
        return self.session.user


class Router:
    """Dispatch ``"<command> <arg> <arg> ..."`` messages.

    ``unknown``: reply for an unknown command (``None`` = stay silent, the safest default for a
    server on a shared channel). ``error``: reply when a handler raises (details are only logged,
    never sent to the client).
    """

    def __init__(self, *, unknown: str | None = "error unknown", error: str | None = "error",
                 denied: str | None = "error login", max_args: int = 16):
        self._cmds: dict[str, tuple[Callable[[Context], Any], bool, int, int | None]] = {}
        self.unknown, self.error, self.denied = unknown, error, denied
        self.max_args = max_args

    def command(self, name: str | None = None, *, login: bool = False, min_args: int = 0,
                max_args: int | None = None):
        """Register a handler. ``login=True`` requires ``session.user`` to be set (see ``auth``).
        ``min_args`` / ``max_args`` are checked before the handler runs (violations get the ``error`` reply)."""
        def deco(fn: Callable[[Context], Any]):
            key = (name or fn.__name__).lower()
            if key in self._cmds:
                raise ValueError(f"command {key!r} already registered")
            self._cmds[key] = (fn, login, min_args, max_args)
            return fn
        return deco

    @property
    def commands(self) -> list[str]:
        return sorted(self._cmds)

    def __call__(self, session: Session, data: bytes) -> bytes | None:
        body = scratch_text.decode(data)
        parts = body.split()
        if not parts or len(parts) > self.max_args + 1:
            return self._reply(self.unknown)
        cmd, args = parts[0].lower(), parts[1:]
        entry = self._cmds.get(cmd)
        if entry is None:
            return self._reply(self.unknown)
        fn, login, lo, hi = entry
        if login and session.user is None:
            return self._reply(self.denied)
        if len(args) < lo or (hi is not None and len(args) > hi):
            return self._reply(self.error)
        try:
            out = fn(Context(session, cmd, args, body, data))
        except Exception:  # noqa: BLE001 - never leak internals to the client
            log.exception("command %r failed", cmd)
            return self._reply(self.error)
        return self._reply(out)

    @staticmethod
    def _reply(out: Any) -> bytes | None:
        if out is None:
            return None
        if isinstance(out, str):
            return scratch_text.encode(out)
        if isinstance(out, (bytes, bytearray)):
            return bytes(out)
        return scratch_text.encode(str(out))
