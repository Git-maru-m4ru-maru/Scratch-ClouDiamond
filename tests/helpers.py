import _setup  # noqa: F401
from cloudiamond_scratch import SecureServer, generate_static_key, public_key


class Clock:
    """Fake monotonic clock."""

    def __init__(self, t: float = 1000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt


def new_server(**kw):
    secret = generate_static_key()
    kw.setdefault("on_message", lambda sid, d: b"re:" + d)
    return secret, SecureServer(secret, **kw)
