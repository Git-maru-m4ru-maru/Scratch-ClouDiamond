"""Server long-term key handling."""
from __future__ import annotations

import base64
import binascii
import os
import re
import stat
import tempfile
import warnings
from pathlib import Path

from .crypto import CryptoError, fingerprint, generate_secret, x25519_public

__all__ = [
    "KeyPermissionWarning", "generate_static_key", "public_key", "parse_secret", "parse_public",
    "load_static_key", "load_or_create_static_key", "save_static_key", "key_from_env", "fingerprint",
    "is_demo_key", "DEMO_PUBLIC_KEY_HEX",
]

ENV_VAR = "CLOUDIAMOND_SERVER_KEY"

#: Public half of ``examples/demo_server.key``. That private key is published in the repository, so a
#: server using it is NOT secure; the CLI warns when it sees this key.
DEMO_PUBLIC_KEY_HEX = "7b33ef8d2a03f0eba8b5fe6f12a23c899f305e57b317cad019225f9f67d16656"
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


class KeyPermissionWarning(UserWarning):
    """The key file can be read by other users."""


def generate_static_key() -> bytes:
    return generate_secret()


def public_key(secret: bytes) -> bytes:
    return x25519_public(secret)


def parse_secret(data: bytes | str) -> bytes:
    """Accepts 32 raw bytes, 64 hex characters, or base64 (comment lines starting with ``#`` are ignored)."""
    if isinstance(data, bytes) and len(data) == 32:
        return data
    text = data.decode("utf-8", "strict") if isinstance(data, bytes) else data
    body = "".join(ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#"))
    body = body.replace(" ", "").replace(":", "")
    if _HEX64.match(body):
        return bytes.fromhex(body)
    try:
        raw = base64.b64decode(body, validate=True)
    except (binascii.Error, ValueError):
        raw = b""
    if len(raw) == 32:
        return raw
    raise CryptoError("not a valid X25519 secret key (expected 32 bytes: raw, 64 hex chars, or base64)")


def parse_public(text: str | bytes) -> bytes:
    """64 hex characters (spaces, colons and dashes allowed) -> 32 bytes."""
    if isinstance(text, bytes):
        if len(text) == 32:
            return text
        text = text.decode("ascii", "strict")
    body = re.sub(r"[\s:\-]", "", text)
    if not _HEX64.match(body):
        raise CryptoError("a public key is 64 hexadecimal characters")
    return bytes.fromhex(body)


def _check_permissions(path: Path, strict: bool) -> None:
    if os.name != "posix":
        return
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        msg = (f"{path} is readable by other users (mode {mode:o}); run: chmod 600 {path}")
        if strict:
            raise PermissionError(msg)
        warnings.warn(msg, KeyPermissionWarning, stacklevel=3)


def load_static_key(path: str | os.PathLike, *, strict: bool = False) -> bytes:
    p = Path(path)
    secret = parse_secret(p.read_bytes())
    if not is_demo_key(x25519_public(secret)):      # the demo key is public on purpose: no permission warning for it
        _check_permissions(p, strict)
    return secret


def save_static_key(path: str | os.PathLike, secret: bytes, *, overwrite: bool = False) -> None:
    """Write the key (hex, mode 0600). Refuses to overwrite unless ``overwrite=True``."""
    p = Path(path)
    body = (
        "# cloudiamond-scratch server secret key (X25519). KEEP PRIVATE - never put it in Scratch or git.\n"
        f"# public key: {x25519_public(secret).hex()}\n"
        f"{secret.hex()}\n"
    ).encode()
    if not overwrite:
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # FileExistsError if present
        with os.fdopen(fd, "wb") as f:
            f.write(body)
        return
    fd, tmp = tempfile.mkstemp(dir=str(p.parent or "."), prefix=".key-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(body)
        os.chmod(tmp, 0o600)
        os.replace(tmp, p)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load_or_create_static_key(path: str | os.PathLike, *, strict: bool = False) -> bytes:
    """Load the key file, creating a new one (mode 0600) if it does not exist."""
    p = Path(path)
    if p.exists():
        return load_static_key(p, strict=strict)
    secret = generate_static_key()
    try:
        save_static_key(p, secret)
    except FileExistsError:  # lost a race with another process
        return load_static_key(p, strict=strict)
    return secret


def is_demo_key(public: bytes) -> bool:
    """True for the publicly known demo key (never use it for real data)."""
    return public.hex() == DEMO_PUBLIC_KEY_HEX


def key_from_env(name: str = ENV_VAR) -> bytes | None:
    """The key from an environment variable (hex / base64), or ``None`` if unset."""
    v = os.environ.get(name)
    return parse_secret(v) if v else None
