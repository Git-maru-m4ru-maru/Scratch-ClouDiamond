"""Cryptographic primitives used by the protocol.

Everything here is a thin layer over standard algorithms:

* X25519 (RFC 7748) and ChaCha20-Poly1305 (RFC 8439) come from ``cryptography``.
* HChaCha20 (draft-irtf-cfrg-xchacha, section 2.2) is implemented in pure Python because
  ``cryptography`` does not expose it. It is checked against the published test vector.
"""
from __future__ import annotations

import hashlib
import hmac
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

__all__ = [
    "CryptoError", "LABEL_MASTER", "LABEL_C2S", "LABEL_S2C", "READY",
    "hchacha20", "x25519_public", "x25519_shared", "generate_secret",
    "aead_seal", "aead_open", "derive_keys", "fingerprint", "ct_equal",
]

LABEL_MASTER = b"SCRSEC1-master" + b"\0" * 2
LABEL_C2S = b"SCRSEC1-c2s" + b"\0" * 5
LABEL_S2C = b"SCRSEC1-s2c" + b"\0" * 5
READY = b"SCRSEC1-READY" + b"\0" * 3

_SIGMA = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)  # "expand 32-byte k"
_M32 = 0xFFFFFFFF


class CryptoError(ValueError):
    """An invalid key / point (for example a low-order point)."""


def _rotl(v: int, n: int) -> int:
    return ((v << n) & _M32) | (v >> (32 - n))


def hchacha20(key: bytes, nonce16: bytes) -> bytes:
    """HChaCha20: 32-byte key + 16-byte input -> 32-byte subkey."""
    if len(key) != 32 or len(nonce16) != 16:
        raise ValueError("hchacha20 needs a 32-byte key and a 16-byte nonce")
    s = list(_SIGMA) + list(struct.unpack("<8I", key)) + list(struct.unpack("<4I", nonce16))

    def qr(a: int, b: int, c: int, d: int) -> None:
        s[a] = (s[a] + s[b]) & _M32; s[d] = _rotl(s[d] ^ s[a], 16)
        s[c] = (s[c] + s[d]) & _M32; s[b] = _rotl(s[b] ^ s[c], 12)
        s[a] = (s[a] + s[b]) & _M32; s[d] = _rotl(s[d] ^ s[a], 8)
        s[c] = (s[c] + s[d]) & _M32; s[b] = _rotl(s[b] ^ s[c], 7)

    for _ in range(10):
        qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)
        qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14)
    return struct.pack("<8I", *(s[0:4] + s[12:16]))


def generate_secret() -> bytes:
    """A fresh X25519 private key (32 random bytes from the OS CSPRNG)."""
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
    k = X25519PrivateKey.generate()
    return k.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def x25519_public(secret: bytes) -> bytes:
    if len(secret) != 32:
        raise CryptoError("X25519 secret must be 32 bytes")
    return X25519PrivateKey.from_private_bytes(secret).public_key().public_bytes_raw()


def x25519_shared(secret: bytes, peer_public: bytes) -> bytes:
    """Diffie-Hellman. Raises ``CryptoError`` for malformed / low-order input (all-zero output)."""
    if len(secret) != 32 or len(peer_public) != 32:
        raise CryptoError("X25519 inputs must be 32 bytes")
    try:
        out = X25519PrivateKey.from_private_bytes(secret).exchange(
            X25519PublicKey.from_public_bytes(peer_public))
    except ValueError as exc:  # cryptography rejects an all-zero shared secret
        raise CryptoError(str(exc)) from None
    if not any(out):  # belt and braces
        raise CryptoError("all-zero shared secret")
    return out


def aead_seal(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
    """ChaCha20-Poly1305. Returns ``ciphertext || tag(16)``."""
    return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)


def aead_open(key: bytes, nonce: bytes, aad: bytes, ct_and_tag: bytes) -> bytes | None:
    """Returns the plaintext, or ``None`` when authentication fails (never raises on bad data)."""
    if len(ct_and_tag) < 16:
        return None
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ct_and_tag, aad)
    except InvalidTag:
        return None


def derive_keys(dh_es: bytes, dh_ee: bytes) -> tuple[bytes, bytes, bytes]:
    """Two-stage key schedule shared with the Scratch client.

    ``master = HChaCha20(dh_ee, HChaCha20(dh_es, LABEL_MASTER)[:16])`` then
    ``k_c2s / k_s2c = HChaCha20(master, label)``.
    Returns ``(master, k_c2s, k_s2c)``.
    """
    t = hchacha20(dh_es, LABEL_MASTER)
    master = hchacha20(dh_ee, t[:16])
    return master, hchacha20(master, LABEL_C2S), hchacha20(master, LABEL_S2C)


def ct_equal(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


def fingerprint(public: bytes, *, groups: int = 8) -> str:
    """Human-comparable fingerprint of a public key: ``AAAA-BBBB-...`` (first ``groups``×4 hex of SHA-256)."""
    h = hashlib.sha256(b"cloudiamond-scratch-pubkey\0" + public).hexdigest().upper()
    return "-".join(h[i * 4:(i + 1) * 4] for i in range(groups))
