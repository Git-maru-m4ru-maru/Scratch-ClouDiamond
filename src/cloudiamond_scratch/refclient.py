"""Reference (Python) implementation of the *client* side of the protocol.

The real client is the Scratch project. This sans-IO class is a second, independent implementation
used by the tests, by ``cloudiamond-scratch selftest`` and for Python-to-Python links. It is not
hardened against local attackers (the Scratch client is the intended client).
"""
from __future__ import annotations

from . import protocol as P
from .crypto import (CryptoError, READY, aead_open, aead_seal, derive_keys, generate_secret,
                     x25519_public, x25519_shared)

__all__ = ["ReferenceClient"]


class ReferenceClient:
    def __init__(self, server_public: bytes, ephemeral_secret: bytes | None = None):
        if len(server_public) != 32:
            raise ValueError("server public key must be 32 bytes")
        self.server_public = server_public
        self._e: bytes | None = ephemeral_secret or generate_secret()
        self.public = x25519_public(self._e)
        self.sid = self.public[:P.SID_LEN]
        self.connected = False
        self.send_ctr = 0
        self.recv_last = 0
        self._k_c2s = self._k_s2c = b""

    def hello(self) -> bytes:
        return self.sid + bytes([P.T_HELLO]) + self.public

    def accept_reply(self, frame: bytes) -> bool:
        """Verify the server's REPLY. ``True`` only if the server proved it owns the private key."""
        if self.connected:
            return True
        if len(frame) != P.REPLY_LEN or frame[8] != P.T_REPLY or frame[:8] != self.sid or self._e is None:
            return False
        big_r = frame[9:41]
        try:
            dh_es = x25519_shared(self._e, self.server_public)
            dh_ee = x25519_shared(self._e, big_r)
        except CryptoError:
            return False
        _m, k_c2s, k_s2c = derive_keys(dh_es, dh_ee)
        aad = self.sid + bytes([P.T_REPLY]) + self.public + big_r
        if aead_open(k_s2c, b"\0" * 12, aad, frame[41:]) != READY:
            return False
        self._k_c2s, self._k_s2c, self.connected, self._e = k_c2s, k_s2c, True, None
        return True

    def seal(self, data: bytes) -> bytes:
        if not self.connected:
            raise RuntimeError("not connected")
        self.send_ctr += 1
        header = self.sid + bytes([P.T_C2S]) + self.send_ctr.to_bytes(6, "big")
        return header + aead_seal(self._k_c2s, P.data_nonce(self.send_ctr), header, P.pad_message(data))

    def open(self, frame: bytes) -> bytes | None:
        n = len(frame)
        if (not self.connected or n < P.HEADER_LEN + P.BLOCK + P.TAG_LEN or n > P.MAX_FRAME
                or (n - P.HEADER_LEN - P.TAG_LEN) % P.BLOCK or frame[8] != P.T_S2C or frame[:8] != self.sid):
            return None
        ctr = int.from_bytes(frame[9:15], "big")
        if ctr <= self.recv_last:
            return None
        plain = aead_open(self._k_s2c, P.data_nonce(ctr), frame[:P.HEADER_LEN], frame[P.HEADER_LEN:])
        if plain is None:
            return None
        self.recv_last = ctr
        return P.unpad_message(plain)
