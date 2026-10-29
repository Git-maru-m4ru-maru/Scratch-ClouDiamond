import _setup  # noqa: F401
import unittest

from cloudiamond_scratch import crypto
from cloudiamond_scratch.crypto import (CryptoError, aead_open, aead_seal, derive_keys, fingerprint,
                                        hchacha20, x25519_public, x25519_shared)


class KnownAnswers(unittest.TestCase):
    def test_hchacha20_draft_vector(self):
        key = bytes(range(32))
        n = bytes.fromhex("000000090000004a0000000031415927")
        self.assertEqual(hchacha20(key, n).hex(),
                         "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")

    def test_hchacha20_input_sizes(self):
        with self.assertRaises(ValueError):
            hchacha20(b"\0" * 31, b"\0" * 16)
        with self.assertRaises(ValueError):
            hchacha20(b"\0" * 32, b"\0" * 12)

    def test_x25519_rfc7748_section_5_2(self):
        k = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        u = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        self.assertEqual(x25519_shared(k, u).hex(),
                         "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")

    def test_x25519_rfc7748_section_6_1(self):
        a = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        b = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        self.assertEqual(x25519_public(a).hex(), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        self.assertEqual(x25519_public(b).hex(), "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        self.assertEqual(x25519_shared(a, x25519_public(b)).hex(), shared)
        self.assertEqual(x25519_shared(b, x25519_public(a)).hex(), shared)

    def test_chacha20poly1305_rfc8439_section_2_8_2(self):
        key = bytes(range(0x80, 0xA0))
        nonce = bytes.fromhex("070000004041424344454647")
        aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
        pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the "
              b"future, sunscreen would be it.")
        sealed = aead_seal(key, nonce, aad, pt)
        self.assertEqual(sealed[:8].hex(), "d31a8d34648e60db")
        self.assertEqual(sealed[-16:].hex(), "1ae10b594f09e26a7e902ecbd0600691")
        self.assertEqual(aead_open(key, nonce, aad, sealed), pt)


class Behaviour(unittest.TestCase):
    def test_low_order_points_are_rejected(self):
        secret = crypto.generate_secret()
        for point in (bytes(32), b"\x01" + bytes(31)):          # zero, and the point of order 1 / 2 family
            with self.assertRaises(CryptoError):
                x25519_shared(secret, point)

    def test_all_zero_shared_secret_is_rejected_even_if_the_backend_allows_it(self):
        """Defence in depth: today OpenSSL already refuses low-order points; if a backend ever returned zeros we still refuse."""
        class Stub:
            def exchange(self, peer):
                return bytes(32)
        real = crypto.X25519PrivateKey.from_private_bytes
        crypto.X25519PrivateKey.from_private_bytes = staticmethod(lambda b: Stub())
        try:
            with self.assertRaises(CryptoError):
                x25519_shared(bytes(32), bytes([9]) + bytes(31))
        finally:
            crypto.X25519PrivateKey.from_private_bytes = real
        self.assertEqual(len(x25519_shared(crypto.generate_secret(), x25519_public(crypto.generate_secret()))), 32)

    def test_wrong_sizes_are_rejected(self):
        with self.assertRaises(CryptoError):
            x25519_public(b"\0" * 31)
        with self.assertRaises(CryptoError):
            x25519_shared(b"\0" * 32, b"\0" * 31)

    def test_aead_open_returns_none_not_exception(self):
        k, n = bytes(32), bytes(12)
        sealed = aead_seal(k, n, b"aad", b"hello")
        self.assertIsNone(aead_open(k, n, b"AAD", sealed))                   # wrong aad
        self.assertIsNone(aead_open(k, n, b"aad", sealed[:-1] + bytes([sealed[-1] ^ 1])))
        self.assertIsNone(aead_open(k, n, b"aad", b"short"))
        self.assertIsNone(aead_open(bytes([1]) * 32, n, b"aad", sealed))     # wrong key

    def test_derive_keys_is_deterministic_and_separates_directions(self):
        a, b = bytes([1]) * 32, bytes([2]) * 32
        m1, c1, s1 = derive_keys(a, b)
        self.assertEqual((m1, c1, s1), derive_keys(a, b))
        self.assertEqual(len({m1, c1, s1}), 3)
        self.assertNotEqual(derive_keys(a, b)[0], derive_keys(b, a)[0])      # order matters

    def test_fingerprint_format_and_sensitivity(self):
        p = bytes(range(32))
        f = fingerprint(p)
        self.assertRegex(f, r"^([0-9A-F]{4}-){7}[0-9A-F]{4}$")
        self.assertNotEqual(f, fingerprint(bytes([1]) + p[1:]))


if __name__ == "__main__":
    unittest.main()
