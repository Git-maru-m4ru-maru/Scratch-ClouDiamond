"""The cryptographic blocks inside the Scratch client, checked against the standards and ``cryptography``."""
import _setup  # noqa: F401
import os
import unittest

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from cloudiamond_scratch import sb3
from cloudiamond_scratch.crypto import hchacha20
from scratch_vm import VM


def vm_new():
    return VM(sb3.build_project(bytes(range(32))), seed=3)


def put(vm, name, data):
    lst = vm.list(name)
    for i, b in enumerate(data):
        lst[i] = float(b)


def get(vm, name, n):
    return bytes(int(float(x)) for x in vm.list(name)[:n])


class X25519Blocks(unittest.TestCase):
    def test_rfc7748_vectors(self):
        vm = vm_new()
        vectors = [
            ("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
             "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
             "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
            ("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
             "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
             "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"),
        ]
        for k, u, out in vectors:
            put(vm, "XK", bytes.fromhex(k))
            put(vm, "XU", bytes.fromhex(u))
            vm.call("ss_x25519")
            self.assertEqual(get(vm, "XOUT", 32).hex(), out)

    def test_public_key_matches_cryptography(self):
        vm = vm_new()
        for _ in range(3):
            sk = os.urandom(32)
            put(vm, "XK", sk)
            vm.call("ss_x25519 base")
            self.assertEqual(get(vm, "XOUT", 32), X25519PrivateKey.from_private_bytes(sk).public_key().public_bytes_raw())

    def test_shared_secret_matches_cryptography(self):
        vm = vm_new()
        a, b = os.urandom(32), os.urandom(32)
        pub_b = X25519PrivateKey.from_private_bytes(b).public_key().public_bytes_raw()
        put(vm, "XK", a)
        put(vm, "XU", pub_b)
        vm.call("ss_x25519")
        self.assertEqual(get(vm, "XOUT", 32), X25519PrivateKey.from_private_bytes(a).exchange(
            X25519PrivateKey.from_private_bytes(b).public_key()))


class HChaChaBlock(unittest.TestCase):
    def test_draft_vector_and_random_inputs(self):
        vm = vm_new()
        key = bytes(range(32))
        n16 = bytes.fromhex("000000090000004a0000000031415927")
        put(vm, "HCK", key)
        put(vm, "HCN", n16)
        vm.call("ss_hchacha20")
        self.assertEqual(get(vm, "HCO", 32).hex(), "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")
        for _ in range(3):
            k, n = os.urandom(32), os.urandom(16)
            put(vm, "HCK", k)
            put(vm, "HCN", n)
            vm.call("ss_hchacha20")
            self.assertEqual(get(vm, "HCO", 32), hchacha20(k, n))


class AeadBlocks(unittest.TestCase):
    def _setup(self, vm, key, nonce, aad, buf, buflen):
        put(vm, "AK", key)
        put(vm, "AN", nonce)
        put(vm, "AAD", aad)
        put(vm, "BUF", buf)
        vm.set_var("AADL", float(len(aad)))
        vm.set_var("BUFL", float(buflen))

    def test_rfc8439_vector(self):
        vm = vm_new()
        key = bytes(range(0x80, 0xA0))
        nonce = bytes.fromhex("070000004041424344454647")
        aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
        pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the "
              b"future, sunscreen would be it.")
        self._setup(vm, key, nonce, aad, pt, len(pt))
        vm.call("ss_aead seal")
        self.assertEqual(get(vm, "BUF", len(pt))[:8].hex(), "d31a8d34648e60db")
        self.assertEqual(get(vm, "ATAG", 16).hex(), "1ae10b594f09e26a7e902ecbd0600691")

    def test_seal_matches_cryptography_for_the_sizes_the_protocol_uses(self):
        vm = vm_new()
        for size in (32, 64, 128, 288):
            key, nonce, aad, pt = os.urandom(32), os.urandom(12), os.urandom(15), os.urandom(size)
            self._setup(vm, key, nonce, aad, pt, size)
            vm.call("ss_aead seal")
            ref = ChaCha20Poly1305(key).encrypt(nonce, pt, aad)
            self.assertEqual(get(vm, "BUF", size), ref[:size], size)
            self.assertEqual(get(vm, "ATAG", 16), ref[size:], size)

    def test_open_accepts_good_and_rejects_every_kind_of_corruption(self):
        vm = vm_new()
        key, nonce, aad, pt = os.urandom(32), os.urandom(12), os.urandom(15), os.urandom(64)
        ref = ChaCha20Poly1305(key).encrypt(nonce, pt, aad)
        ct, tag = ref[:64], ref[64:]

        def attempt(key=key, nonce=nonce, aad=aad, ct=ct, tag=tag):
            self._setup(vm, key, nonce, aad, ct, 64)
            put(vm, "TAGIN", tag)
            vm.call("ss_aead open")
            return str(vm.var("AOK")) == "1", get(vm, "BUF", 64)

        ok, plain = attempt()
        self.assertTrue(ok)
        self.assertEqual(plain, pt)
        flip = lambda b, i: b[:i] + bytes([b[i] ^ 1]) + b[i + 1:]   # noqa: E731
        for label, kw in {
            "tag": dict(tag=flip(tag, 0)), "tag-last": dict(tag=flip(tag, 15)), "ciphertext": dict(ct=flip(ct, 30)),
            "aad": dict(aad=flip(aad, 2)), "nonce": dict(nonce=flip(nonce, 11)), "key": dict(key=flip(key, 5)),
        }.items():
            ok, plain = attempt(**kw)
            self.assertFalse(ok, label)
            self.assertEqual(plain, ct if label != "ciphertext" else flip(ct, 30), "no plaintext may be released on failure: " + label)


if __name__ == "__main__":
    unittest.main()
