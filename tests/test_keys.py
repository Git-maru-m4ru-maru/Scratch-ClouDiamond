import _setup  # noqa: F401
import base64
import os
import stat
import tempfile
import unittest
import warnings
from pathlib import Path

from cloudiamond_scratch import keys
from cloudiamond_scratch.crypto import CryptoError, x25519_public


class Parse(unittest.TestCase):
    def setUp(self):
        self.secret = bytes(range(1, 33))

    def test_formats(self):
        self.assertEqual(keys.parse_secret(self.secret), self.secret)
        self.assertEqual(keys.parse_secret(self.secret.hex()), self.secret)
        self.assertEqual(keys.parse_secret(self.secret.hex().upper().encode()), self.secret)
        self.assertEqual(keys.parse_secret(base64.b64encode(self.secret).decode()), self.secret)
        self.assertEqual(keys.parse_secret("# comment\n# another\n" + self.secret.hex() + "\n"), self.secret)

    def test_invalid(self):
        for bad in ("", "zz" * 32, "ab" * 31, "ab" * 33, b"short", "not a key at all", base64.b64encode(b"x" * 31).decode()):
            with self.assertRaises(CryptoError, msg=repr(bad)):
                keys.parse_secret(bad)

    def test_public_key_forms(self):
        pub = x25519_public(self.secret)
        self.assertEqual(keys.parse_public(pub.hex()), pub)
        self.assertEqual(keys.parse_public(":".join(pub.hex()[i:i + 2] for i in range(0, 64, 2))), pub)
        self.assertEqual(keys.parse_public(" " + pub.hex().upper() + "\n"), pub)
        self.assertEqual(keys.parse_public(pub), pub)
        for bad in ("", "00" * 31, "xx" * 32):
            with self.assertRaises(CryptoError):
                keys.parse_public(bad)


class Files(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_create_load_roundtrip(self):
        p = self.dir / "server.key"
        secret = keys.load_or_create_static_key(p)
        self.assertEqual(len(secret), 32)
        self.assertEqual(keys.load_or_create_static_key(p), secret)
        self.assertEqual(keys.load_static_key(p), secret)
        text = p.read_text()
        self.assertIn(x25519_public(secret).hex(), text)       # the comment shows the public key for convenience
        self.assertEqual(keys.public_key(secret), x25519_public(secret))

    @unittest.skipUnless(os.name == "posix", "POSIX permissions")
    def test_file_is_private(self):
        p = self.dir / "k"
        keys.save_static_key(p, os.urandom(32))
        self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
        keys.save_static_key(p, os.urandom(32), overwrite=True)
        self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)

    def test_never_overwrites_by_accident(self):
        p = self.dir / "k"
        first = os.urandom(32)
        keys.save_static_key(p, first)
        with self.assertRaises(FileExistsError):
            keys.save_static_key(p, os.urandom(32))
        self.assertEqual(keys.load_static_key(p), first)

    @unittest.skipUnless(os.name == "posix", "POSIX permissions")
    def test_warns_when_the_key_file_is_world_readable(self):
        p = self.dir / "k"
        keys.save_static_key(p, os.urandom(32))
        p.chmod(0o644)
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            keys.load_static_key(p)
        self.assertTrue(any(issubclass(x.category, keys.KeyPermissionWarning) for x in w))
        with self.assertRaises(PermissionError):
            keys.load_static_key(p, strict=True)

    @unittest.skipUnless(os.name == "posix", "POSIX permissions")
    def test_no_permission_warning_for_the_public_demo_key(self):
        demo = Path(__file__).resolve().parent.parent / "examples" / "demo_server.key"
        if not demo.exists():
            self.skipTest("examples/ not available")
        copy = self.dir / "demo.key"
        copy.write_bytes(demo.read_bytes())
        copy.chmod(0o644)
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            keys.load_static_key(copy, strict=True)               # strict would raise for a normal key
        self.assertEqual([x for x in w if issubclass(x.category, keys.KeyPermissionWarning)], [])

    def test_legacy_raw_32_byte_file(self):
        p = self.dir / "raw.key"
        raw = os.urandom(32)
        p.write_bytes(raw)
        p.chmod(0o600)
        self.assertEqual(keys.load_static_key(p), raw)

    def test_environment_variable(self):
        secret = os.urandom(32)
        os.environ["CD_TEST_KEY"] = secret.hex()
        try:
            self.assertEqual(keys.key_from_env("CD_TEST_KEY"), secret)
        finally:
            del os.environ["CD_TEST_KEY"]
        self.assertIsNone(keys.key_from_env("CD_TEST_KEY"))

    def test_atomic_overwrite_leaves_no_temp_files(self):
        p = self.dir / "k"
        keys.save_static_key(p, os.urandom(32))
        keys.save_static_key(p, os.urandom(32), overwrite=True)
        self.assertEqual(sorted(x.name for x in self.dir.iterdir()), ["k"])


if __name__ == "__main__":
    unittest.main()
