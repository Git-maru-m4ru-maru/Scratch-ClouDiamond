"""Runs only on Windows (CI). The Windows logic is otherwise tested with a fake icacls in test_fsperm.py."""
import _setup  # noqa: F401
import contextlib
import io
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from cloudiamond_scratch import fsperm, keys
from cloudiamond_scratch.cli import main


@unittest.skipUnless(os.name == "nt", "Windows only")
class RealWindows(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def acl(self, path):
        return subprocess.run(["icacls", str(path)], capture_output=True, text=True, errors="replace").stdout

    def test_a_new_key_file_is_restricted_to_the_current_user(self):
        p = self.dir / "server.key"
        self.assertTrue(keys.save_static_key(p, os.urandom(32)), "icacls could not restrict the key file")
        self.assertIs(fsperm.is_private(p), True, self.acl(p))
        self.assertNotIn("(I)", self.acl(p), "inherited ACL entries must be gone:\n" + self.acl(p))
        keys.load_static_key(p, strict=True)

    def test_overwrite_keeps_it_private(self):
        p = self.dir / "server.key"
        keys.save_static_key(p, os.urandom(32))
        self.assertTrue(keys.save_static_key(p, os.urandom(32), overwrite=True))
        self.assertIs(fsperm.is_private(p), True, self.acl(p))

    def test_load_or_create_is_idempotent(self):
        p = self.dir / "server.key"
        a = keys.load_or_create_static_key(p, strict=True)
        self.assertEqual(keys.load_or_create_static_key(p, strict=True), a)

    def test_restrict_to_owner_fixes_an_inherited_file(self):
        p = self.dir / "plain.key"
        p.write_text("x", encoding="utf-8")
        self.assertTrue(fsperm.restrict_to_owner(p), self.acl(p))
        self.assertIs(fsperm.is_private(p), True, self.acl(p))

    def test_keygen_command(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["keygen", str(self.dir / "cli.key"), "--strict"])
        self.assertEqual(code, 0, err.getvalue())
        self.assertIn("restricted to the current Windows user", out.getvalue())
        self.assertIs(fsperm.is_private(self.dir / "cli.key"), True)

    def test_a_non_ascii_path(self):
        p = self.dir / "鍵フォルダ" / "サーバー.key"
        p.parent.mkdir()
        self.assertTrue(keys.save_static_key(p, os.urandom(32)), self.acl(p))
        self.assertIs(fsperm.is_private(p), True, self.acl(p))


if __name__ == "__main__":
    unittest.main()
