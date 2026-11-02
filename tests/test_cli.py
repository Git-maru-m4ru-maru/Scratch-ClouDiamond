import _setup  # noqa: F401
import contextlib
import io
import os
import tempfile
import sys
import unittest
from pathlib import Path
from unittest import mock

from cloudiamond_scratch import fingerprint, fsperm, keys, sb3
from cloudiamond_scratch.cli import main


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = main(list(argv))
        except SystemExit as e:           # argparse errors
            code = e.code
    return code, out.getvalue(), err.getvalue()


class Workflow(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cwd = os.getcwd()
        os.chdir(self.tmp.name)

    def tearDown(self):
        os.chdir(self.cwd)
        self.tmp.cleanup()

    def test_keygen_build_inspect_verify_audit(self):
        code, out, _ = run("keygen", "-o", "s.key")
        self.assertEqual(code, 0)
        secret = keys.load_static_key("s.key")
        pub = keys.public_key(secret)
        self.assertIn(pub.hex(), out)
        self.assertIn(fingerprint(pub), out)

        code, out, _ = run("build", "--key", "s.key", "-o", "a.sb3", "--name", "Quiz")
        self.assertEqual(code, 0)
        self.assertIn("sha256", out)
        data = Path("a.sb3").read_bytes()
        self.assertEqual(data, sb3.build_sb3(pub, name="Quiz"))
        self.assertNotIn(secret.hex().encode(), data, "the secret key must never end up in the project")
        self.assertNotIn(secret, data)

        code, out, _ = run("inspect", "a.sb3")
        self.assertEqual(code, 0)
        self.assertIn(pub.hex(), out)
        self.assertIn("💎Quiz", out)

        self.assertEqual(run("verify", "a.sb3", "--key", "s.key")[0], 0)
        self.assertEqual(run("verify", "a.sb3", "--pub", pub.hex())[0], 0)
        self.assertEqual(run("verify", "a.sb3", "--pub", "00" * 32)[0], 1)
        code, out, _ = run("audit", "a.sb3")
        self.assertEqual(code, 0)
        self.assertIn("audit OK", out)

    def test_build_from_public_key_and_library_mode(self):
        pub = keys.public_key(keys.generate_static_key())
        self.assertEqual(run("build", "--pub", pub.hex(), "-o", "lib.sb3", "--no-demo")[0], 0)
        project, _ = sb3.read_sb3(Path("lib.sb3").read_bytes())
        self.assertFalse(any(isinstance(b, dict) and b["opcode"] == "event_whenflagclicked" for b in sb3._sprite(project)["blocks"].values()))

    def test_keygen_accepts_a_positional_path_like_v0_1(self):
        self.assertEqual(run("keygen", "pos.key")[0], 0)
        self.assertTrue(Path("pos.key").exists())
        self.assertEqual(run("keygen")[0], 0)
        self.assertTrue(Path("server.key").exists())

    def test_demo_key_triggers_a_warning(self):
        demo = Path(__file__).resolve().parent.parent / "examples" / "demo_server.key"
        if not demo.exists():
            self.skipTest("examples/ not available")
        code, out, err = run("build", "--key", str(demo), "-o", "demo.sb3")
        self.assertEqual(code, 0)
        self.assertIn("publicly known DEMO key", err)
        code, out, err = run("keygen", "mine.key")
        self.assertEqual(run("build", "--key", "mine.key", "-o", "mine.sb3")[2].count("DEMO"), 0)

    @unittest.skipUnless(os.name == "posix", "POSIX mode bits")
    def test_keygen_says_how_the_key_was_protected(self):
        code, out, err = run("keygen", "p.key")
        self.assertEqual(code, 0)
        self.assertIn("mode 600", out)
        self.assertEqual(err, "")

    def test_keygen_reports_when_the_key_could_not_be_protected(self):
        with mock.patch.object(fsperm, "restrict_to_owner", lambda p: False):
            code, out, err = run("keygen", "weak.key")
        self.assertEqual(code, 0, "the key is still written: a generated key is never thrown away")
        self.assertTrue(Path("weak.key").exists())
        self.assertIn("WARNING", err)
        self.assertIn("could NOT", err)
        self.assertIn("public key", out)

    def test_keygen_strict_fails_and_keeps_no_file(self):
        with mock.patch.object(fsperm, "restrict_to_owner", lambda p: False):
            code, out, err = run("keygen", "weak.key", "--strict")
        self.assertEqual(code, 2)
        self.assertFalse(Path("weak.key").exists())
        self.assertIn("--strict", err)

    def test_a_console_that_cannot_show_emoji_does_not_crash(self):
        """Windows consoles often use cp1252 / cp932; the sprite name starts with a diamond emoji."""
        self.assertEqual(run("build", "--pub", "11" * 32, "-o", "a.sb3")[0], 0)
        for command in (["inspect", "a.sb3"], ["audit", "a.sb3", "-v"], ["verify", "a.sb3"]):
            raw = io.BytesIO()
            console = io.TextIOWrapper(raw, encoding="ascii", errors="strict")
            errc = io.TextIOWrapper(io.BytesIO(), encoding="ascii", errors="strict")
            with contextlib.redirect_stdout(console), contextlib.redirect_stderr(errc):
                code = main(command)                      # must not raise UnicodeEncodeError
            console.flush()
            self.assertIn(code, (0, 1), command)
            if command[0] == "inspect":
                self.assertIn("?Cloudiamond", raw.getvalue().decode("ascii"))

    def test_keygen_refuses_to_overwrite(self):
        self.assertEqual(run("keygen", "-o", "s.key")[0], 0)
        first = Path("s.key").read_bytes()
        code, _, err = run("keygen", "-o", "s.key")
        self.assertEqual(code, 2)
        self.assertIn("already exists", err)
        self.assertEqual(Path("s.key").read_bytes(), first)
        self.assertEqual(run("keygen", "-o", "s.key", "--force")[0], 0)
        self.assertNotEqual(Path("s.key").read_bytes(), first)

    def test_build_never_overwrites_the_key_file(self):
        run("keygen", "-o", "s.key")
        before = Path("s.key").read_bytes()
        self.assertEqual(run("build", "--key", "s.key", "-o", "s.key")[0], 2)
        self.assertEqual(Path("s.key").read_bytes(), before)

    def test_build_needs_a_key(self):
        code, _, err = run("build", "-o", "x.sb3")
        self.assertEqual(code, 2)
        self.assertFalse(Path("x.sb3").exists())

    def test_bad_inputs_give_clean_errors(self):
        self.assertEqual(run("build", "--pub", "zz", "-o", "x.sb3")[0], 2)
        self.assertEqual(run("build", "--key", "missing.key", "-o", "x.sb3")[0], 2)
        Path("junk.sb3").write_bytes(b"junk")
        for cmd in ("inspect", "audit", "verify"):
            code, _, err = run(cmd, "junk.sb3")
            self.assertEqual(code, 2, cmd)
            self.assertIn("error:", err)
        self.assertEqual(run("inspect", "nope.sb3")[0], 2)

    def test_audit_fails_on_a_dirty_project(self):
        pub = keys.public_key(keys.generate_static_key())
        project = sb3.build_project(pub)
        sp = sb3._sprite(project)
        next(v for v in sp["lists"].values() if v[0] == "KC2S")[1] = [9] * 32
        import io as _io, json, zipfile
        buf = _io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("project.json", json.dumps(project))
        Path("dirty.sb3").write_bytes(buf.getvalue())
        code, out, err = run("audit", "dirty.sb3")
        self.assertEqual(code, 1)
        self.assertIn("CRITICAL", out)
        self.assertIn("do not publish", err)

    def test_pubkey_command(self):
        run("keygen", "-o", "s.key")
        code, out, err = run("pubkey", "--key", "s.key")
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), keys.public_key(keys.load_static_key("s.key")).hex())
        self.assertEqual(run("pubkey", "--key", "missing")[0], 2)

    def test_selftest(self):
        code, out, _ = run("selftest")
        self.assertEqual(code, 0)
        self.assertIn("all checks passed", out)
        code, out, _ = run("selftest", "-v")
        self.assertGreaterEqual(out.count("  ok"), 14)

    def test_version_and_usage(self):
        self.assertEqual(run("--version")[0], 0)
        self.assertEqual(run()[0], 2)
        self.assertEqual(run("bogus")[0], 2)


if __name__ == "__main__":
    unittest.main()
