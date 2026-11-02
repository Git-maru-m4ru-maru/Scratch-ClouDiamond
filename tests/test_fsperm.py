"""Key-file protection. The Windows logic is tested here with a fake ``icacls`` / ``whoami`` (so it runs anywhere);
the real thing is exercised by test_windows_real.py on Windows."""
import _setup  # noqa: F401
import os
import stat
import tempfile
import unittest
import warnings
from pathlib import Path
from subprocess import CompletedProcess
from unittest import mock

from cloudiamond_scratch import fsperm, keys

SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"
ME = "DESKTOP-ABC\\alice"


class FakeWindows:
    """Stands in for ``subprocess.run`` on Windows. ``acl`` is what ``icacls <file>`` will print (a callable gets the path)."""

    def __init__(self, acl, grant_rc=0, whoami_ok=True):
        self.calls = []
        self.acl, self.grant_rc, self.whoami_ok = acl, grant_rc, whoami_ok

    def __call__(self, cmd, **kw):
        self.calls.append(list(cmd))
        out = lambda text, rc=0: CompletedProcess(cmd, rc, stdout=text.encode("utf-8"), stderr=b"")  # noqa: E731
        if cmd[0] == "whoami" and "/user" in cmd:
            return out(f'"{ME}","{SID}"\r\n') if self.whoami_ok else out("", 1)
        if cmd[0] == "whoami":
            return out(ME + "\r\n") if self.whoami_ok else out("", 1)
        if cmd[0] == "icacls" and "/grant:r" in cmd:
            return out("processed file\r\n", self.grant_rc)
        if cmd[0] == "icacls":
            text = self.acl(cmd[1]) if callable(self.acl) else self.acl
            return out(text or "", 0 if text is not None else 1)
        raise AssertionError(cmd)


def protected_acl(path):
    return f"{path} {ME}:(F)\r\n\r\nSuccessfully processed 1 files; Failed processing 0 files\r\n"


INHERITED_ACL = lambda path: (  # noqa: E731
    f"{path} BUILTIN\\Administrators:(I)(F)\r\n"
    "       NT AUTHORITY\\SYSTEM:(I)(F)\r\n"
    f"       {ME}:(I)(F)\r\n\r\nSuccessfully processed 1 files; Failed processing 0 files\r\n")

JAPANESE_SUMMARY_ACL = lambda path: (  # noqa: E731
    f"{path} {ME}:(F)\r\n\r\n1 個のファイルが正常に処理されました; 0 個のファイルを処理できませんでした\r\n")


def as_windows(fake):
    return mock.patch.multiple(fsperm, _is_windows=lambda: True, _run=fake)


class ParseIcacls(unittest.TestCase):
    def test_single_entry_with_path_prefix(self):
        p = "C:\\Users\\alice\\server.key"
        self.assertEqual(fsperm.parse_icacls(protected_acl(p), p), [(ME, ["F"])])

    def test_inherited_multi_line_listing(self):
        p = "C:\\Users\\alice\\server.key"
        aces = fsperm.parse_icacls(INHERITED_ACL(p), p)
        self.assertEqual([w for w, _ in aces], ["BUILTIN\\Administrators", "NT AUTHORITY\\SYSTEM", ME])
        self.assertTrue(all("I" in flags for _, flags in aces))

    def test_paths_with_spaces_and_japanese(self):
        p = "C:\\Users\\太郎\\My Keys\\server.key"
        self.assertEqual(fsperm.parse_icacls(protected_acl(p), p), [(ME, ["F"])])
        self.assertEqual(fsperm.parse_icacls(JAPANESE_SUMMARY_ACL(p), p), [(ME, ["F"])])

    def test_flags_are_split(self):
        self.assertEqual(fsperm.parse_icacls("x A\\b:(OI)(CI)(RX,W)\r\n", "x"), [("A\\b", ["OI", "CI", "RX,W"])])

    def test_garbage_yields_nothing(self):
        for text in ("", "Access is denied.\r\n", "random: text (here)\n", "no acl at all"):
            self.assertEqual(fsperm.parse_icacls(text, "p"), [], text)


class WindowsLogic(unittest.TestCase):
    def path(self):
        return os.path.abspath("C:\\Users\\alice\\server.key")

    def test_restrict_runs_the_right_commands(self):
        fake = FakeWindows(protected_acl)
        with as_windows(fake):
            self.assertTrue(fsperm.restrict_to_owner("server.key"))
        grants = [c for c in fake.calls if "/grant:r" in c]
        self.assertEqual(len(grants), 1)
        path = os.path.abspath("server.key")
        self.assertEqual(grants[0], ["icacls", path, "/inheritance:r", "/grant:r", f"*{SID}:F"])
        self.assertTrue(all(isinstance(a, str) for c in fake.calls for a in c), "arguments are passed as a list, never through a shell")

    def test_path_is_absolute_so_it_can_never_look_like_an_option(self):
        fake = FakeWindows(protected_acl)
        with as_windows(fake):
            fsperm.restrict_to_owner("/inheritance:r")
        self.assertTrue(os.path.isabs(next(c for c in fake.calls if "/grant:r" in c)[1]))

    def test_restrict_fails_cleanly(self):
        with as_windows(FakeWindows(protected_acl, whoami_ok=False)):
            self.assertFalse(fsperm.restrict_to_owner("k"))
        with as_windows(FakeWindows(protected_acl, grant_rc=5)):
            self.assertFalse(fsperm.restrict_to_owner("k"))                      # icacls: access denied
        with as_windows(FakeWindows(INHERITED_ACL)):
            self.assertFalse(fsperm.restrict_to_owner("k"), "icacls said OK but the result still inherits: not private")
        with mock.patch.multiple(fsperm, _is_windows=lambda: True, _run=lambda *a, **k: None):
            self.assertFalse(fsperm.restrict_to_owner("k"))                      # icacls / whoami not found

    def test_unreadable_result_after_a_successful_grant_is_accepted(self):
        with as_windows(FakeWindows(lambda p: None)):                             # grant rc 0, read-back fails (None)
            self.assertTrue(fsperm.restrict_to_owner("k"))

    def test_is_private(self):
        with as_windows(FakeWindows(protected_acl)):
            self.assertIs(fsperm.is_private("k"), True)
        with as_windows(FakeWindows(INHERITED_ACL)):
            self.assertIs(fsperm.is_private("k"), False)
        with as_windows(FakeWindows(lambda p: f"{p} {ME}:(F)\r\n       BUILTIN\\Users:(R)\r\n")):
            self.assertIs(fsperm.is_private("k"), False, "another account is listed")
        with as_windows(FakeWindows(lambda p: f"{p} {ME.upper()}:(F)\r\n")):
            self.assertIs(fsperm.is_private("k"), True, "account names compare case-insensitively")
        with as_windows(FakeWindows(lambda p: "Access is denied.\r\n")):
            self.assertIsNone(fsperm.is_private("k"))
        with as_windows(FakeWindows(lambda p: None)):
            self.assertIsNone(fsperm.is_private("k"))
        with as_windows(FakeWindows(protected_acl, whoami_ok=False)):
            self.assertIsNone(fsperm.is_private("k"), "cannot tell who 'me' is")

    def test_an_inherited_entry_is_never_confirmed_private_even_if_it_is_only_mine(self):
        """While inheritance is on, a change to the folder's permissions changes access to the file: not 'confirmed private'."""
        with as_windows(FakeWindows(lambda p: f"{p} {ME}:(I)(F)\r\n")):
            self.assertIs(fsperm.is_private("k"), False)
        with as_windows(FakeWindows(lambda p: f"{p} {ME}:(F)\r\n")):
            self.assertIs(fsperm.is_private("k"), True)

    def test_only_the_current_user_entry_counts_even_with_a_similar_name(self):
        with as_windows(FakeWindows(lambda p: f"{p} OTHERPC\\malice:(F)\r\n")):
            self.assertIs(fsperm.is_private("k"), False)

    def test_messages(self):
        with as_windows(FakeWindows(protected_acl)):
            self.assertIn("icacls", fsperm.describe_restriction("server.key", False))
            self.assertIn("/inheritance:r", fsperm.icacls_fix_command("server.key"))
            self.assertIn("current Windows user", fsperm.describe_restriction("server.key", True))


@unittest.skipUnless(os.name == "posix", "POSIX mode bits")
class Posix(unittest.TestCase):
    def test_restrict_and_check(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "k"
            f.write_text("x", encoding="utf-8")
            f.chmod(0o644)
            self.assertIs(fsperm.is_private(f), False)
            self.assertTrue(fsperm.restrict_to_owner(f))
            self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o600)
            self.assertIs(fsperm.is_private(f), True)
            f.chmod(0o640)
            self.assertIs(fsperm.is_private(f), False)
            f.chmod(0o604)
            self.assertIs(fsperm.is_private(f), False)

    def test_missing_file(self):
        self.assertIsNone(fsperm.is_private("/nonexistent/path/key"))
        self.assertFalse(fsperm.restrict_to_owner("/nonexistent/path/key"))


class KeyFilesUseIt(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    @unittest.skipUnless(os.name == "posix", "POSIX mode bits")
    def test_posix_file_is_private_from_the_moment_it_exists(self):
        """Not just 'after chmod': with the protection step disabled, the created file must already be mode 600."""
        modes = []

        def spy(path):
            modes.append(stat.S_IMODE(os.stat(path).st_mode))
            return True
        with mock.patch.object(fsperm, "restrict_to_owner", spy):
            keys.save_static_key(self.dir / "k", os.urandom(32))
        self.assertEqual(modes, [0o600])
        self.assertEqual(stat.S_IMODE((self.dir / "k").stat().st_mode), 0o600)
        modes.clear()
        with mock.patch.object(fsperm, "restrict_to_owner", spy):
            keys.save_static_key(self.dir / "k", os.urandom(32), overwrite=True)
        self.assertEqual(modes, [0o600], "mkstemp creates the temporary file private as well")

    def test_the_file_is_restricted_before_the_secret_is_written(self):
        """On Windows the file is created with the folder's ACL; it must be locked down while it is still empty."""
        seen = {}

        def spy(path):
            seen["size"] = Path(path).stat().st_size
            seen["exists"] = Path(path).exists()
            return True
        with mock.patch.object(fsperm, "restrict_to_owner", spy):
            keys.save_static_key(self.dir / "k", os.urandom(32))
        self.assertEqual(seen, {"size": 0, "exists": True})
        seen.clear()
        with mock.patch.object(fsperm, "restrict_to_owner", spy):
            keys.save_static_key(self.dir / "k", os.urandom(32), overwrite=True)
        self.assertEqual(seen, {"size": 0, "exists": True}, "the overwrite path locks its temporary file down first, too")

    def test_failure_to_protect_is_reported_not_hidden(self):
        secret = os.urandom(32)
        with mock.patch.object(fsperm, "restrict_to_owner", lambda p: False):
            self.assertFalse(keys.save_static_key(self.dir / "k", secret))
        self.assertEqual(keys.parse_secret((self.dir / "k").read_bytes()), secret, "a key that was generated is never lost")

    def test_strict_removes_the_file_and_raises(self):
        with mock.patch.object(fsperm, "restrict_to_owner", lambda p: False):
            with self.assertRaises(PermissionError):
                keys.save_static_key(self.dir / "k", os.urandom(32), strict=True)
            self.assertFalse((self.dir / "k").exists())
            with self.assertRaises(PermissionError):
                keys.save_static_key(self.dir / "k2", os.urandom(32), overwrite=True, strict=True)
            self.assertFalse((self.dir / "k2").exists())
        self.assertEqual([x.name for x in self.dir.iterdir()], [], "no temporary files left behind")

    def test_overwrite_retries_the_protection_on_the_final_file(self):
        calls = []
        results = iter([False, True])           # the temporary file could not be locked down; the final one could

        def fake(path):
            calls.append(Path(path).name)
            return next(results)
        with mock.patch.object(fsperm, "restrict_to_owner", fake):
            self.assertTrue(keys.save_static_key(self.dir / "k", os.urandom(32), overwrite=True))
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1], "k")

    def write_key(self):
        p = self.dir / "k"
        keys.save_static_key(p, os.urandom(32))
        return p

    def test_load_warns_when_the_key_may_be_shared(self):
        p = self.write_key()
        with mock.patch.object(fsperm, "is_private", lambda path: False):
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                keys.load_static_key(p)
            self.assertTrue(any(issubclass(x.category, keys.KeyPermissionWarning) for x in w))
            with self.assertRaises(PermissionError):
                keys.load_static_key(p, strict=True)

    def test_load_is_quiet_when_private_or_unknown_but_strict_wants_certainty(self):
        p = self.write_key()
        for state in (True, None):
            with mock.patch.object(fsperm, "is_private", lambda path, s=state: s):
                with warnings.catch_warnings(record=True) as w:
                    warnings.simplefilter("always")
                    keys.load_static_key(p)
                self.assertEqual([x for x in w if issubclass(x.category, keys.KeyPermissionWarning)], [], state)
        with mock.patch.object(fsperm, "is_private", lambda path: None):
            with self.assertRaises(PermissionError):
                keys.load_static_key(p, strict=True)

    def test_windows_message_names_the_fix_without_overclaiming(self):
        p = self.write_key()
        with as_windows(FakeWindows(INHERITED_ACL)):
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                keys.load_static_key(p)
        msg = str(next(x for x in w if issubclass(x.category, keys.KeyPermissionWarning)).message)
        self.assertIn("icacls", msg)
        self.assertIn("could not be confirmed", msg)
        self.assertNotIn("readable by other users", msg, "on Windows this depends on the folder's ACL; do not claim more than is known")


if __name__ == "__main__":
    unittest.main()
