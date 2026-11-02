import _setup  # noqa: F401
import unittest

from cloudiamond_scratch import Router, SecureServer, generate_static_key, text
from cloudiamond_scratch.auth import LoginThrottle, hash_password, verify_password
from cloudiamond_scratch.refclient import ReferenceClient
from helpers import Clock


def make(router):
    srv = SecureServer(generate_static_key(), handler=router)
    c = ReferenceClient(srv.public_key)
    c.accept_reply(srv.handle_frame(c.hello()))

    def ask(msg: str):
        out = srv.handle_frame(c.seal(text.encode(msg)))
        return None if out is None else text.decode(c.open(out))
    return srv, ask


class TextTable(unittest.TestCase):
    def test_ascii_part_is_identical_to_v0_1(self):
        expected = ([chr(c) for c in range(32, 65)] + [chr(c) for c in range(91, 97)]
                    + [chr(c) for c in range(97, 123)] + [chr(c) for c in range(123, 127)])
        self.assertEqual(text.CHARS[:69], expected)
        self.assertEqual(text.CODES[:69], [ord(c) for c in expected])

    def test_table_is_a_bijection_within_a_byte(self):
        self.assertEqual(len(set(text.CODES)), len(text.CODES))
        self.assertEqual(len(set(text.CHARS)), len(text.CHARS))
        self.assertTrue(all(0 <= c <= 255 for c in text.CODES))
        self.assertNotIn(0, text.CODES, "0 is the padding byte")

    def test_round_trips(self):
        for s in ("hello world 123 !?", "ひらがな、カタカナ！", "ー・「」。", "abc ぁぃぅ ヴヵヶ"):
            self.assertEqual(text.decode(text.encode(s)), s)

    def test_scratch_limitations_are_explicit(self):
        self.assertEqual(text.to_scratch_text("Hello World"), "hello world")
        self.assertEqual(text.to_scratch_text("漢字🙂~"), "???~")
        self.assertEqual(text.decode(bytes([200, 255, 0, 127])[2:]), "??")
        self.assertTrue(text.is_sendable("abc ひら"))
        self.assertFalse(text.is_sendable("ABC"))

    def test_every_hiragana_and_katakana_is_present(self):
        for cp in list(range(0x3041, 0x3094)) + list(range(0x30A1, 0x30F7)):
            self.assertIn(chr(cp), text.TABLE)


class RouterTests(unittest.TestCase):
    def test_dispatch_and_args(self):
        r = Router()

        @r.command("add")
        def add(ctx):
            return str(sum(int(x) for x in ctx.args))

        @r.command()
        def ping(ctx):
            return "pong"
        srv, ask = make(r)
        self.assertEqual(ask("add 1 2 3"), "6")
        self.assertEqual(ask("PING"), "pong")                 # Scratch lowercases anyway
        self.assertEqual(r.commands, ["add", "ping"])

    def test_unknown_error_and_no_leak(self):
        r = Router()

        @r.command("boom")
        def boom(ctx):
            raise RuntimeError("secret internal detail")
        srv, ask = make(r)
        self.assertEqual(ask("nope"), "error unknown")
        reply = ask("boom")
        self.assertEqual(reply, "error")
        self.assertNotIn("secret", reply)
        self.assertEqual(ask("   "), "error unknown")

    def test_silent_on_unknown(self):
        srv, ask = make(Router(unknown=None))
        self.assertIsNone(ask("what"))

    def test_arg_limits(self):
        r = Router()
        r.command("two", min_args=2, max_args=2)(lambda ctx: "ok")
        srv, ask = make(r)
        self.assertEqual(ask("two a b"), "ok")
        self.assertEqual(ask("two a"), "error")
        self.assertEqual(ask("two a b c"), "error")
        self.assertEqual(Router(max_args=3)(None, text.encode("x " + "a " * 10)), text.encode("error unknown"))

    def test_login_guard(self):
        r = Router()

        @r.command("login")
        def login(ctx):
            ctx.session.user = ctx.args[0]
            return "welcome " + ctx.args[0]
        r.command("secret", login=True)(lambda ctx: "data for " + ctx.user)
        srv, ask = make(r)
        self.assertEqual(ask("secret"), "error login")
        self.assertEqual(ask("login alice"), "welcome alice")
        self.assertEqual(ask("secret"), "data for alice")
        # a different session is not logged in
        srv2, ask2 = make(r)
        self.assertEqual(ask2("secret"), "error login")

    def test_duplicate_registration(self):
        r = Router()
        r.command("a")(lambda ctx: "1")
        with self.assertRaises(ValueError):
            r.command("a")(lambda ctx: "2")

    def test_reply_conversion(self):
        r = Router()
        r.command("up")(lambda ctx: "LOUD ＮＯ")
        r.command("raw")(lambda ctx: bytes([97, 98]))
        r.command("num")(lambda ctx: 42)
        r.command("none")(lambda ctx: None)
        srv, ask = make(r)
        self.assertEqual(ask("up"), "loud ??")
        self.assertEqual(ask("raw"), "ab")
        self.assertEqual(ask("num"), "42")
        self.assertIsNone(ask("none"))

    def test_japanese_commands(self):
        r = Router()
        r.command("こんにちは")(lambda ctx: "やあ、" + " ".join(ctx.args))
        srv, ask = make(r)
        self.assertEqual(ask("こんにちは せかい"), "やあ、せかい")


class Passwords(unittest.TestCase):
    def test_hash_and_verify(self):
        h = hash_password("correct horse battery")
        self.assertTrue(h.startswith("scrypt$"))
        self.assertTrue(verify_password("correct horse battery", h))
        self.assertFalse(verify_password("correct horse batterz", h))
        self.assertNotEqual(h, hash_password("correct horse battery"))      # random salt
        self.assertNotIn("correct", h)

    def test_unicode_password(self):
        h = hash_password("ぱすわーど")
        self.assertTrue(verify_password("ぱすわーど", h))

    def test_malformed_records_never_raise(self):
        for bad in ("", "x", "scrypt$1$2$3$4", "scrypt$a$b$c$d$e", "md5$1$1$1$AA==$AA==", "scrypt$16384$8$1$!!$!!",
                    "scrypt$99999999999$8$1$AA==$AA==", "scrypt$3$8$1$AA==$AA==", None, 5):
            self.assertFalse(verify_password("x", bad), repr(bad))   # type: ignore[arg-type]

    def test_throttle(self):
        clock = Clock()
        t = LoginThrottle(max_failures=3, window=60, lockout=120, clock=clock)
        for _ in range(3):
            self.assertTrue(t.allowed("alice"))
            t.failure("alice")
        self.assertFalse(t.allowed("alice"))
        self.assertTrue(t.allowed("bob"))
        clock.advance(121)
        self.assertTrue(t.allowed("alice"))
        t.failure("alice")
        t.success("alice")
        for _ in range(2):
            t.failure("alice")
        self.assertTrue(t.allowed("alice"))              # success() reset the counter

    def test_old_failures_age_out(self):
        clock = Clock()
        t = LoginThrottle(max_failures=3, window=60, clock=clock)
        t.failure("a"); t.failure("a")
        clock.advance(61)
        t.failure("a")
        self.assertTrue(t.allowed("a"))


if __name__ == "__main__":
    unittest.main()
