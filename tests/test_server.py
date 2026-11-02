import _setup  # noqa: F401
import threading
import unittest

from cloudiamond_scratch import MessageTooLarge, SecureServer, UnknownSession, generate_static_key, public_key
from cloudiamond_scratch import protocol as P
from cloudiamond_scratch.refclient import ReferenceClient
from helpers import Clock, new_server


def connect(server, secret=None):
    c = ReferenceClient(server.public_key)
    reply = server.handle_frame(c.hello())
    assert reply is not None and c.accept_reply(reply)
    return c


class Handshake(unittest.TestCase):
    def test_client_and_server_agree(self):
        secret, srv = new_server()
        c = ReferenceClient(srv.public_key)
        reply = srv.handle_frame(c.hello())
        self.assertEqual(len(reply), P.REPLY_LEN)
        self.assertEqual(reply[8], P.T_REPLY)
        self.assertTrue(c.accept_reply(reply))
        self.assertEqual(srv.stats["session_new"], 1)

    def test_reply_is_only_accepted_by_the_client_that_asked(self):
        _, srv = new_server()
        a, b = ReferenceClient(srv.public_key), ReferenceClient(srv.public_key)
        reply_a = srv.handle_frame(a.hello())
        self.assertFalse(b.accept_reply(reply_a))
        self.assertTrue(a.accept_reply(reply_a))

    def test_client_rejects_a_server_without_the_private_key(self):
        """An impostor knows the public key (it is public) but not the secret: it cannot produce an accepted reply."""
        _, real = new_server()
        _, impostor = new_server()                     # different key
        c = ReferenceClient(real.public_key)
        self.assertFalse(c.accept_reply(impostor.handle_frame(c.hello())))
        self.assertFalse(c.connected)

    def test_tampered_reply_is_rejected_by_the_client(self):
        """Flip every single byte of a genuine reply: the very client that asked must refuse each one."""
        _, srv = new_server(hello_rate=1e6, hello_burst=1e6)
        for i in range(P.REPLY_LEN):
            c = ReferenceClient(srv.public_key)
            reply = srv.handle_frame(c.hello())
            t = bytearray(reply)
            t[i] ^= 0x01
            self.assertFalse(c.accept_reply(bytes(t)), f"byte {i} of the reply is not authenticated")
            self.assertFalse(c.connected)
            self.assertTrue(c.accept_reply(reply), "the untouched reply must still be accepted afterwards")

    def test_hello_retransmit_returns_the_same_reply_without_new_session(self):
        _, srv = new_server()
        c = ReferenceClient(srv.public_key)
        r1 = srv.handle_frame(c.hello())
        r2 = srv.handle_frame(c.hello())
        self.assertEqual(r1, r2)
        self.assertEqual(srv.stats["session_new"], 1)
        self.assertEqual(srv.stats["hello_retransmit"], 1)
        self.assertTrue(c.accept_reply(r2))

    def test_sid_collision_cannot_replace_a_live_session(self):
        """An attacker can craft a public key with the same first 8 bytes (the session id)."""
        _, srv = new_server()
        victim = connect(srv)
        evil_pub = victim.public[:8] + bytes([7]) * 24
        self.assertIsNone(srv.handle_frame(victim.sid + b"\x01" + evil_pub))
        self.assertEqual(srv.stats["drop.sid_collision"], 1)
        self.assertEqual(len(srv.sessions), 1)
        self.assertEqual(victim.open(srv.handle_frame(victim.seal(b"still works"))), b"re:still works")

    def test_malformed_hello_is_dropped_silently(self):
        _, srv = new_server()
        good = ReferenceClient(srv.public_key).hello()
        cases = {
            "short": good[:-1], "long": good + b"\0",
            "sid != key prefix": bytes([good[0] ^ 1]) + good[1:],
            "low order point": bytes(8) + b"\x01" + bytes(32),
        }
        for name, frame in cases.items():
            self.assertIsNone(srv.handle_frame(frame), name)
        self.assertEqual(srv.stats["session_new"], 0)
        self.assertEqual(srv.stats["drop.bad_point"], 1)

    def test_all_zero_public_key_is_rejected(self):
        _, srv = new_server()
        self.assertIsNone(srv.handle_frame(bytes(8) + b"\x01" + bytes(32)))
        self.assertEqual(srv.stats["drop.bad_point"], 1)

    def test_garbage_frames_never_raise(self):
        _, srv = new_server()
        import os
        for n in list(range(0, 80)) + [100, 200, 336, 337, 1000]:
            for _ in range(3):
                srv.handle_frame(os.urandom(n))
        for t in range(256):                            # every type byte
            srv.handle_frame(bytes(8) + bytes([t]) + os.urandom(60))
        srv.handle_frame(None)            # type: ignore[arg-type]
        srv.handle_frame("text")          # type: ignore[arg-type]


class DataFrames(unittest.TestCase):
    def test_round_trip_both_directions(self):
        _, srv = new_server()
        c = connect(srv)
        out = srv.handle_frame(c.seal(b"hello"))
        self.assertEqual(c.open(out), b"re:hello")

    def test_empty_and_max_size_messages(self):
        _, srv = new_server(on_message=lambda sid, d: d)
        c = connect(srv)
        self.assertEqual(c.open(srv.handle_frame(c.seal(b""))), b"")
        big = bytes(range(256))[:200] + bytes(86)
        self.assertEqual(len(big), P.MAX_MESSAGE)
        frame = c.seal(big)
        self.assertLessEqual(len(frame), P.MAX_FRAME)
        self.assertEqual(c.open(srv.handle_frame(frame)), big)

    def test_replay_is_dropped(self):
        got = []
        _, srv = new_server(on_message=lambda sid, d: got.append(d))
        c = connect(srv)
        f = c.seal(b"pay 100")
        srv.handle_frame(f)
        self.assertIsNone(srv.handle_frame(f))
        self.assertEqual(got, [b"pay 100"])
        self.assertEqual(srv.stats["drop.replay"], 1)

    def test_old_counter_is_dropped_even_if_authentic(self):
        got = []
        _, srv = new_server(on_message=lambda sid, d: got.append(d))
        c = connect(srv)
        f1, f2 = c.seal(b"one"), c.seal(b"two")
        srv.handle_frame(f2)
        srv.handle_frame(f1)                            # authentic but older than the last accepted counter
        self.assertEqual(got, [b"two"])

    def test_tampering_any_byte_is_dropped(self):
        got = []
        _, srv = new_server(on_message=lambda sid, d: got.append(d))
        c = connect(srv)
        f = c.seal(b"transfer")
        for i in range(len(f)):
            t = bytearray(f)
            t[i] ^= 0x01
            srv.handle_frame(bytes(t))
        self.assertEqual(got, [])
        srv.handle_frame(f)
        self.assertEqual(got, [b"transfer"])           # failures did not advance the counter

    def test_truncation_and_extension_are_dropped(self):
        got = []
        _, srv = new_server(on_message=lambda sid, d: got.append(d))
        c = connect(srv)
        f = c.seal(b"x")
        srv.handle_frame(f[:-1])
        srv.handle_frame(f + b"\0")
        srv.handle_frame(f[:-32])
        self.assertEqual(got, [])

    def test_frames_of_other_sessions_do_not_cross(self):
        got = []
        _, srv = new_server(on_message=lambda sid, d: got.append((sid, d)))
        a, b = connect(srv), connect(srv)
        srv.handle_frame(a.seal(b"from a"))
        srv.handle_frame(b.seal(b"from b"))
        self.assertEqual(got, [(a.sid, b"from a"), (b.sid, b"from b")])
        # a frame re-labelled with another session id fails authentication
        fa = bytearray(a.seal(b"x"))
        fa[:8] = b.sid
        self.assertIsNone(srv.handle_frame(bytes(fa)))

    def test_client_cannot_decrypt_with_the_wrong_direction_key(self):
        """c2s and s2c keys are different: reflecting the client's own frame back must not verify."""
        _, srv = new_server()
        c = connect(srv)
        mine = bytearray(c.seal(b"reflect me"))
        mine[8] = P.T_S2C
        self.assertIsNone(c.open(bytes(mine)))

    def test_server_reply_replay_is_rejected_by_client(self):
        _, srv = new_server()
        c = connect(srv)
        reply = srv.handle_frame(c.seal(b"a"))
        self.assertEqual(c.open(reply), b"re:a")
        self.assertIsNone(c.open(reply))

    def test_handler_exception_does_not_stop_the_server(self):
        calls = []

        def boom(sid, d):
            calls.append(d)
            if d == b"bad":
                raise RuntimeError("bug")
            return b"ok"
        _, srv = new_server(on_message=boom)
        c = connect(srv)
        self.assertIsNone(srv.handle_frame(c.seal(b"bad")))
        self.assertEqual(c.open(srv.handle_frame(c.seal(b"good"))), b"ok")
        self.assertEqual(srv.stats["handler_error"], 1)

    def test_oversized_reply_is_dropped_not_crashed(self):
        _, srv = new_server(on_message=lambda sid, d: bytes(300))
        c = connect(srv)
        self.assertIsNone(srv.handle_frame(c.seal(b"x")))
        self.assertEqual(srv.stats["reply_too_large"], 1)

    def test_reply_types(self):
        _, srv = new_server(on_message=lambda sid, d: "text reply")
        c = connect(srv)
        self.assertEqual(c.open(srv.handle_frame(c.seal(b"x"))), b"text reply")
        _, srv = new_server(on_message=lambda sid, d: bytearray(b"ba"))
        c = connect(srv)
        self.assertEqual(c.open(srv.handle_frame(c.seal(b"x"))), b"ba")

    def test_unsupported_reply_type_is_contained(self):
        _, srv = new_server(on_message=lambda sid, d: 123)      # a handler bug: returns an int
        c = connect(srv)
        self.assertIsNone(srv.handle_frame(c.seal(b"x")))
        self.assertEqual(srv.stats["handler_error"], 1)
        self.assertIsNone(srv.handle_frame(c.seal(b"y")))        # and the server keeps working
        self.assertEqual(srv.stats["handler_error"], 2)

    def test_handler_and_on_message_are_exclusive(self):
        with self.assertRaises(ValueError):
            SecureServer(generate_static_key(), on_message=lambda s, d: None, handler=lambda s, d: None)

    def test_handler_receives_the_session(self):
        seen = []
        _, srv = new_server(on_message=None, handler=lambda s, d: (seen.append(s), None)[1])
        c = connect(srv)
        srv.handle_frame(c.seal(b"x"))
        self.assertEqual(seen[0].sid, c.sid)
        self.assertNotIn("k_c2s", repr(seen[0]))
        self.assertNotIn(srv._s.hex(), repr(srv))


class Push(unittest.TestCase):
    def test_server_initiated_messages_arrive_in_order(self):
        _, srv = new_server()
        c = connect(srv)
        f1, f2 = srv.seal(c.sid, b"first"), srv.seal(c.sid, b"second")
        self.assertEqual(c.open(f1), b"first")
        self.assertEqual(c.open(f2), b"second")
        self.assertIsNone(c.open(f1))                            # replay of a push

    def test_push_errors(self):
        _, srv = new_server()
        c = connect(srv)
        with self.assertRaises(UnknownSession):
            srv.seal(bytes(8), b"x")
        with self.assertRaises(MessageTooLarge):
            srv.seal(c.sid, bytes(287))
        self.assertEqual(c.open(srv.seal(c.sid.hex(), "str is fine")), b"str is fine")


class Limits(unittest.TestCase):
    def test_idle_sessions_expire(self):
        clock = Clock()
        _, srv = new_server(clock=clock, session_ttl=100, handshake_ttl=10)
        c = connect(srv)
        srv.handle_frame(c.seal(b"x"))
        clock.advance(99)
        self.assertIsNotNone(srv.handle_frame(c.seal(b"still here")))
        clock.advance(101)
        self.assertIsNone(srv.handle_frame(c.seal(b"too late")))
        self.assertEqual(srv.stats["session_expired"], 1)

    def test_unconfirmed_sessions_expire_fast(self):
        clock = Clock()
        _, srv = new_server(clock=clock, session_ttl=1000, handshake_ttl=10)
        c = ReferenceClient(srv.public_key)
        srv.handle_frame(c.hello())
        self.assertEqual(len(srv.sessions), 1)
        clock.advance(11)
        srv.sweep()
        self.assertEqual(len(srv.sessions), 0)

    def test_capacity_evicts_unconfirmed_before_real_users(self):
        clock = Clock()
        _, srv = new_server(clock=clock, max_sessions=3, hello_rate=1000, hello_burst=1000)
        real = connect(srv)
        srv.handle_frame(real.seal(b"hi"))             # confirmed
        clock.advance(500)                             # the real user is quiet for a while
        junk = [ReferenceClient(srv.public_key) for _ in range(5)]
        for j in junk:
            clock.advance(1)
            srv.handle_frame(j.hello())
        self.assertLessEqual(len(srv.sessions), 3)
        self.assertIsNotNone(srv.get_session(real.sid), "a confirmed session must survive a flood of fake handshakes")

    def test_hello_flood_is_rate_limited(self):
        clock = Clock()
        _, srv = new_server(clock=clock, hello_rate=1, hello_burst=5)
        made = sum(srv.handle_frame(ReferenceClient(srv.public_key).hello()) is not None for _ in range(50))
        self.assertEqual(made, 5)
        self.assertEqual(srv.stats["drop.hello_rate"], 45)
        clock.advance(3)
        self.assertIsNotNone(srv.handle_frame(ReferenceClient(srv.public_key).hello()))

    def test_retransmitted_hello_does_not_use_the_rate_limit(self):
        clock = Clock()
        _, srv = new_server(clock=clock, hello_rate=0.0001, hello_burst=1)
        c = ReferenceClient(srv.public_key)
        for _ in range(10):
            self.assertIsNotNone(srv.handle_frame(c.hello()))

    def test_per_session_message_rate_limit(self):
        clock = Clock()
        got = []
        _, srv = new_server(clock=clock, message_rate=1, message_burst=3, on_message=lambda s, d: got.append(d))
        c = connect(srv)
        for i in range(10):
            srv.handle_frame(c.seal(bytes([i])))
        self.assertEqual(len(got), 3)
        clock.advance(2)
        srv.handle_frame(c.seal(b"later"))
        self.assertEqual(got[-1], b"later")

    def test_global_frame_rate_guard(self):
        clock = Clock()
        _, srv = new_server(clock=clock, frame_rate=1, frame_burst=10)
        import os
        for _ in range(100):
            srv.handle_frame(os.urandom(41))
        self.assertGreaterEqual(srv.stats["drop.frame_rate"], 89)

    def test_callbacks(self):
        events = []
        clock = Clock()
        _, srv = new_server(clock=clock, session_ttl=5,
                            on_connect=lambda s: events.append(("connect", s.sid_hex)),
                            on_close=lambda s, why: events.append(("close", why)))
        c = connect(srv)
        self.assertEqual(events, [])                    # a handshake alone is not a "connection"
        srv.handle_frame(c.seal(b"a"))
        srv.handle_frame(c.seal(b"b"))
        self.assertEqual(events, [("connect", c.sid.hex())])
        clock.advance(10)
        srv.sweep()
        self.assertEqual(events[-1], ("close", "expired"))
        self.assertTrue(srv.close_session(c.sid) is False)

    def test_failing_callbacks_do_not_break_the_server(self):
        def bad(*a):
            raise RuntimeError("x")
        _, srv = new_server(on_connect=bad, on_close=bad)
        c = connect(srv)
        self.assertIsNotNone(srv.handle_frame(c.seal(b"a")))
        srv.close_session(c.sid)

    def test_close_session(self):
        _, srv = new_server()
        c = connect(srv)
        srv.handle_frame(c.seal(b"a"))
        self.assertTrue(srv.close_session(c.sid))
        self.assertIsNone(srv.handle_frame(c.seal(b"b")))


class Concurrency(unittest.TestCase):
    def test_many_threads(self):
        counts = []
        _, srv = new_server(on_message=lambda s, d: (counts.append(1), d)[1], message_rate=1e6, message_burst=1e6,
                            frame_rate=1e6, frame_burst=1e6, hello_rate=1e6, hello_burst=1e6)
        errors = []

        def worker():
            try:
                c = connect(srv)
                for i in range(20):
                    assert c.open(srv.handle_frame(c.seal(b"m%d" % i))) == b"m%d" % i
            except Exception as e:  # noqa: BLE001
                errors.append(e)
        ts = [threading.Thread(target=worker) for _ in range(8)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(errors, [])
        self.assertEqual(len(counts), 160)


if __name__ == "__main__":
    unittest.main()
