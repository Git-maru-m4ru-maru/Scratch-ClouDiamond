"""Interoperability and attack tests that run the REAL compiled Scratch client blocks (in the test VM)
against the Python server. This is the core evidence that both halves speak the same protocol."""
import _setup  # noqa: F401
import unittest

from cloudiamond_scratch import sb3, text
from cloudiamond_scratch import protocol as P
from harness import deliver_frame_to_client, frames_in_log, make_client, zero_lists
from scratch_vm import StopScript

KEY_LISTS = ["EK", "DHES", "DHEE", "MASTER", "HCK", "HCO", "XK", "XOUT"]
SESSION_KEY_LISTS = ["KC2S", "KS2C", "AK"]


def connected(vm) -> bool:
    return float(vm.var("🔒 connected")) == 1


def got(vm) -> bool:
    return float(vm.var("🔒 got message")) == 1


class Basics(unittest.TestCase):
    def test_connect_and_echo(self):
        vm, srv, sim, _ = make_client()
        vm.call("🔒 connect")
        self.assertTrue(connected(vm))
        self.assertEqual(vm.var("🔒 status"), "connected (server verified)")
        vm.call("🔒 send text %s", "hello scratch 123!")
        vm.call("🔒 wait for message (max %s sec)", 5.0)
        self.assertTrue(got(vm))
        self.assertEqual(vm.var("🔒 received text"), "re:hello scratch 123!")
        self.assertEqual(srv.stats["session_new"], 1)

    def test_request_block(self):
        vm, srv, sim, _ = make_client()
        vm.call("🔒 connect")
        vm.call("🔒 request %s (max %s sec)", "ping 42", 5.0)
        self.assertTrue(got(vm))
        self.assertEqual(vm.var("🔒 received text"), "re:ping 42")

    def test_handshake_keys_are_wiped_but_session_keys_work(self):
        vm, srv, sim, _ = make_client()
        vm.call("🔒 connect")
        self.assertTrue(zero_lists(vm, KEY_LISTS), "ephemeral/handshake secrets must be erased after the handshake")
        self.assertFalse(zero_lists(vm, ["KC2S"]), "session keys must exist while connected")

    def test_many_messages_and_counters(self):
        vm, srv, sim, _ = make_client()
        vm.call("🔒 connect")
        for i in range(12):
            vm.call("🔒 request %s (max %s sec)", f"msg {i}", 5.0)
            self.assertEqual(vm.var("🔒 received text"), f"re:msg {i}")
        s2c_hdrs = [v for d, n, v in sim.log if d == "s2c" and "S2C_HDR" in n]
        self.assertEqual(len(s2c_hdrs), len(set(s2c_hdrs)), "every server frame must have a fresh HDR value")
        self.assertEqual(srv.stats["data"], 12)

    def test_japanese_text_round_trip(self):
        seen = []
        vm, srv, sim, _ = make_client(handler=lambda sid, d: (seen.append(text.decode(d)), b"> " + d)[1])
        vm.call("🔒 connect")
        msg = "こんにちは、セカイ！ Hello 123 テスト？"
        vm.call("🔒 request %s (max %s sec)", msg, 5.0)
        self.assertEqual(seen, ["こんにちは、セカイ！ hello 123 テスト？"])      # uppercase -> lowercase (Scratch limitation)
        self.assertEqual(vm.var("🔒 received text"), "> こんにちは、セカイ！ hello 123 テスト？")

    def test_unsupported_characters_become_question_marks(self):
        seen = []
        vm, srv, sim, _ = make_client(handler=lambda sid, d: seen.append(text.decode(d)))
        vm.call("🔒 connect")
        vm.call("🔒 send text %s", "漢字abc")
        self.assertEqual(seen, ["??abc"])

    def test_largest_messages_fit(self):
        vm, srv, sim, _ = make_client(handler=lambda sid, d: d)
        vm.call("🔒 connect")
        vm.call("🔒 request %s (max %s sec)", "x" * 286, 10.0)
        self.assertEqual(vm.var("🔒 received text"), "x" * 286)
        frames = frames_in_log(sim.log, "c2s")
        self.assertEqual(max(len(f) for f in frames), 15 + 288 + 16)
        self.assertEqual(len(P.frame_to_slots(frames[-1])), 4)

    def test_input_longer_than_the_limit_is_truncated_not_corrupted(self):
        seen = []
        vm, srv, sim, _ = make_client(handler=lambda sid, d: seen.append(d))
        vm.call("🔒 connect")
        vm.call("🔒 send text %s", "y" * 400)
        self.assertEqual(seen, [b"y" * 286])

    def test_server_initiated_push(self):
        vm, srv, sim, _ = make_client()
        vm.call("🔒 connect")
        sid = srv.sessions[0].sid
        sim.bridge.push(sid, text.encode("news: server says hi"))
        vm.call("🔒 wait for message (max %s sec)", 5.0)
        self.assertTrue(got(vm))
        self.assertEqual(vm.var("🔒 received text"), "news: server says hi")

    def test_two_clients_are_isolated(self):
        results = {}
        vm1, srv1, sim1, secret = make_client(handler=lambda sid, d: b"1:" + d, seed=1)
        # second client talks to the SAME server object through its own cloud simulation
        from harness import CloudSim
        from scratch_vm import VM
        from cloudiamond_scratch import CloudBridge, public_key
        vm2 = VM(sb3.build_project(public_key(secret)), seed=2)
        CloudSim(vm2, lambda w: CloudBridge(srv1, w))
        vm1.call("🔒 connect")
        vm2.call("🔒 connect")
        self.assertEqual(len(srv1.sessions), 2)
        self.assertNotEqual(srv1.sessions[0].sid, srv1.sessions[1].sid)
        vm1.call("🔒 request %s (max %s sec)", "aaa", 5.0)
        vm2.call("🔒 request %s (max %s sec)", "bbb", 5.0)
        self.assertEqual(vm1.var("🔒 received text"), "1:aaa")
        self.assertEqual(vm2.var("🔒 received text"), "1:bbb")

    def test_disconnect_wipes_and_blocks_sending(self):
        vm, srv, sim, _ = make_client()
        vm.call("🔒 connect")
        vm.call("🔒 disconnect")
        self.assertTrue(zero_lists(vm, KEY_LISTS + SESSION_KEY_LISTS))
        before = srv.stats["data"] + srv.stats["drop.auth"]
        vm.call("🔒 send text %s", "should not be sent")
        self.assertEqual(srv.stats["data"] + srv.stats["drop.auth"], before)
        vm.call("🔒 connect")
        self.assertTrue(connected(vm))
        self.assertEqual(len(srv.sessions), 2, "a reconnect is a new session with new keys")

    def test_demo_script(self):
        vm, srv, sim, _ = make_client(demo=True)
        vm.answers = ["hello there", "second"]
        with self.assertRaises(StopScript):
            vm.run_flag()
        self.assertIn("re:hello there", vm.said)
        self.assertIn("re:second", vm.said)
        self.assertIn("connected (server verified)", vm.said)


class Reliability(unittest.TestCase):
    def test_lost_hello_is_retransmitted(self):
        vm, srv, sim, _ = make_client()
        n = {"c": 0}

        def lose_first(name, value):
            if "C2S_HDR" in name:
                n["c"] += 1
                return n["c"] == 1
            return False
        sim.drop_c2s = lose_first
        vm.call("🔒 connect")
        self.assertTrue(connected(vm))
        self.assertEqual(float(vm.var("ss_connect.sends")), 2)
        self.assertEqual(srv.stats["session_new"], 1)

    def test_lost_replies_are_answered_from_the_server_cache(self):
        vm, srv, sim, _ = make_client()
        n = {"c": 0}

        def lose_two(name, value):
            if "S2C_HDR" in name:
                n["c"] += 1
                return n["c"] <= 2
            return False
        sim.drop_s2c = lose_two
        vm.call("🔒 connect")
        self.assertTrue(connected(vm))
        self.assertEqual(srv.stats["hello_retransmit"], 2)
        self.assertEqual(srv.stats["session_new"], 1)

    def test_gives_up_cleanly_when_no_server_answers(self):
        vm, srv, sim, _ = make_client()
        sim.drop_c2s = lambda n, v: True
        vm.call("🔒 connect")
        self.assertFalse(connected(vm))
        self.assertEqual(vm.var("🔒 status"), "FAILED: server not verified")
        self.assertEqual(float(vm.var("ss_connect.sends")), 3, "at most 3 HELLOs")
        self.assertTrue(zero_lists(vm, KEY_LISTS + SESSION_KEY_LISTS))
        self.assertLess(vm.now, 40, "must not hang")

    def test_works_with_network_latency(self):
        vm, srv, sim, _ = make_client(latency=0.4)
        vm.call("🔒 connect")
        self.assertTrue(connected(vm))
        vm.call("🔒 request %s (max %s sec)", "slow link", 10.0)
        self.assertEqual(vm.var("🔒 received text"), "re:slow link")

    def test_wait_times_out_without_a_reply(self):
        vm, srv, sim, _ = make_client(handler=lambda sid, d: None)
        vm.call("🔒 connect")
        vm.call("🔒 request %s (max %s sec)", "anyone?", 3.0)
        self.assertFalse(got(vm))
        self.assertEqual(vm.var("🔒 received text"), "")


class Attacks(unittest.TestCase):
    def test_client_refuses_an_impostor_server(self):
        """The server does not hold the private key matching the embedded public key."""
        vm, srv, sim, _ = make_client(server_secret=b"\x42" * 32)
        vm.call("🔒 connect")
        self.assertFalse(connected(vm))
        self.assertEqual(vm.var("🔒 status"), "FAILED: server not verified")
        self.assertTrue(zero_lists(vm, KEY_LISTS + SESSION_KEY_LISTS))
        vm.call("🔒 send text %s", "my secret")
        self.assertEqual(srv.stats["data"], 0, "nothing may be sent to an unverified server")

    def test_tampered_reply_is_refused(self):
        vm, srv, sim, _ = make_client()

        def flip_digit(name, value):
            if name.endswith("S2C_0"):
                d = "5" if value[100] != "5" else "6"
                value = value[:100] + d + value[101:]
                vm.set_cloud(name, value)
                return True            # we wrote the altered value ourselves
            return False
        sim.drop_s2c = flip_digit
        vm.call("🔒 connect")
        self.assertFalse(connected(vm))
        self.assertTrue(zero_lists(vm, KEY_LISTS + SESSION_KEY_LISTS))

    def test_stale_reply_from_an_old_session_is_ignored(self):
        vm0, srv0, sim0, secret = make_client(seed=11)
        vm0.call("🔒 connect")
        old_reply = frames_in_log(sim0.log, "s2c")[0]
        vm, srv, sim, _ = make_client(secret=secret, seed=12)
        injected = {"done": False}

        def inject_first(name, value):
            if "S2C" in name and not injected["done"] and name.endswith("S2C_HDR"):
                injected["done"] = True
                deliver_frame_to_client(vm, old_reply, 777)       # attacker replays an old genuine reply
                return True                                       # ...and the real one is lost
            return name.endswith(("S2C_0", "S2C_1", "S2C_2", "S2C_3")) and not injected["done"]
        sim.drop_s2c = inject_first
        vm.call("🔒 connect")
        self.assertTrue(connected(vm), "the client must still connect once the real reply (retransmit) arrives")

    def test_replayed_client_frames_are_dropped_by_the_server(self):
        calls = []
        vm, srv, sim, _ = make_client(handler=lambda sid, d: (calls.append(d), b"ok")[1])
        vm.call("🔒 connect")
        vm.call("🔒 send text %s", "transfer 100")
        frame = frames_in_log(sim.log, "c2s")[-1]
        slots = P.frame_to_slots(frame)
        for rep in range(3):                                       # attacker replays the captured frame
            for i, s in enumerate(slots):
                sim.bridge.on_variable(P.CLOUD_PREFIX + P.VAR_C2S[i], s)
            sim.bridge.on_variable(P.CLOUD_PREFIX + P.VAR_C2S_HDR, str(P.make_hdr(900 + rep, len(slots))))
        self.assertEqual(len(calls), 1)
        self.assertEqual(srv.stats["drop.replay"], 3)

    def test_server_frames_cannot_be_replayed_to_the_client(self):
        vm, srv, sim, _ = make_client()
        vm.call("🔒 connect")
        sim.bridge.push(srv.sessions[0].sid, text.encode("one"))
        vm.call("🔒 wait for message (max %s sec)", 3.0)
        self.assertEqual(vm.var("🔒 received text"), "one")
        push_frame = frames_in_log(sim.log, "s2c")[-1]
        deliver_frame_to_client(vm, push_frame, 4242)               # replay the same genuine frame
        vm.call("🔒 wait for message (max %s sec)", 3.0)
        self.assertFalse(got(vm), "a replayed server frame must not be accepted twice")

    def test_reflected_client_frame_is_not_accepted_as_server_frame(self):
        vm, srv, sim, _ = make_client()
        vm.call("🔒 connect")
        vm.call("🔒 send text %s", "reflect me")
        mine = bytearray(frames_in_log(sim.log, "c2s")[-1])
        mine[8] = P.T_S2C                                           # pretend it came from the server
        deliver_frame_to_client(vm, bytes(mine), 5151)
        vm.call("🔒 wait for message (max %s sec)", 3.0)
        self.assertFalse(got(vm))

    def test_garbage_in_cloud_variables_is_ignored(self):
        vm, srv, sim, _ = make_client()
        vm.call("🔒 connect")
        for junk in ("", "abc", "1" + "9" * 252, "0", "-5", "1.5e3", "1000" * 70):
            vm.set_cloud("\u2601 S2C_0", junk)
            vm.set_cloud("\u2601 S2C_HDR", str(P.make_hdr(123 + len(junk), 1)))
            vm.call("🔒 wait for message (max %s sec)", 1.0)
            self.assertFalse(got(vm), junk[:10])
        vm.call("🔒 request %s (max %s sec)", "still alive", 5.0)
        self.assertEqual(vm.var("🔒 received text"), "re:still alive")

    def test_an_eavesdropper_sees_no_plaintext(self):
        secrets_seen = ["hunter2-password", "very-private-reply"]
        vm, srv, sim, _ = make_client(handler=lambda sid, d: text.encode("very-private-reply"))
        vm.call("🔒 connect")
        vm.call("🔒 request %s (max %s sec)", "hunter2-password", 5.0)
        c2s, s2c = frames_in_log(sim.log, "c2s"), frames_in_log(sim.log, "s2c")
        self.assertEqual([len(f) for f in c2s], [41, 63])      # HELLO, one data frame
        self.assertEqual([len(f) for f in s2c], [73, 63])      # REPLY, one data frame
        wire = b"".join(c2s + s2c)
        for s in secrets_seen:
            self.assertNotIn(s.encode(), wire)
            self.assertNotIn(text.encode(s), wire)


class SavedProject(unittest.TestCase):
    def test_audit_flags_a_project_saved_while_connected_and_passes_after_wipe(self):
        vm, srv, sim, _ = make_client()
        vm.call("🔒 connect")
        vm.call("🔒 request %s (max %s sec)", "my password is hunter2", 5.0)
        dirty = vm.export_project()
        self.assertEqual(sb3.lint_project(dirty), [])
        rep = sb3.audit_project(dirty)
        self.assertTrue(rep.critical)
        self.assertFalse(rep.ok)
        names = " ".join(f.what for f in rep.findings if f.severity == "critical")
        for k in ("KC2S", "KS2C", "AK"):
            self.assertIn(f"'{k}'", names)
        vm.call("🔒 wipe secrets")
        clean = vm.export_project()
        rep2 = sb3.audit_project(clean)
        self.assertTrue(rep2.ok, [str(f) for f in rep2.findings if f.severity != "info"])
        self.assertEqual(vm.var("🔒 received text"), "")

    def test_a_fresh_build_passes_audit_and_verify(self):
        vm, srv, sim, secret = make_client()
        rep = sb3.audit_project(vm.project)
        self.assertTrue(rep.ok)


if __name__ == "__main__":
    unittest.main()
