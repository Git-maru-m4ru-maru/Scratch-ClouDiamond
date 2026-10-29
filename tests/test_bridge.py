import _setup  # noqa: F401
import unittest

from cloudiamond_scratch import BridgeCore, CloudBridge, UnknownSession
from cloudiamond_scratch import protocol as P
from cloudiamond_scratch.bridge import short_name
from cloudiamond_scratch.refclient import ReferenceClient
from helpers import Clock, new_server

PFX = P.CLOUD_PREFIX


def client_write(core, frame: bytes, seq: int, *, prefix=PFX, initial=False):
    """What the Scratch client does: slots first, then HDR."""
    out = []
    slots = P.frame_to_slots(frame)
    for i, s in enumerate(slots):
        core.feed(prefix + P.VAR_C2S[i], s, initial=initial)
    out += core.feed(prefix + P.VAR_C2S_HDR, str(P.make_hdr(seq, len(slots))), initial=initial)
    return out


def frame_from_writes(writes):
    names = [n for n, _ in writes]
    assert names[-1].endswith(P.VAR_S2C_HDR), "HDR must be written last"
    hdr = P.parse_hdr(writes[-1][1])
    assert hdr and hdr[1] == len(writes) - 1
    return P.slots_to_frame([v for _, v in writes[:-1]])


class Core(unittest.TestCase):
    def test_handshake_and_message_through_the_core(self):
        _, srv = new_server()
        core = BridgeCore(srv, seq_start=10)
        c = ReferenceClient(srv.public_key)
        frames = client_write(core, c.hello(), 1)
        self.assertEqual(len(frames), 1)
        self.assertTrue(c.accept_reply(frame_from_writes(frames[0])))
        frames = client_write(core, c.seal(b"hi"), 2)
        self.assertEqual(c.open(frame_from_writes(frames[0])), b"re:hi")

    def test_slots_are_written_before_the_hdr_and_names_carry_the_prefix(self):
        _, srv = new_server()
        core = BridgeCore(srv)
        c = ReferenceClient(srv.public_key)
        writes = client_write(core, c.hello(), 1)[0]
        self.assertTrue(all(n.startswith(PFX) for n, _ in writes))
        n_slots = len(writes) - 1
        self.assertEqual(n_slots, 1)                              # a 73-byte REPLY fits one slot
        self.assertEqual([n[len(PFX):] for n, _ in writes], ["S2C_0", "S2C_HDR"])

    def test_unknown_variables_are_ignored(self):
        _, srv = new_server()
        core = BridgeCore(srv)
        for name in ("score", "☁ score", "C2S_X", "", "☁ "):
            self.assertEqual(core.feed(name, "123"), [])

    def test_name_forms(self):
        self.assertEqual(short_name("☁ C2S_HDR"), "C2S_HDR")
        self.assertEqual(short_name("C2S_HDR"), "C2S_HDR")
        self.assertEqual(short_name("☁C2S_HDR"), "C2S_HDR")
        _, srv = new_server()
        core = BridgeCore(srv)
        c = ReferenceClient(srv.public_key)
        self.assertEqual(len(client_write(core, c.hello(), 1, prefix="")), 1)     # names without the cloud mark work too

    def test_initial_snapshot_values_are_not_processed(self):
        got = []
        _, srv = new_server(on_message=lambda s, d: got.append(d))
        core = BridgeCore(srv)
        c = ReferenceClient(srv.public_key)
        self.assertEqual(client_write(core, c.hello(), 1, initial=True), [])
        self.assertEqual(srv.stats["hello"], 0)
        # but the values are remembered, so the next live HDR change works on them
        self.assertEqual(len(client_write(core, c.hello(), 2)), 1)

    def test_bad_hdr_and_bad_slots_are_dropped(self):
        _, srv = new_server()
        core = BridgeCore(srv)
        for hdr in ("", "x", "5", "100000009", "100000000"):
            self.assertEqual(core.feed(PFX + P.VAR_C2S_HDR, hdr), [])
        core.feed(PFX + P.VAR_C2S[0], "1abc")
        self.assertEqual(core.feed(PFX + P.VAR_C2S_HDR, str(P.make_hdr(1, 1))), [])
        self.assertGreaterEqual(srv.stats["drop.bad_hdr"], 4)
        self.assertEqual(srv.stats["drop.bad_slots"], 1)

    def test_numbers_are_accepted_as_values(self):
        _, srv = new_server()
        core = BridgeCore(srv)
        c = ReferenceClient(srv.public_key)
        slots = P.frame_to_slots(c.hello())
        for i, s in enumerate(slots):
            core.feed(PFX + P.VAR_C2S[i], s)
        self.assertEqual(len(core.feed(PFX + P.VAR_C2S_HDR, P.make_hdr(1, len(slots)))), 1)       # int
        self.assertEqual(len(core.feed(PFX + P.VAR_C2S_HDR, float(P.make_hdr(2, len(slots))))), 1)  # float

    def test_s2c_hdr_changes_on_every_frame_even_on_wraparound_collision(self):
        _, srv = new_server()
        core = BridgeCore(srv, seq_start=999_999)
        c = ReferenceClient(srv.public_key)
        hdrs = []
        f = client_write(core, c.hello(), 1)
        hdrs.append(f[0][-1][1])
        c.accept_reply(frame_from_writes(f[0]))
        for i in range(6):
            f = client_write(core, c.seal(b"m"), 10 + i)
            hdrs.append(f[0][-1][1])
        for a, b in zip(hdrs, hdrs[1:]):
            self.assertNotEqual(a, b)

    def test_hdr_never_equals_the_value_already_in_the_cloud(self):
        """After a server restart the cloud still holds the old S2C_HDR; a new frame must not reuse that exact value."""
        _, srv = new_server()
        core = BridgeCore(srv, seq_start=0)
        c = ReferenceClient(srv.public_key)
        # the first frame would get seq 1 and 1 slot -> exactly this value, already present in the cloud:
        stale = str(P.make_hdr(1, 1))
        core.feed(PFX + P.VAR_S2C_HDR, stale, initial=True)
        frames = client_write(core, c.hello(), 1)
        self.assertNotEqual(frames[0][-1][1], stale)

    def test_sequence_start_is_random(self):
        _, srv = new_server()
        starts = {BridgeCore(srv)._seq for _ in range(30)}
        self.assertGreater(len(starts), 20)
        self.assertTrue(all(1 <= s <= 900_000 for s in starts))

    def test_push(self):
        _, srv = new_server()
        core = BridgeCore(srv)
        c = ReferenceClient(srv.public_key)
        c.accept_reply(frame_from_writes(client_write(core, c.hello(), 1)[0]))
        out = core.push(c.sid, b"hello client")
        self.assertEqual(c.open(frame_from_writes(out[0])), b"hello client")
        with self.assertRaises(UnknownSession):
            core.push(bytes(8), b"x")


class Callback(unittest.TestCase):
    def test_writes_go_to_the_callback_in_order(self):
        _, srv = new_server()
        written = []
        bridge = CloudBridge(srv, lambda n, v: written.append((n, v)))
        c = ReferenceClient(srv.public_key)
        for i, s in enumerate(P.frame_to_slots(c.hello())):
            bridge.on_variable(PFX + P.VAR_C2S[i], s)
        bridge.on_variable(PFX + P.VAR_C2S_HDR, str(P.make_hdr(1, 1)))
        self.assertTrue(c.accept_reply(frame_from_writes(written)))

    def test_min_interval_spaces_frames(self):
        _, srv = new_server()
        clock = Clock()
        sleeps = []
        bridge = CloudBridge(srv, lambda n, v: None, min_interval=0.25, clock=clock,
                             sleep=lambda s: (sleeps.append(s), clock.advance(s)))
        c = ReferenceClient(srv.public_key)
        for i, s in enumerate(P.frame_to_slots(c.hello())):
            bridge.on_variable(PFX + P.VAR_C2S[i], s)
        bridge.on_variable(PFX + P.VAR_C2S_HDR, str(P.make_hdr(1, 1)))   # first frame: no wait
        self.assertEqual(sleeps, [])
        sid = srv.sessions[0].sid
        bridge.push(sid, b"a")
        bridge.push(sid, b"b")
        self.assertEqual(len(sleeps), 2)
        self.assertAlmostEqual(sleeps[0], 0.25, places=6)

    def test_push_unknown_session(self):
        _, srv = new_server()
        bridge = CloudBridge(srv, lambda n, v: None)
        with self.assertRaises(UnknownSession):
            bridge.push(bytes(8), b"x")


if __name__ == "__main__":
    unittest.main()
