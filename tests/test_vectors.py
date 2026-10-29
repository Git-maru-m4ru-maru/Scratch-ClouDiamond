"""Fixed-input test vectors (also printed in docs/PROTOCOL.md).

Both the Python implementation and the compiled Scratch blocks must reproduce them exactly, which makes them
usable by anyone writing a third implementation.
"""
import _setup  # noqa: F401
import unittest

from cloudiamond_scratch import SecureServer, crypto as C, protocol as P, sb3, server as server_module
from cloudiamond_scratch.refclient import ReferenceClient
from scratch_vm import VM

V = dict(
    s="0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
    e="2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40",
    r="4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60",
    S="07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c",
    E="5869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b",
    R="64b101b1d0be5a8704bd078f9895001fc03e8e9f9522f188dd128d9846d48466",
    sid="5869aff450549732",
    dh_es="a84dc7c3c8f058b1b2dc4cd1e9b5dc0a7987f88b6a9564cde3391fc421159e77",
    dh_ee="b6ddcb217f2edb78fe01f0d967925f1e3fda132789e4566ddc2abcd3e2fd9526",
    master="cad8478268edb88363b63919faed32a0272d3fa7c381946ac09891adcf0cdac4",
    k_c2s="7948efaae553e5ac95e3ef01d9e08c7c1fb28cd5a0be9eb3333945538f22983b",
    k_s2c="7c2324249956b8f2ec329740bd95ba19bc85faee18711e2547f7b1f8796f4982",
    hello="5869aff450549732015869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b",
    reply="5869aff4505497320264b101b1d0be5a8704bd078f9895001fc03e8e9f9522f188dd128d9846d484661ddfe6c479057bdecf1b9abb7913c54961bb7aa6f5cb302ff0dd63d44d84ecbd",
    c2s="5869aff450549732030000000000017f94cb573006fc3c6366491e72fb67f610f1ef605215e2d35a6cb7f2f75d1b6fa528d23f2aaca47797d9cbed527ac4cd",
    s2c="5869aff450549732040000000000015d04f3144d81655aa9ebbd951ff4edf46a6d0e2aeb5b14a51bc156cad199b72646fcda8d0d5e42f2fc07a2095668fbac",
)
b = {k: bytes.fromhex(v) for k, v in V.items()}


def data_frame(key, typ, ctr, msg):
    h = b["sid"] + bytes([typ]) + ctr.to_bytes(6, "big")
    return h + C.aead_seal(key, P.data_nonce(ctr), h, P.pad_message(msg))


class PythonImplementation(unittest.TestCase):
    def test_key_agreement(self):
        self.assertEqual(C.x25519_public(b["s"]), b["S"])
        self.assertEqual(C.x25519_public(b["e"]), b["E"])
        self.assertEqual(C.x25519_public(b["r"]), b["R"])
        self.assertEqual(b["sid"], b["E"][:8])
        self.assertEqual(C.x25519_shared(b["s"], b["E"]), b["dh_es"])
        self.assertEqual(C.x25519_shared(b["e"], b["S"]), b["dh_es"])
        self.assertEqual(C.x25519_shared(b["r"], b["E"]), b["dh_ee"])
        self.assertEqual(C.x25519_shared(b["e"], b["R"]), b["dh_ee"])

    def test_key_schedule(self):
        master, kc, ks = C.derive_keys(b["dh_es"], b["dh_ee"])
        self.assertEqual((master, kc, ks), (b["master"], b["k_c2s"], b["k_s2c"]))

    def test_frames(self):
        self.assertEqual(b["hello"], b["sid"] + b"\x01" + b["E"])
        reply = b["sid"] + b"\x02" + b["R"] + C.aead_seal(b["k_s2c"], bytes(12), b["sid"] + b"\x02" + b["E"] + b["R"], C.READY)
        self.assertEqual(reply, b["reply"])
        self.assertEqual(data_frame(b["k_c2s"], 3, 1, b"hello"), b["c2s"])
        self.assertEqual(data_frame(b["k_s2c"], 4, 1, b"world"), b["s2c"])

    def test_server_produces_exactly_this_reply(self):
        original = server_module.generate_secret
        server_module.generate_secret = lambda: b["r"]              # pin the server's one-time key
        try:
            srv = SecureServer(b["s"], on_message=lambda sid, d: b"world")
            self.assertEqual(srv.handle_frame(b["hello"]), b["reply"])
            self.assertEqual(srv.handle_frame(b["c2s"]), b["s2c"])  # and its first answer is byte-identical too
        finally:
            server_module.generate_secret = original

    def test_reference_client_accepts_the_vector(self):
        c = ReferenceClient(C.x25519_public(b["s"]), ephemeral_secret=b["e"])
        self.assertEqual(c.hello(), b["hello"])
        self.assertTrue(c.accept_reply(b["reply"]))
        self.assertEqual(c.seal(b"hello"), b["c2s"])
        self.assertEqual(c.open(b["s2c"]), b"world")

    def test_header_and_slot_examples(self):
        self.assertEqual(P.make_hdr(7, 1), 100000701)
        self.assertEqual(P.frame_to_slots(b["hello"])[0][:13], "1088105175244")      # "1" + 088 105 175 244 ...
        self.assertEqual(len(P.frame_to_slots(b["hello"])[0]), 1 + 3 * 41)


class ScratchBlocks(unittest.TestCase):
    """The compiled client blocks given the same fixed state."""

    def vm(self):
        vm = VM(sb3.build_project(b["S"], demo=False), seed=1)
        self.put = lambda name, data: [vm.list(name).__setitem__(i, float(x)) for i, x in enumerate(data)]
        self.get = lambda name, n: bytes(int(float(x)) for x in vm.list(name)[:n])
        return vm

    def test_derive_and_verify_reproduces_the_key_schedule(self):
        vm = self.vm()
        self.put("EK", b["e"])
        self.put("EP", b["E"])
        self.put("SID", b["sid"])
        self.put("RXF", b["reply"])
        vm.set_var("RXL", 73.0)
        vm.call("ss_ss derive and verify")
        self.assertEqual(str(vm.var("🔒 connected")), "1", "the Scratch client must accept the reference REPLY")
        self.assertEqual(self.get("KC2S", 32), b["k_c2s"])
        self.assertEqual(self.get("KS2C", 32), b["k_s2c"])

    def test_seal_reproduces_the_client_to_server_frame(self):
        vm = self.vm()
        self.put("EK", b["e"]); self.put("EP", b["E"]); self.put("SID", b["sid"]); self.put("RXF", b["reply"])
        vm.set_var("RXL", 73.0)
        vm.call("ss_ss derive and verify")
        vm.list("🔒 TX bytes").clear()
        vm.list("🔒 TX bytes").extend(float(x) for x in b"hello")
        vm.call("ss_ss seal")
        n = int(float(vm.var("TXL")))
        self.assertEqual(self.get("TXF", n), b["c2s"])

    def test_open_decrypts_the_server_to_client_frame(self):
        vm = self.vm()
        self.put("EK", b["e"]); self.put("EP", b["E"]); self.put("SID", b["sid"]); self.put("RXF", b["reply"])
        vm.set_var("RXL", 73.0)
        vm.call("ss_ss derive and verify")
        self.put("RXF", b["s2c"])
        vm.set_var("RXL", float(len(b["s2c"])))
        vm.call("ss_ss open")
        self.assertEqual(bytes(int(float(x)) for x in vm.list("🔒 RX bytes")), b"world")

    def test_the_scratch_client_rejects_a_reply_made_for_another_key(self):
        vm = self.vm()
        other = bytearray(b["reply"])
        other[-1] ^= 1
        self.put("EK", b["e"]); self.put("EP", b["E"]); self.put("SID", b["sid"]); self.put("RXF", bytes(other))
        vm.set_var("RXL", 73.0)
        vm.call("ss_ss derive and verify")
        self.assertNotEqual(str(vm.var("🔒 connected")), "1")


if __name__ == "__main__":
    unittest.main()
