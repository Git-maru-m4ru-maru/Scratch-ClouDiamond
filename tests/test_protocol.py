import _setup  # noqa: F401
import unittest

from cloudiamond_scratch import protocol as P


class Slots(unittest.TestCase):
    def test_slot_format(self):
        self.assertEqual(P.encode_slot(b"\x00\x01\xff"), "1000001255")
        self.assertEqual(len(P.encode_slot(bytes(84))), 253)           # 1 + 84*3, fits a 256-char variable

    def test_roundtrip_every_byte_value(self):
        data = bytes(range(256))
        for size in (1, 2, 83, 84, 85, 168, 200, 252, 336):
            frame = (data * 2)[:size]
            self.assertEqual(P.slots_to_frame(P.frame_to_slots(frame)), frame, size)

    def test_frame_limits(self):
        with self.assertRaises(ValueError):
            P.frame_to_slots(b"")
        with self.assertRaises(ValueError):
            P.frame_to_slots(bytes(337))
        self.assertEqual(len(P.frame_to_slots(bytes(336))), 4)

    def test_malformed_slots_are_rejected(self):
        self.assertEqual(P.decode_slot("1"), b"")               # an empty slot is legal
        bad = ["", "0001", "1ab", "1000256", "10001", "1" + "000" * 85, "１000", "1-00", None, " 1000", "1000 "]
        for s in bad:
            self.assertIsNone(P.decode_slot(s), repr(s))

    def test_numeric_slot_values_from_json_are_accepted(self):
        self.assertEqual(P.decode_slot(1000001), b"\x00\x01")
        self.assertIsNone(P.decode_slot(True))

    def test_empty_or_too_many_slots(self):
        self.assertIsNone(P.slots_to_frame([]))
        self.assertIsNone(P.slots_to_frame(["1001"] * 5))
        self.assertIsNone(P.slots_to_frame(["1"]))               # decodes to nothing -> no frame


class Header(unittest.TestCase):
    def test_make_and_parse(self):
        for seq in (0, 1, 999_999, 1_000_000, 123_456):
            for n in (1, 2, 3, 4):
                self.assertEqual(P.parse_hdr(P.make_hdr(seq, n)), (seq % 1_000_000, n))

    def test_value_matches_scratch_formula(self):
        # the client computes: 100000000 + ((SEQ % 1000000) * 100) + n
        self.assertEqual(P.make_hdr(5, 2), 100_000_000 + 5 * 100 + 2)

    def test_garbage_is_rejected(self):
        for v in ("", "abc", "0", 5, "99999999", "200000000", "100000000", "100000005", None, True, "1e8", -100000001):
            self.assertIsNone(P.parse_hdr(v), repr(v))

    def test_accepts_string_or_number(self):
        self.assertEqual(P.parse_hdr("100000102"), (1, 2))
        self.assertEqual(P.parse_hdr(100000102), (1, 2))
        self.assertEqual(P.parse_hdr(100000102.0), (1, 2))

    def test_slot_count_bounds(self):
        with self.assertRaises(ValueError):
            P.make_hdr(1, 0)
        with self.assertRaises(ValueError):
            P.make_hdr(1, 5)


class Message(unittest.TestCase):
    def test_pad_unpad(self):
        for n in (0, 1, 29, 30, 31, 62, 286):
            data = bytes(range(n % 256)) * (n // 256 + 1)
            data = data[:n]
            padded = P.pad_message(data)
            self.assertEqual(len(padded) % 32, 0)
            self.assertEqual(P.unpad_message(padded), data)

    def test_limits(self):
        self.assertEqual(P.MAX_MESSAGE, 286)
        self.assertEqual(len(P.pad_message(bytes(286))), 288)
        with self.assertRaises(ValueError):
            P.pad_message(bytes(287))
        # the largest message still fits into 4 slots: 15 + 288 + 16 = 319 <= 336
        self.assertLessEqual(P.HEADER_LEN + 288 + P.TAG_LEN, P.MAX_FRAME)

    def test_unpad_rejects_inconsistent_length(self):
        self.assertIsNone(P.unpad_message(b"\x01\x00" + bytes(30)))   # claims 256 bytes in a 32-byte block
        self.assertIsNone(P.unpad_message(bytes(31)))
        self.assertIsNone(P.unpad_message(b""))

    def test_nonce_layout(self):
        self.assertEqual(P.data_nonce(1), bytes(11) + b"\x01")
        self.assertEqual(P.data_nonce(0x0102030405), bytes(6) + bytes([0, 1, 2, 3, 4, 5]))
        self.assertEqual(len(P.data_nonce(P.CTR_MAX)), 12)


if __name__ == "__main__":
    unittest.main()
