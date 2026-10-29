"""The test VM must follow Scratch's documented semantics, otherwise passing tests would prove little."""
import _setup  # noqa: F401
import math
import unittest

from scratch_vm import (DIV, EQ, FLOOR, GT, INDEXOF, ITEM, LETTER, LT, MOD, N, S, SETITEM, UnsupportedBlock, VM,
                        compare, fmt_num, js_number)


class Cast(unittest.TestCase):
    def test_to_number(self):
        self.assertEqual(N("12"), 12)
        self.assertEqual(N(" 12 "), 12)
        self.assertEqual(N("1e3"), 1000)
        self.assertEqual(N("0x10"), 16)
        self.assertEqual(N(".5"), 0.5)
        for junk in ("abc", "", "1_000", "nan", "12abc", None):
            self.assertEqual(N(junk), 0, repr(junk))
        self.assertEqual(N(True), 1)
        self.assertTrue(math.isnan(js_number("abc")))

    def test_to_string(self):
        self.assertEqual(S(5.0), "5")
        self.assertEqual(S(-0.0), "0")
        self.assertEqual(S(0.5), "0.5")
        self.assertEqual(S(1e21), "1e+21")
        self.assertEqual(S("x"), "x")
        self.assertEqual(S(True), "true")
        self.assertEqual(fmt_num(float("inf")), "Infinity")

    def test_compare_is_case_insensitive_and_numeric_aware(self):
        self.assertTrue(EQ("a", "A"))
        self.assertTrue(EQ("1", 1.0))
        self.assertTrue(EQ("1.0", "1"))
        self.assertTrue(GT("10", "9"), "numbers compare numerically")
        self.assertTrue(LT("abc", "abd"))
        self.assertFalse(EQ("", 0), "empty string is not the number 0 in Scratch")
        self.assertFalse(EQ(" ", 0))
        self.assertTrue(EQ("0", 0))
        self.assertTrue(EQ("ひ", "ひ"))
        self.assertFalse(EQ("あ", "ア"))

    def test_math(self):
        self.assertEqual(MOD(-1, 3), 2)
        self.assertEqual(MOD(5, 3), 2)
        self.assertEqual(MOD(5, -3), -1)
        self.assertTrue(math.isnan(MOD(5, 0)))
        self.assertEqual(MOD(1099511627776.0 * 5 + 7, 256), 7)
        self.assertEqual(FLOOR(-0.5), -1)
        self.assertEqual(FLOOR(3.999), 3)
        self.assertEqual(DIV(1, 0), float("inf"))
        self.assertEqual(DIV(-1, 0), float("-inf"))
        self.assertTrue(math.isnan(DIV(0, 0)))
        # doubles are exact up to 2**53 (the client relies on that)
        self.assertEqual((2 ** 53 - 1) + 0.0, float(2 ** 53 - 1))

    def test_strings_and_lists(self):
        self.assertEqual(LETTER(1, "abc"), "a")
        self.assertEqual(LETTER(3, "abc"), "c")
        self.assertEqual(LETTER(4, "abc"), "")
        self.assertEqual(LETTER(0, "abc"), "")
        lst = ["x", "Y", "z"]
        self.assertEqual(ITEM(lst, 1), "x")
        self.assertEqual(ITEM(lst, 1.9), "x")
        self.assertEqual(ITEM(lst, 0), "")
        self.assertEqual(ITEM(lst, 4), "")
        self.assertEqual(ITEM(lst, "last"), "z")
        self.assertEqual(INDEXOF("y", lst), 2)                 # case-insensitive
        self.assertEqual(INDEXOF("nope", lst), 0)
        SETITEM(lst, 2, "k")
        SETITEM(lst, 9, "ignored")
        self.assertEqual(lst, ["x", "k", "z"])


class Machine(unittest.TestCase):
    def test_unknown_opcode_is_refused_not_ignored(self):
        project = {"targets": [
            {"isStage": True, "name": "Stage", "variables": {}, "lists": {}, "blocks": {}},
            {"isStage": False, "name": "S", "variables": {}, "lists": {}, "blocks": {
                "a": {"opcode": "motion_movesteps", "next": None, "parent": None, "inputs": {}, "fields": {}, "topLevel": True},
                "d": {"opcode": "procedures_definition", "next": "a", "parent": None, "inputs": {"custom_block": [2, "p"]}, "fields": {}, "topLevel": True},
                "p": {"opcode": "procedures_prototype", "next": None, "parent": "d", "inputs": {}, "fields": {},
                      "mutation": {"proccode": "f", "argumentnames": "[]", "argumentids": "[]"}}}}]}
        with self.assertRaises(UnsupportedBlock):
            VM(project)

    def test_virtual_time_and_wait(self):
        from harness import load_template
        from cloudiamond_scratch import sb3
        vm = VM(sb3.build_project(bytes(32)))
        waited = []
        vm.on_wait = waited.append
        vm.call("ss_ss mix sample")
        self.assertEqual(vm.now, 0)
        vm.call("ss_ss gather")
        self.assertAlmostEqual(vm.now, 90 * 0.03, delta=3.0)
        self.assertEqual(len(waited), 90)


if __name__ == "__main__":
    unittest.main()
