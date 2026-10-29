import _setup  # noqa: F401
import copy
import io
import json
import unittest
import zipfile

from cloudiamond_scratch import fingerprint, sb3
from cloudiamond_scratch import protocol as P

PUB = bytes(range(10, 42))


def fresh():
    return sb3.build_project(PUB)


class Build(unittest.TestCase):
    def test_content_is_deterministic(self):
        self.assertEqual(sb3.build_sb3(PUB), sb3.build_sb3(PUB))
        self.assertNotEqual(sb3.build_sb3(PUB), sb3.build_sb3(bytes(range(11, 43))))

    def test_embedded_key_name_and_monitors(self):
        data = sb3.build_sb3(PUB, name="Quiz")
        project, assets = sb3.read_sb3(data)
        self.assertEqual(sb3.embedded_public_key(project), PUB)
        sp = sb3._sprite(project)
        self.assertEqual(sp["name"], "\U0001F48EQuiz")
        self.assertTrue(all(m["spriteName"] == "\U0001F48EQuiz" for m in project["monitors"]))
        self.assertEqual(len(assets), 3)
        self.assertEqual(sb3.lint_project(project), [])

    def test_the_comment_documents_the_key(self):
        sp = sb3._sprite(fresh())
        text = next(iter(sp["comments"].values()))["text"]
        self.assertIn(PUB.hex(), text)
        self.assertIn(fingerprint(PUB), text)
        self.assertIn("wipe secrets", text)

    def test_zip_layout(self):
        z = zipfile.ZipFile(io.BytesIO(sb3.build_sb3(PUB)))
        names = z.namelist()
        self.assertEqual(names[0], "project.json")
        self.assertEqual(len(names), 4)
        self.assertIsNone(z.testzip())
        for i in z.infolist():
            self.assertEqual(i.date_time, (2020, 1, 1, 0, 0, 0))

    def test_library_mode_has_no_green_flag_script(self):
        demo, lib = fresh(), sb3.build_project(PUB, demo=False)
        has_flag = lambda p: any(isinstance(b, dict) and b["opcode"] == "event_whenflagclicked" for b in sb3._sprite(p)["blocks"].values())  # noqa: E731
        self.assertTrue(has_flag(demo))
        self.assertFalse(has_flag(lib))
        self.assertEqual(sb3.lint_project(lib), [])
        self.assertLess(len(sb3._sprite(lib)["blocks"]), len(sb3._sprite(demo)["blocks"]))
        # the library blocks are untouched
        self.assertEqual(sb3._blocks_without_demo(sb3._sprite(demo)), sb3._sprite(lib)["blocks"])

    def test_bad_arguments(self):
        for bad in (b"", bytes(31), bytes(33)):
            with self.assertRaises(ValueError):
                sb3.build_project(bad)
        for bad in ("", "   ", "x" * 41, "tab\there", "nl\nname"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                sb3.build_project(PUB, name=bad)

    def test_the_template_has_exactly_the_ten_cloud_variables(self):
        stage = next(t for t in fresh()["targets"] if t["isStage"])
        cloud = sorted(v[0] for v in stage["variables"].values() if len(v) > 2 and v[2])
        self.assertEqual(cloud, sorted(P.CLOUD_PREFIX + n for n in P.CLOUD_VARIABLES))
        self.assertEqual(len(cloud), 10, "Scratch allows at most 10 cloud variables")


class Lint(unittest.TestCase):
    """Each mutation breaks the project in a way that makes Scratch refuse (or misbehave); lint must notice."""

    def mutated(self, fn):
        p = copy.deepcopy(fresh())
        fn(sb3._sprite(p), p)
        return sb3.lint_project(p)

    def test_clean_project(self):
        self.assertEqual(sb3.lint_project(fresh()), [])

    def test_missing_next_block(self):
        def f(sp, p):
            bid = next(k for k, b in sp["blocks"].items() if isinstance(b, dict) and b["next"])
            sp["blocks"][bid]["next"] = "does-not-exist"
        self.assertTrue(any("missing next" in e for e in self.mutated(f)))

    def test_wrong_parent(self):
        def f(sp, p):
            bid = next(k for k, b in sp["blocks"].items() if isinstance(b, dict) and b["next"])
            sp["blocks"][sp["blocks"][bid]["next"]]["parent"] = "other"
        self.assertTrue(self.mutated(f))

    def test_deleted_input_block(self):
        def f(sp, p):
            bid = next(k for k, b in sp["blocks"].items() if isinstance(b, dict) and b["opcode"] == "operator_add")
            del sp["blocks"][bid]
        self.assertTrue(any("missing" in e for e in self.mutated(f)))

    def test_variable_id_mismatch(self):
        def f(sp, p):
            vid = next(k for k, v in sp["variables"].items() if v[0] == "SS_TRIES")
            sp["variables"][vid][0] = "renamed"
        self.assertTrue(any("mismatch" in e for e in self.mutated(f)))

    def test_call_to_unknown_procedure(self):
        def f(sp, p):
            c = next(b for b in sp["blocks"].values() if isinstance(b, dict) and b["opcode"] == "procedures_call")
            c["mutation"]["proccode"] = "nope %s"
        self.assertTrue(any("unknown procedure" in e for e in self.mutated(f)))

    def test_argument_ids_differ(self):
        def f(sp, p):
            c = next(b for b in sp["blocks"].values() if isinstance(b, dict) and b["opcode"] == "procedures_call"
                     and json.loads(b["mutation"]["argumentids"]))
            c["mutation"]["argumentids"] = '["x"]'
        self.assertTrue(any("argument ids" in e for e in self.mutated(f)))

    def test_toplevel_without_position(self):
        def f(sp, p):
            b = next(b for b in sp["blocks"].values() if isinstance(b, dict) and b.get("topLevel"))
            del b["x"]
        self.assertTrue(any("without x/y" in e for e in self.mutated(f)))

    def test_missing_cloud_variable(self):
        def f(sp, p):
            stage = next(t for t in p["targets"] if t["isStage"])
            vid = next(k for k, v in stage["variables"].items() if v[0].endswith("C2S_2"))
            del stage["variables"][vid]
        self.assertTrue(any("cloud variables differ" in e for e in self.mutated(f)))

    def test_a_cloud_variable_that_is_not_cloud(self):
        def f(sp, p):
            stage = next(t for t in p["targets"] if t["isStage"])
            for v in stage["variables"].values():
                if v[0].endswith("S2C_HDR"):
                    del v[2:]
        self.assertTrue(any("cloud variables differ" in e for e in self.mutated(f)))

    def test_definition_without_prototype(self):
        def f(sp, p):
            d = next(b for b in sp["blocks"].values() if isinstance(b, dict) and b["opcode"] == "procedures_definition")
            d["inputs"]["custom_block"] = [2, "gone"]
        self.assertTrue(self.mutated(f))


class Verify(unittest.TestCase):
    def verify(self, project, assets=None, **kw):
        return sb3.verify_project(project, assets, **kw)

    def test_fresh_build_is_identical(self):
        project, assets = sb3.read_sb3(sb3.build_sb3(PUB, name="X"))
        r = self.verify(project, assets, expected_pub=PUB)
        self.assertTrue(r.ok and r.identical and r.client_unmodified)
        self.assertEqual((r.name, r.demo, r.public_key), ("X", True, PUB))

    def test_library_mode_is_recognised(self):
        project, assets = sb3.read_sb3(sb3.build_sb3(PUB, demo=False))
        r = self.verify(project, assets)
        self.assertTrue(r.ok and r.identical)
        self.assertFalse(r.demo)

    def test_a_changed_constant_in_the_client_is_detected(self):
        p = fresh()
        sp = sb3._sprite(p)
        b = next(b for b in sp["blocks"].values() if isinstance(b, dict) and b["opcode"] == "data_setvariableto"
                 and b["inputs"]["VALUE"][1] == [10, "1"])
        b["inputs"]["VALUE"] = [1, [10, "2"]]
        r = self.verify(p)
        self.assertFalse(r.client_unmodified)
        self.assertFalse(r.ok)
        self.assertTrue(any("changed" in n for n in r.notes))

    def test_an_added_block_is_detected(self):
        p = fresh()
        sp = sb3._sprite(p)
        sp["blocks"]["evil"] = {"opcode": "looks_say", "next": None, "parent": None, "inputs": {}, "fields": {},
                                "shadow": False, "topLevel": True, "x": 0, "y": 0}
        self.assertFalse(self.verify(p).client_unmodified)

    def test_a_changed_demo_script_is_not_a_client_modification_but_not_identical(self):
        p = fresh()
        sp = sb3._sprite(p)
        flag = next(b for b in sp["blocks"].values() if isinstance(b, dict) and b["opcode"] == "event_whenflagclicked")
        flag["x"] += 1
        r = self.verify(p)
        self.assertTrue(r.client_unmodified)
        self.assertFalse(r.identical)

    def test_swapped_public_key_is_reported(self):
        project, assets = sb3.read_sb3(sb3.build_sb3(PUB))
        r = self.verify(project, assets, expected_pub=bytes(32))
        self.assertTrue(any("differs from the expected" in n for n in r.notes))

    def test_tampered_asset(self):
        project, assets = sb3.read_sb3(sb3.build_sb3(PUB))
        k = next(iter(assets))
        assets[k] = assets[k] + b" "
        r = self.verify(project, assets)
        self.assertFalse(r.assets_ok)
        self.assertFalse(r.ok)

    def test_not_a_client(self):
        r = self.verify({"targets": [{"isStage": True, "name": "Stage", "variables": {}, "lists": {}, "blocks": {}}]})
        self.assertFalse(r.ok)
        self.assertTrue(r.notes)

    def test_extra_sprite_with_blocks_is_noted(self):
        p = fresh()
        p["targets"].append({"isStage": False, "name": "Cat", "variables": {}, "lists": {}, "blocks": {
            "a": {"opcode": "looks_say", "next": None, "parent": None, "inputs": {}, "fields": {}, "topLevel": True}}})
        r = sb3.verify_project(copy.deepcopy(p))
        self.assertFalse(r.ok)      # two sprites with blocks: cannot even identify the client


class Audit(unittest.TestCase):
    def audit(self, project):
        return sb3.audit_project(project)

    def test_fresh_build_is_clean(self):
        r = self.audit(fresh())
        self.assertTrue(r.ok)
        self.assertEqual(r.public_key, PUB)

    def set_list(self, p, name, values):
        sp = sb3._sprite(p)
        next(v for v in sp["lists"].values() if v[0] == name)[1] = values

    def test_session_key_left_behind_is_critical(self):
        for lst in ("KC2S", "KS2C", "AK", "EK", "MASTER"):
            p = fresh()
            self.set_list(p, lst, [7] * 32)
            r = self.audit(p)
            self.assertTrue(r.critical, lst)
            self.assertFalse(r.ok)

    def test_message_residue_is_a_warning(self):
        p = fresh()
        self.set_list(p, "🔒 RX bytes", [104, 105])
        r = self.audit(p)
        self.assertFalse(r.critical)
        self.assertFalse(r.ok)
        sp = sb3._sprite(p)
        next(v for v in sp["variables"].values() if v[0] == "🔒 received text")[1] = "secret words"
        self.assertTrue(any("received message" in f.what for f in self.audit(p).findings))

    def test_modified_constant_table_is_flagged(self):
        p = fresh()
        sp = sb3._sprite(p)
        lst = next(v for v in sp["lists"].values() if v[0] == "LBL_C2S")
        lst[1][0] = 99
        self.assertFalse(self.audit(p).ok)

    def test_pasted_secret_key_is_critical_even_in_a_variable_or_block_text(self):
        secret_hex = "ab" * 32
        p = fresh()
        sp = sb3._sprite(p)
        sp["variables"]["vx"] = ["my key", secret_hex]
        r = self.audit(p)
        self.assertTrue(r.critical)
        self.assertTrue(any("64-hex" in f.what for f in r.findings))

    def test_the_embedded_public_key_is_not_a_false_positive(self):
        self.assertTrue(self.audit(fresh()).ok)       # the comment and SRV hold the public key in hex

    def test_state_that_is_harmless_is_only_info(self):
        p = fresh()
        sp = sb3._sprite(p)
        next(v for v in sp["variables"].values() if v[0] == "SS_SENDCTR")[1] = 5
        stage = next(t for t in p["targets"] if t["isStage"])
        next(v for v in stage["variables"].values() if v[0].endswith("C2S_0"))[1] = "1234"
        r = self.audit(p)
        self.assertTrue(r.ok)
        self.assertTrue(any(f.severity == "info" for f in r.findings))

    def test_invalid_embedded_key(self):
        p = fresh()
        self.set_list(p, "SRV", [1, 2, 3])
        r = self.audit(p)
        self.assertFalse(r.ok)
        self.assertIsNone(r.public_key)

    def test_not_a_client(self):
        r = self.audit({"targets": [{"isStage": True, "name": "Stage", "variables": {}, "lists": {}, "blocks": {}}]})
        self.assertTrue(r.critical)


class ReadSb3(unittest.TestCase):
    def test_rejects_bad_input(self):
        with self.assertRaises(ValueError):
            sb3.read_sb3(b"not a zip")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("other.txt", "x")
        with self.assertRaises(ValueError):
            sb3.read_sb3(buf.getvalue())
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("project.json", "[1,2]")
        with self.assertRaises(ValueError):
            sb3.read_sb3(buf.getvalue())

    def test_zip_bomb_guard(self):
        old = sb3.MAX_PROJECT_BYTES
        sb3.MAX_PROJECT_BYTES = 1000
        try:
            with self.assertRaises(ValueError):
                sb3.read_sb3(sb3.build_sb3(PUB))
        finally:
            sb3.MAX_PROJECT_BYTES = old


if __name__ == "__main__":
    unittest.main()
