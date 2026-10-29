"""Checks that the files that ship together agree with each other."""
import _setup  # noqa: F401
import json
import re
import unittest
from pathlib import Path

from cloudiamond_scratch import __version__, keys, sb3
from cloudiamond_scratch import text as scratch_text

ROOT = Path(__file__).resolve().parent.parent


class Consistency(unittest.TestCase):
    def test_version_matches_pyproject(self):
        py = ROOT / "pyproject.toml"
        if not py.exists():
            self.skipTest("not running from the source tree")
        m = re.search(r'^version\s*=\s*"([^"]+)"', py.read_text(), re.M)
        self.assertEqual(m.group(1), __version__)

    def test_changelog_mentions_the_version(self):
        ch = ROOT / "CHANGELOG.md"
        if not ch.exists():
            self.skipTest("not running from the source tree")
        self.assertIn(f"## [{__version__}]", ch.read_text(encoding="utf-8"))

    def test_demo_key_file_matches_the_published_constant(self):
        f = ROOT / "examples" / "demo_server.key"
        if not f.exists():
            self.skipTest("examples/ not available")
        secret = keys.parse_secret(f.read_text())
        self.assertEqual(keys.public_key(secret).hex(), keys.DEMO_PUBLIC_KEY_HEX)
        self.assertTrue(keys.is_demo_key(keys.public_key(secret)))

    def test_shipped_template_is_reproducible_from_the_v0_1_client(self):
        """data/client_template.json must be exactly what tools/make_template.py derives from the v0.1 file."""
        up = ROOT / "tools" / "upstream" / "v0.1_DEMO.sb3"
        if not up.exists():
            self.skipTest("tools/ not available")
        import importlib.util
        spec = importlib.util.spec_from_file_location("make_template", ROOT / "tools" / "make_template.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        derived = mod.build_template(up)
        shipped = json.loads((ROOT / "src" / "cloudiamond_scratch" / "data" / "client_template.json").read_text(encoding="utf-8"))
        self.assertEqual(derived, shipped)

    def test_text_table_in_the_template_is_the_python_table(self):
        sp = sb3._sprite(sb3.build_project(bytes(32)))
        chars = next(v for v in sp["lists"].values() if v[0] == "TXT_CHARS")[1]
        codes = next(v for v in sp["lists"].values() if v[0] == "TXT_CODES")[1]
        self.assertEqual(chars, scratch_text.CHARS)
        self.assertEqual([int(c) for c in codes], scratch_text.CODES)

    def test_the_v0_1_crypto_blocks_are_untouched(self):
        """Everything that is not connection logic must still be the compiled v0.1 code."""
        up = ROOT / "tools" / "upstream" / "v0.1_DEMO.sb3"
        if not up.exists():
            self.skipTest("tools/ not available")
        old, _ = sb3.read_sb3(up.read_bytes())
        old_blocks = sb3._sprite(old)["blocks"]
        new_blocks = sb3._sprite(sb3.build_project(bytes(32), demo=False))["blocks"]
        changed = {k for k in old_blocks if k in new_blocks and old_blocks[k] != new_blocks[k]}
        removed = set(old_blocks) - set(new_blocks)
        # the v0.1 demo script was removed in library mode; every other changed block must be in the connect procedure
        import json as _j
        def proc_of(bid, blocks):
            while blocks[bid]["parent"] is not None:
                bid = blocks[bid]["parent"]
            top = blocks[bid]
            if top["opcode"] == "procedures_definition":
                return blocks[top["inputs"]["custom_block"][1]]["mutation"]["proccode"]
            return top["opcode"]
        owners = {proc_of(k, new_blocks) for k in changed}
        self.assertLessEqual(owners, {"\U0001F512 connect"}, owners)
        flag_blocks = {k for k in removed if proc_of(k, old_blocks) == "event_whenflagclicked"}
        self.assertEqual(removed, flag_blocks)


if __name__ == "__main__":
    unittest.main()
