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
        m = re.search(r'^version\s*=\s*"([^"]+)"', py.read_text(encoding="utf-8"), re.M)
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
        secret = keys.parse_secret(f.read_text(encoding="utf-8"))
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


    def test_readme_links_are_absolute_so_they_work_on_the_pypi_page(self):
        readme = ROOT / "README.md"
        if not readme.exists():
            self.skipTest("not running from the source tree")
        relative = re.findall(r"\]\((?!https?://|#|mailto:)([^)]*)\)", readme.read_text(encoding="utf-8"))
        self.assertEqual(relative, [], "relative links are broken on the PyPI project page")

    def test_the_shipped_release_file_is_current_and_matches_its_checksum(self):
        rel = ROOT / "releases"
        if not rel.exists():
            self.skipTest("releases/ not available")
        import hashlib
        name = f"ClouDiamond_v{__version__}_DEMO.sb3"
        files = sorted(x.name for x in rel.glob("*.sb3"))
        self.assertEqual(files, [name], "releases/ must hold exactly this version's demo file (no stale files)")
        data = (rel / name).read_bytes()
        project, assets = sb3.read_sb3(data)
        demo_pub = bytes.fromhex(keys.DEMO_PUBLIC_KEY_HEX)
        self.assertEqual(sb3._dump(project), sb3._dump(sb3.build_project(demo_pub)), "the release file is not a fresh build")
        self.assertTrue(sb3.verify_project(project, assets, expected_pub=demo_pub).ok)
        self.assertTrue(sb3.audit_project(project).ok)
        sums = (rel / "SHA256SUMS").read_text(encoding="utf-8").split()
        self.assertEqual(sums, [hashlib.sha256(data).hexdigest(), name])
        self.assertIn(__version__, next(iter(sb3._sprite(project)["comments"].values()))["text"])


    def test_manifest_includes_every_file_of_tests_docs_examples_and_tools(self):
        """A test helper that is not listed in MANIFEST.in (say a .js harness) is silently missing from the sdist."""
        manifest = ROOT / "MANIFEST.in"
        if not manifest.exists():
            self.skipTest("not running from the source tree")
        try:
            from setuptools._distutils.filelist import FileList
        except ImportError:                       # pragma: no cover
            self.skipTest("setuptools is not available")
        import os
        old = os.getcwd()
        os.chdir(ROOT)
        try:
            fl = FileList()
            fl.findall()
            for line in manifest.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    fl.process_template_line(line)
            included = {p.replace("\\", "/") for p in fl.files}
            skip = {"__pycache__", "node_modules", ".git", ".pytest_cache"}
            missing = []
            for sub in ("tests", "docs", "examples", "tools"):
                for p in (ROOT / sub).rglob("*"):
                    if p.is_file() and not skip & set(p.parts) and p.suffix not in (".pyc", ".pyo"):
                        rel = p.relative_to(ROOT).as_posix()
                        if rel not in included:
                            missing.append(rel)
        finally:
            os.chdir(old)
        self.assertEqual(missing, [], "files that would be missing from the sdist")

    def test_manifest_would_include_a_js_harness_and_json_fixtures(self):
        """The exact failure seen on PyPI: tests/vmharness.js was not packaged."""
        manifest = ROOT / "MANIFEST.in"
        if not manifest.exists():
            self.skipTest("not running from the source tree")
        try:
            from setuptools._distutils.filelist import FileList
        except ImportError:                       # pragma: no cover
            self.skipTest("setuptools is not available")
        fl = FileList()
        fl.allfiles = ["tests/vmharness.js", "tests/vm.py", "tests/fixtures/data.json", "tests/package.json",
                       "tests/node_modules/x/index.js", "tests/__pycache__/vm.cpython-312.pyc"]
        for line in manifest.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                fl.process_template_line(line)
        self.assertEqual(sorted(fl.files), ["tests/fixtures/data.json", "tests/package.json", "tests/vm.py", "tests/vmharness.js"])


if __name__ == "__main__":
    unittest.main()
