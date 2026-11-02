"""Text files must be read and written with an explicit encoding.

Without it Python uses the locale's code page: UTF-8 on most Linux/macOS systems but cp1252 / cp932 on Windows, where
reading a UTF-8 file that contains Japanese text fails. (``pyproject.toml`` has Japanese comments.)
"""
import _setup  # noqa: F401
import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP_PARTS = {"__pycache__", "node_modules", "upstream", ".git"}


def python_files():
    for sub in ("src", "tests", "tools", "examples"):
        d = ROOT / sub
        if d.exists():
            for p in sorted(d.rglob("*.py")):
                if not SKIP_PARTS & set(p.parts):
                    yield p


def findings(tree):
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f, kws = node.func, {k.arg for k in node.keywords}
        if isinstance(f, ast.Attribute) and f.attr in ("read_text", "write_text") and "encoding" not in kws:
            yield node.lineno, f"{f.attr}() without encoding="
        is_builtin_open = isinstance(f, ast.Name) and f.id == "open"
        is_io_open = isinstance(f, ast.Attribute) and f.attr == "open" and isinstance(f.value, ast.Name) and f.value.id == "io"
        if is_builtin_open or is_io_open:
            mode = None
            if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                mode = node.args[1].value
            for k in node.keywords:
                if k.arg == "mode" and isinstance(k.value, ast.Constant):
                    mode = k.value.value
            if "b" not in (mode or "") and "encoding" not in kws:
                yield node.lineno, f"open(mode={mode!r}) without encoding="


class ExplicitEncodings(unittest.TestCase):
    def test_no_locale_dependent_text_io(self):
        problems = []
        for p in python_files():
            tree = ast.parse(p.read_text(encoding="utf-8"), str(p))
            problems += [f"{p.relative_to(ROOT)}:{line}: {what}" for line, what in findings(tree)]
        self.assertEqual(problems, [], "\n".join(problems))

    def test_the_scanner_itself_catches_the_bad_patterns(self):
        bad = ast.parse("a.read_text()\nb.write_text('x')\nopen('f')\nopen('f', 'w')\nio.open('f')\nopen(p, mode='r')")
        self.assertEqual(len(list(findings(bad))), 6)
        good = ast.parse("a.read_text(encoding='utf-8')\nopen('f','rb')\nopen('f', 'w', encoding='utf-8')\nos.open(p, 1)\nx.open(frame)")
        self.assertEqual(list(findings(good)), [])

    def test_no_machine_specific_paths_are_shipped(self):
        import re
        bad = []
        for sub in ("src", "tests", "tools", "examples", "docs", ".github"):
            d = ROOT / sub
            for p in sorted(d.rglob("*")) if d.exists() else []:
                if p.is_file() and p.suffix in (".py", ".md", ".yml", ".toml") and not SKIP_PARTS & set(p.parts) \
                        and p.name != "test_text_io.py":
                    for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
                        if re.search(r"/home/claude|/mnt/user-data|/tmp/(work|stage|buildcopy)", line):
                            bad.append(f"{p.relative_to(ROOT)}:{i}")
        self.assertEqual(bad, [])

    def test_the_japanese_project_files_are_readable_as_utf8(self):
        for name in ("pyproject.toml", "README.md", "CHANGELOG.md"):
            f = ROOT / name
            if f.exists():
                f.read_text(encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
