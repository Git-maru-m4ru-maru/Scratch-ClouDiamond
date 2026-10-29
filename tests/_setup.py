"""Import this first in every test module: makes ``src/`` importable without installing the package."""
import pathlib
import sys

SRC = str(pathlib.Path(__file__).resolve().parent.parent / "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)
