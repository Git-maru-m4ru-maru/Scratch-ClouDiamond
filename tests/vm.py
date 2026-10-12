"""vm.py -- テストから本物の Scratch VM(Node の scratch-vm)を呼ぶための小さなヘルパー。

scratch-vm の場所: 環境変数 CLOUDIAMOND_SCRATCH_VM(node_modules ディレクトリ)。
Node や scratch-vm が無い環境(PyPI から入れた利用者など)では VM テストは自動で skip される。
"""
import json
import os
import shutil
import subprocess
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
HARNESS = os.path.join(HERE, "vmharness.js")


def _modules_dir():
    return os.environ.get("CLOUDIAMOND_SCRATCH_VM") or os.path.join(HERE, "node_modules")


def vm_available() -> bool:
    return bool(shutil.which("node")) and os.path.isdir(os.path.join(_modules_dir(), "scratch-vm"))


def env():
    e = dict(os.environ)
    e["CLOUDIAMOND_SCRATCH_VM"] = _modules_dir()
    return e


def run_project(sb3_bytes: bytes, timeout: float = 120.0) -> dict:
    """緑の旗を押し、変数 done が 1 になるまで実行して、全変数とリストを返す。"""
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "p.sb3")
        with open(path, "wb") as f:
            f.write(sb3_bytes)
        r = subprocess.run(["node", HARNESS, "run", path, str(timeout)], capture_output=True, text=True,
                           timeout=timeout + 60, env=env())
    if r.returncode != 0:
        raise RuntimeError("scratch-vm harness failed:\n" + r.stderr[-2000:])
    return json.loads(r.stdout.strip().splitlines()[-1])
