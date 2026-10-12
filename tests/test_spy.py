"""test_spy.py -- SPy コンパイラ(Python -> Scratch ブロック)の検証。

  ・同じソースを Python で実行した結果と、本物の Scratch VM で実行した結果が一致すること
  ・生成した project.json の構造が正しいこと(孤立ブロックや存在しない参照が無い)
  ・使えない構文は黙って誤変換せず、必ずエラーにすること
"""
import importlib.util
import io
import json
import os
import zipfile

import pytest

import vm
from cloudiamond_scratch.scratch.build import build_sb3
from cloudiamond_scratch.scratch.spy import Compiler, SpyError

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE = os.path.join(HERE, "spy_sample.py")


def load_sample():
    spec = importlib.util.spec_from_file_location("spy_sample_mod", SAMPLE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def norm(x):
    """VM のリスト要素は文字列の数字のことがある。数として読めるなら数に揃える。"""
    if isinstance(x, str):
        try:
            return float(x)
        except ValueError:
            return x
    return float(x)


def test_sample_runs_as_plain_python():
    m = load_sample()
    m.main()
    assert m.done == 1 and m.OUT[2] == 720 and m.OUT[12] == 302 and m.OUT[14] == 4004


@pytest.mark.skipif(not vm.vm_available(), reason="Node.js と scratch-vm が必要(CLOUDIAMOND_SCRATCH_VM)")
def test_sample_in_real_scratch_vm_matches_python():
    m = load_sample()
    m.main()
    data, _ = build_sb3(open(SAMPLE, encoding="utf-8").read())
    r = vm.run_project(data, timeout=30)
    assert not r["timedOut"], r
    assert [norm(x) for x in r["lists"]["OUT"]] == [norm(x) for x in m.OUT]
    assert norm(r["vars"]["total"]) == m.total
    assert [norm(x) for x in r["lists"]["CNT"]] == [norm(x) for x in m.CNT]


def _project(source, **kw):
    data, comp = build_sb3(source, **kw)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        return json.loads(z.read("project.json")), z.namelist()


def test_project_json_is_structurally_sound():
    proj, names = _project(open(SAMPLE, encoding="utf-8").read())
    sprite = proj["targets"][1]
    blocks = sprite["blocks"]
    assert any(n.endswith(".svg") for n in names) and "project.json" in names
    for bid, b in blocks.items():
        assert b["topLevel"] or b["parent"] in blocks, "孤立ブロック: %s %s" % (bid, b["opcode"])
        if b["next"] is not None:
            assert b["next"] in blocks and blocks[b["next"]]["parent"] == bid
        for name, inp in b["inputs"].items():
            for ref in inp[1:]:
                if isinstance(ref, str):
                    assert ref in blocks, "存在しない参照: %s.%s -> %s" % (bid, name, ref)
                    assert blocks[ref]["parent"] == bid
    top = [b for b in blocks.values() if b["topLevel"]]
    assert {b["opcode"] for b in top} == {"event_whenflagclicked", "procedures_definition"}


def test_floor_division_by_one_is_not_optimised_away():
    # 小数の値(timer など)に対する `x // 1` は床関数。消すと壊れる
    proj, _ = _project("def f(x):\n    y = x // 1\n    return y\n")
    ops = [b["opcode"] for b in proj["targets"][1]["blocks"].values()]
    assert "operator_mathop" in ops and "operator_divide" in ops


def test_list_and_display_names_and_overrides():
    src = 'L = Lst(3, "my list")\nV = Var(5, "my var")\nCL = Cloud("☁ x")\n'
    proj, _ = _project(src, list_overrides={"L": [7, 8]})
    sprite, stage = proj["targets"][1], proj["targets"][0]
    assert list(sprite["lists"].values()) == [["my list", [7, 8]]]
    assert ["my var", 5] in sprite["variables"].values()
    assert list(stage["variables"].values()) == [["☁ x", 0, True]]


@pytest.mark.parametrize("src", [
    "def f():\n    return 1\n    x = 2\n",                       # return が末尾でない
    "def f(a):\n    a = 1\n",                                      # 引数への代入
    "def f():\n    x = 1 if 2 else 3\n",                           # 三項演算子
    "def f():\n    x = 1 << 2\n",                                  # ビット演算
    "def f():\n    x = 1 & 2\n",
    "def f(y):\n    x = y ** 2\n",                                 # 変数のべき乗
    "def f():\n    x = y + 1\n",                                   # 一度も代入されない名前(タイプミス)
    "L = Lst(3)\ndef f(i):\n    for k in range(1, 5, i):\n        pass\n",   # step が定数でない
    "def f():\n    if 1 < x < 3:\n        pass\n",                 # 連鎖比較
    "T = Vars(3)\ndef f(i):\n    T[i] = 1\n",                      # Vars の添字は定数のみ
    "def f():\n    while g() < 3:\n        pass\ndef g():\n    return 1\n",   # while 条件に関数呼び出し
    "def f():\n    import os\n",
    "def f():\n    x = [1, 2]\n",
    "def f():\n    x = unknown(1)\n",
])
def test_unsupported_constructs_raise(src):
    with pytest.raises(SpyError):
        Compiler(src).compile_all()
