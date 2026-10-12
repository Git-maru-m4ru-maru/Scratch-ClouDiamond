"""
spyrt.py -- SPy ソースを「普通の Python」として実行するための部品。

SPy のソースは `from cloudiamond_scratch.scratch.spyrt import *` で読み込めば、そのまま Python として動く。
これにより (1) 暗号ロジックを速い Python で検証でき、(2) 同じソースをコンパイルした Scratch ブロックを
VM で動かした結果と突き合わせられる。Scratch の挙動(大文字小文字を区別しない比較など)は忠実に真似る。
"""
import random as _random
import time as _time

unroll = range


class Lst(list):
    """Scratch のリスト。Lst(n) は n 個の 0、Lst([...]) は初期値つき。第 2 引数は表示名(Python では無視)。"""

    def __init__(self, arg=0, display=None):
        super().__init__([0] * arg if isinstance(arg, int) else list(arg))


def Var(v=0, display=None):
    return v


def Vars(n):
    return [0] * n


def Cloud(name):
    return 0


def api(code):
    return lambda f: f


def nowarp(f):
    return f


def when_flag(f):
    return f


# ---- 「調べる」「見た目」ブロック相当(テスト用の簡易版)
_t0 = _time.time()
_answers = []
_said = []


def rand_int(a, b):
    return _random.randint(a, b)


def mouse_x():
    return 0


def mouse_y():
    return 0


def timer():
    return _time.time() - _t0


def reset_timer():
    global _t0
    _t0 = _time.time()


def days_since_2000():
    return (_time.time() - 946684800) / 86400.0


def ask(prompt):
    _said.append(("ask", prompt))


def answer():
    return _answers.pop(0) if _answers else ""


def say(msg):
    _said.append(("say", msg))


def wait(sec):
    pass


def _s(x):
    if isinstance(x, float) and x == int(x) and abs(x) < 1e21:
        x = int(x)
    return str(x)


def join(a, b):
    return _s(a) + _s(b)


def letter_of(i, s):
    """Scratch の「(i) 番目の文字」。Scratch は "1" = 1 を数として比べ、"7" * 100 も 700 になる。
    Python でそれを再現するため、1 文字が数字ならそのまま int で返す(数字以外は str)。"""
    s = _s(s)
    c = s[int(i) - 1] if 1 <= i <= len(s) else ""
    return int(c) if c.isdigit() and c.isascii() else c


def length_of(s):
    return len(_s(s))


def _num(v):
    """JavaScript の Number(v) 相当。空白だけの文字列は Scratch の特例で NaN 扱い。"""
    if isinstance(v, (int, float)):
        return float(v)
    t = str(v)
    if t.strip() == "":
        return float("nan")
    try:
        return float(t)
    except ValueError:
        return float("nan")


def scratch_equal(a, b):
    """Scratch の Cast.compare(a, b) == 0 と同じ。数として読めるなら数で、そうでなければ小文字化した文字列で比べる。"""
    x, y = _num(a), _num(b)
    if x != x or y != y:
        return _s(a).lower() == _s(b).lower()
    return x == y


def list_index_of(lst, v):
    """1 始まり。無ければ 0。比較は Scratch 流。"""
    for k, x in enumerate(lst):
        if scratch_equal(x, v):
            return k + 1
    return 0
