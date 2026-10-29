"""A small Scratch 3 block interpreter used to test the generated client.

It transpiles the blocks of the Scratch sprite into Python functions and runs them with
Scratch-compatible semantics (IEEE doubles, case-insensitive string comparison, 1-based
list indexing, floor-mod, ...). It supports exactly the block set the ClouDiamond client
uses; an unknown opcode raises ``UnsupportedBlock`` instead of being ignored.

This is NOT the real ``scratch-vm``. It is a second, independent implementation of the
documented block semantics, which lets the test-suite run the *actual compiled client
blocks* against the Python server without Node.js.
"""
from __future__ import annotations

import json
import math
import random
import re
from typing import Any, Callable

INF = float("inf")
NAN = float("nan")


class UnsupportedBlock(Exception):
    pass


class StopScript(Exception):
    """Raised by the harness to end a ``forever`` loop."""


# --------------------------------------------------------------------------- Cast
_DEC = re.compile(r"^[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?$")
_HEX = re.compile(r"^0[xX][0-9a-fA-F]+$")
_BIN = re.compile(r"^0[bB][01]+$")
_OCT = re.compile(r"^0[oO][0-7]+$")


def js_number(x: Any) -> float:
    """JavaScript ``Number(x)`` (NaN when not convertible)."""
    if isinstance(x, bool):
        return 1.0 if x else 0.0
    if isinstance(x, (int, float)):
        return float(x)
    if isinstance(x, str):
        s = x.strip()
        if s == "":
            return 0.0
        if _DEC.match(s):
            return float(s)
        if s in ("Infinity", "+Infinity"):
            return INF
        if s == "-Infinity":
            return -INF
        if _HEX.match(s):
            return float(int(s, 16))
        if _BIN.match(s):
            return float(int(s[2:], 2))
        if _OCT.match(s):
            return float(int(s[2:], 8))
    return NAN


def N(x: Any) -> float:
    """Scratch ``Cast.toNumber``."""
    if isinstance(x, float):
        return 0.0 if x != x else x
    n = js_number(x)
    return 0.0 if n != n else n


def fmt_num(x: float) -> str:
    if x != x:
        return "NaN"
    if x == INF:
        return "Infinity"
    if x == -INF:
        return "-Infinity"
    if x == int(x) and abs(x) < 1e21:
        return str(int(x))
    r = repr(x)
    return r.replace("e-0", "e-").replace("e+0", "e+")


def S(x: Any) -> str:
    """Scratch ``Cast.toString``."""
    if isinstance(x, str):
        return x
    if isinstance(x, bool):
        return "true" if x else "false"
    if isinstance(x, (int, float)):
        return fmt_num(float(x))
    return str(x)


def _is_ws(v: Any) -> bool:
    return isinstance(v, str) and v.strip() == ""


def compare(a: Any, b: Any) -> float:
    n1, n2 = js_number(a), js_number(b)
    if n1 == 0 and _is_ws(a):
        n1 = NAN
    elif n2 == 0 and _is_ws(b):
        n2 = NAN
    if n1 != n1 or n2 != n2:
        s1, s2 = S(a).lower(), S(b).lower()
        return -1 if s1 < s2 else (1 if s1 > s2 else 0)
    if (n1 == INF and n2 == INF) or (n1 == -INF and n2 == -INF):
        return 0
    return n1 - n2


def EQ(a, b): return compare(a, b) == 0
def LT(a, b): return compare(a, b) < 0
def GT(a, b): return compare(a, b) > 0


def DIV(a: float, b: float) -> float:
    if b == 0:
        if a == 0 or a != a:
            return NAN
        return INF if (a > 0) == (math.copysign(1.0, b) > 0) else -INF
    return a / b


def MOD(n: float, m: float) -> float:
    try:
        r = math.fmod(n, m)
    except ValueError:
        return NAN
    if m != 0 and r / m < 0:
        r += m
    return r


def FLOOR(x: float) -> float:
    if x != x or x in (INF, -INF):
        return x
    return float(math.floor(x))


def LETTER(i: Any, s: Any) -> str:
    idx = N(i) - 1
    st = S(s)
    if idx < 0 or idx >= len(st):
        return ""
    return st[int(idx)]


def _list_index(index: Any, length: int) -> int:
    """Cast.toListIndex (acceptAll=False); returns 0 for invalid."""
    if not isinstance(index, (int, float)):
        if index == "last":
            return length if length > 0 else 0
        if index in ("random", "any"):
            return 1 + int(random.random() * length) if length > 0 else 0
    i = math.floor(N(index))
    if i < 1 or i > length:
        return 0
    return int(i)


def ITEM(lst: list, index: Any):
    i = _list_index(index, len(lst))
    return "" if i == 0 else lst[i - 1]


def SETITEM(lst: list, index: Any, value: Any) -> None:
    i = _list_index(index, len(lst))
    if i:
        lst[i - 1] = value


def INDEXOF(item: Any, lst: list) -> float:
    for i, v in enumerate(lst):
        if compare(v, item) == 0:
            return float(i + 1)
    return 0.0


def _is_int(v: Any) -> bool:
    if isinstance(v, str):
        return "." not in v
    return float(v) % 1 == 0


# ----------------------------------------------------------------------- compiler
class Compiler:
    def __init__(self, project: dict):
        self.project = project
        stage = next(t for t in project["targets"] if t["isStage"])
        sprites = [t for t in project["targets"] if not t["isStage"] and t["blocks"]]
        if len(sprites) != 1:
            raise ValueError("expected exactly one sprite with blocks")
        self.stage, self.sprite = stage, sprites[0]
        self.B: dict[str, dict] = {k: v for k, v in self.sprite["blocks"].items() if isinstance(v, dict)}
        self.vars: dict[str, str] = {}        # id -> pyname
        self.var_names: dict[str, str] = {}   # scratch name -> pyname
        self.cloud: dict[str, str] = {}       # pyname -> scratch name
        self.lists: dict[str, str] = {}
        self.list_names: dict[str, str] = {}
        self.procs: dict[str, str] = {}       # proccode -> pyname
        self.proc_args: dict[str, list[str]] = {}
        self.lines: list[str] = []
        self._n = 0

    # -- naming
    def _decl(self):
        for t in (self.stage, self.sprite):
            for vid, v in t["variables"].items():
                py = f"V{len(self.vars)}"
                self.vars[vid] = py
                self.var_names[v[0]] = py
                if len(v) > 2 and v[2]:
                    self.cloud[py] = v[0]
            for lid, l in t["lists"].items():
                py = f"L{len(self.lists)}"
                self.lists[lid] = py
                self.list_names[l[0]] = py

    # -- expressions: return (code, tag) tag in n/s/b/a
    def num(self, inp) -> str:
        c, t = self.val(inp)
        return c if t == "n" else f"N({c})"

    def val(self, inp):
        if inp is None:
            return ("0.0", "n")
        x = inp[1]
        if x is None:
            return ('""', "s")
        if isinstance(x, str):
            return self.reporter(x)
        t = x[0]
        if t == 12:
            return (self.vars.get(x[2]) or self.var_names[x[1]], "a")
        if t in (4, 5, 6, 7, 8):
            n = js_number(x[1])
            if n == n and str(x[1]).strip() != "":
                return (repr(n), "n")
            return (repr(str(x[1])), "s")
        return (repr(str(x[1])), "s")

    def cond(self, inp) -> str:
        if inp is None or inp[1] is None:
            return "False"
        c, t = self.val(inp)
        return c if t == "b" else f"bool(N({c}))"

    def reporter(self, bid: str):
        b = self.B[bid]
        op, i, f = b["opcode"], b["inputs"], b["fields"]
        if op in ("operator_add", "operator_subtract", "operator_multiply"):
            sym = {"operator_add": "+", "operator_subtract": "-", "operator_multiply": "*"}[op]
            return (f"({self.num(i.get('NUM1'))} {sym} {self.num(i.get('NUM2'))})", "n")
        if op == "operator_divide":
            return (f"DIV({self.num(i.get('NUM1'))}, {self.num(i.get('NUM2'))})", "n")
        if op == "operator_mod":
            return (f"MOD({self.num(i.get('NUM1'))}, {self.num(i.get('NUM2'))})", "n")
        if op in ("operator_equals", "operator_lt", "operator_gt"):
            fn = {"operator_equals": "EQ", "operator_lt": "LT", "operator_gt": "GT"}[op]
            return (f"{fn}({self.val(i.get('OPERAND1'))[0]}, {self.val(i.get('OPERAND2'))[0]})", "b")
        if op in ("operator_and", "operator_or"):
            kw = "and" if op == "operator_and" else "or"
            return (f"({self.cond(i.get('OPERAND1'))} {kw} {self.cond(i.get('OPERAND2'))})", "b")
        if op == "operator_not":
            return (f"(not {self.cond(i.get('OPERAND'))})", "b")
        if op == "operator_mathop":
            if f["OPERATOR"][0] != "floor":
                raise UnsupportedBlock(f"mathop {f['OPERATOR'][0]}")
            return (f"FLOOR({self.num(i.get('NUM'))})", "n")
        if op == "operator_join":
            return (f"(S({self.val(i.get('STRING1'))[0]}) + S({self.val(i.get('STRING2'))[0]}))", "s")
        if op == "operator_letter_of":
            return (f"LETTER({self.val(i.get('LETTER'))[0]}, {self.val(i.get('STRING'))[0]})", "s")
        if op == "operator_length":
            return (f"float(len(S({self.val(i.get('STRING'))[0]})))", "n")
        if op == "operator_random":
            a, b2 = self.val(i.get("FROM"))[0], self.val(i.get("TO"))[0]
            return (f"RANDOM({a}, {b2})", "n")
        if op == "data_itemoflist":
            return (f"ITEM({self.lists[f['LIST'][1]]}, {self.val(i.get('INDEX'))[0]})", "a")
        if op == "data_lengthoflist":
            return (f"float(len({self.lists[f['LIST'][1]]}))", "n")
        if op == "data_itemnumoflist":
            return (f"INDEXOF({self.val(i.get('ITEM'))[0]}, {self.lists[f['LIST'][1]]})", "n")
        if op == "argument_reporter_string_number":
            return ("a_" + re.sub(r"\W", "_", f["VALUE"][0]), "a")
        if op == "sensing_timer":
            return ("TIMER()", "n")
        if op == "sensing_mousex":
            return ("MOUSE_X()", "n")
        if op == "sensing_mousey":
            return ("MOUSE_Y()", "n")
        if op == "sensing_dayssince2000":
            return ("DAYS()", "n")
        if op == "sensing_answer":
            return ("ANSWER()", "s")
        raise UnsupportedBlock(op)

    # -- statements
    def emit(self, ind: int, s: str):
        self.lines.append("    " * ind + s)

    def stack(self, bid, ind: int):
        start = len(self.lines)
        while bid:
            self.stmt(self.B[bid], ind)
            bid = self.B[bid]["next"]
        if len(self.lines) == start:
            self.emit(ind, "pass")

    def sub(self, b, key, ind):
        x = b["inputs"].get(key)
        if x and isinstance(x[1], str):
            self.stack(x[1], ind)
        else:
            self.emit(ind, "pass")

    def stmt(self, b, ind):
        op, i, f = b["opcode"], b["inputs"], b["fields"]
        if op == "data_setvariableto":
            py = self.vars[f["VARIABLE"][1]]
            self.emit(ind, f"{py} = {self.val(i.get('VALUE'))[0]}")
            if py in self.cloud:
                self.emit(ind, f"CLOUD_SET({self.cloud[py]!r}, {py})")
        elif op == "data_changevariableby":
            py = self.vars[f["VARIABLE"][1]]
            self.emit(ind, f"{py} = N({py}) + {self.num(i.get('VALUE'))}")
            if py in self.cloud:
                self.emit(ind, f"CLOUD_SET({self.cloud[py]!r}, {py})")
        elif op == "data_replaceitemoflist":
            self.emit(ind, f"SETITEM({self.lists[f['LIST'][1]]}, {self.val(i.get('INDEX'))[0]}, {self.val(i.get('ITEM'))[0]})")
        elif op == "data_addtolist":
            self.emit(ind, f"{self.lists[f['LIST'][1]]}.append({self.val(i.get('ITEM'))[0]})")
        elif op == "data_deletealloflist":
            self.emit(ind, f"{self.lists[f['LIST'][1]]}.clear()")
        elif op == "control_repeat":
            self.emit(ind, f"for _ in range(max(0, round(N({self.val(i.get('TIMES'))[0]})))):")
            self.sub(b, "SUBSTACK", ind + 1)
        elif op == "control_repeat_until":
            self.emit(ind, f"while not {self.cond(i.get('CONDITION'))}:")
            self.sub(b, "SUBSTACK", ind + 1)
        elif op == "control_forever":
            self.emit(ind, "while True:")
            self.sub(b, "SUBSTACK", ind + 1)
        elif op == "control_if":
            self.emit(ind, f"if {self.cond(i.get('CONDITION'))}:")
            self.sub(b, "SUBSTACK", ind + 1)
        elif op == "control_if_else":
            self.emit(ind, f"if {self.cond(i.get('CONDITION'))}:")
            self.sub(b, "SUBSTACK", ind + 1)
            self.emit(ind, "else:")
            self.sub(b, "SUBSTACK2", ind + 1)
        elif op == "control_wait":
            self.emit(ind, f"WAIT(N({self.val(i.get('DURATION'))[0]}))")
        elif op == "looks_say":
            self.emit(ind, f"SAY({self.val(i.get('MESSAGE'))[0]})")
        elif op == "sensing_resettimer":
            self.emit(ind, "RESET_TIMER()")
        elif op == "sensing_askandwait":
            self.emit(ind, f"ASK({self.val(i.get('QUESTION'))[0]})")
        elif op == "procedures_call":
            code = b["mutation"]["proccode"]
            ids = json.loads(b["mutation"]["argumentids"])
            args = ", ".join(self.val(i.get(a))[0] for a in ids)
            self.emit(ind, f"{self.procs[code]}({args})")
        else:
            raise UnsupportedBlock(op)

    def compile(self) -> str:
        self._decl()
        for b in self.B.values():
            if b["opcode"] == "procedures_prototype":
                code = b["mutation"]["proccode"]
                self.procs[code] = f"P{len(self.procs)}"
                self.proc_args[code] = [re.sub(r"\W", "_", n) for n in json.loads(b["mutation"]["argumentnames"])]
        globs = sorted(set(self.vars.values()))
        for b in self.B.values():
            if b["opcode"] == "procedures_definition":
                proto = self.B[b["inputs"]["custom_block"][1]]
                code = proto["mutation"]["proccode"]
                args = ", ".join("a_" + a for a in self.proc_args[code])
                self.emit(0, f"def {self.procs[code]}({args}):")
                self.emit(1, "global " + ", ".join(globs))
                self.stack(b["next"], 1)
                self.emit(0, "")
            elif b["opcode"] == "event_whenflagclicked":
                self.emit(0, "def FLAG():")
                self.emit(1, "global " + ", ".join(globs))
                self.stack(b["next"], 1)
                self.emit(0, "")
        return "\n".join(self.lines)


# ---------------------------------------------------------------------------- VM
class VM:
    """Runs the client sprite. All time is virtual: ``wait`` advances a clock."""

    def __init__(self, project: dict, *, seed: int | None = 1, mouse=(0.0, 0.0), days: float | None = None):
        self.project = json.loads(json.dumps(project))
        self.c = Compiler(self.project)
        self.source = self.c.compile()
        self.rng = random.Random(seed)
        self.now = 0.0
        self.timer0 = 0.0
        self.mouse = mouse
        self.days = days if days is not None else 9777.123456789
        self.said: list[str] = []
        self.answers: list[str] = []
        self.on_cloud_set: Callable[[str, Any], None] = lambda name, value: None
        self.on_wait: Callable[[float], None] = lambda dt: None   # called after the clock advanced
        self.ops = 0
        ns: dict[str, Any] = {
            "N": N, "S": S, "EQ": EQ, "LT": LT, "GT": GT, "DIV": DIV, "MOD": MOD, "FLOOR": FLOOR,
            "LETTER": LETTER, "ITEM": ITEM, "SETITEM": SETITEM, "INDEXOF": INDEXOF,
            "RANDOM": self._random, "TIMER": lambda: self.now - self.timer0,
            "MOUSE_X": lambda: float(self.mouse[0]), "MOUSE_Y": lambda: float(self.mouse[1]),
            "DAYS": lambda: self.days, "CLOUD_SET": self._cloud_set, "WAIT": self._wait,
            "SAY": lambda m: self.said.append(S(m)), "RESET_TIMER": self._reset_timer,
            "ASK": lambda q: None, "ANSWER": self._answer,
        }
        # initial values come from the project file
        for t in (self.c.stage, self.c.sprite):
            pass
        self.ns = ns
        self._load_initial_state()
        exec(compile(self.source, "<scratch>", "exec"), ns)

    # state ------------------------------------------------------------------
    def _load_initial_state(self):
        for t in (self.c.stage, self.c.sprite):
            for vid, v in t["variables"].items():
                self.ns[self.c.vars[vid]] = v[1]
            for lid, l in t["lists"].items():
                self.ns[self.c.lists[lid]] = list(l[1])

    def var(self, name: str):
        return self.ns[self.c.var_names[name]]

    def set_var(self, name: str, value) -> None:
        self.ns[self.c.var_names[name]] = value

    def list(self, name: str) -> list:
        return self.ns[self.c.list_names[name]]

    def set_cloud(self, name: str, value) -> None:
        """A cloud variable was changed by the outside world (the server)."""
        self.ns[self.c.var_names[name]] = value

    def export_project(self) -> dict:
        """The project as Scratch would save it right now (current values included)."""
        out = json.loads(json.dumps(self.project))
        for t in out["targets"]:
            if t["isStage"] or t["blocks"]:
                for vid, v in t["variables"].items():
                    cur = self.ns[self.c.vars[vid]]
                    v[1] = fmt_num(cur) if isinstance(cur, float) and cur == int(cur) else cur
                for lid, l in t["lists"].items():
                    l[1] = [fmt_num(x) if isinstance(x, float) and x == int(x) else x for x in self.ns[self.c.lists[lid]]]
        return out

    # io ---------------------------------------------------------------------
    def _random(self, a, b):
        lo, hi = N(a), N(b)
        if lo > hi:
            lo, hi = hi, lo
        if lo == hi:
            return lo
        if _is_int(a) and _is_int(b):
            return float(lo + math.floor(self.rng.random() * ((hi + 1) - lo)))
        return self.rng.random() * (hi - lo) + lo

    def _cloud_set(self, name, value):
        self.on_cloud_set(name, S(value))

    def _wait(self, d: float):
        dt = max(d, 1 / 30)
        self.now += dt
        self.on_wait(dt)

    def _reset_timer(self):
        self.timer0 = self.now

    def _answer(self):
        if not self.answers:
            raise StopScript()
        return self.answers.pop(0)

    # run --------------------------------------------------------------------
    def call(self, proccode: str, *args):
        return self.ns[self.c.procs[proccode]](*args)

    def run_flag(self):
        self.ns["FLAG"]()
