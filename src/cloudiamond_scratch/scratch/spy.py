"""
spy.py -- 制限付き Python ("SPy") を Scratch 3 のブロックへコンパイルする。

目的: Scratch の暗号コードを「手でブロックを組む」のではなく、読めてテストできる Python で書き、
      機械的にブロックへ変換する。同じソースは普通の Python としても実行できる(spyrt.py が部品を供給)。
      → Python 実行で暗号の正しさを検証し、VM 実行でコンパイラの正しさを検証できる。

SPy で使える構文
  宣言(モジュール直下)  X = Lst(n | [..], "表示名") | Var(初期値, "表示名") | Vars(n) | Cloud("☁ name") | 整数定数
  関数                  def f(a, b): ...      引数はスカラーのみ。値は return で返す(関数末尾のみ)
  文                    代入 / += -= / if elif else / while / for in range / for in unroll(コンパイル時展開)
                        L.append(v) L.clear() del L[i] / 関数呼び出し
  式                    + - * // %  比較  and or not  L[i]  len(L)  関数呼び出し(式の中でも可)
  部品                  rand_int mouse_x mouse_y timer reset_timer days_since_2000 ask answer say wait
                        join letter_of length_of list_index_of
デコレータ
  @api("proccode %s")   カスタムブロックの表示名(%s が引数の数だけ必要)
  @nowarp               「画面を再描画せずに実行」を切る(wait や UI を含む関数用)
  @when_flag            緑の旗スクリプト

制約(Scratch の仕様由来)
  ・数値は倍精度。整数の演算結果は 2^53 未満に収めること(暗号コード側で保証・テストで検査)
  ・再帰なし / 関数の戻り値は 1 個(グローバル `_ret` 経由) / 引数への代入不可
  ・「//」は floor(a / b)。a が 2^53 未満の整数なら、除数が何であっても結果は厳密
  ・ループ変数はループ後に「最後の値 + step」になる(Python は最後の値)。ループ後に読まないこと
"""
from __future__ import annotations

import ast
import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple


class SpyError(Exception):
    pass


class _NotConst(Exception):
    pass


_MISSING = object()
RET = "_ret"


def _hid(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest()[:20]


class Val:
    """lit: 定数(int/float/str/bool)   blk: ブロック ID"""
    __slots__ = ("kind", "v")

    def __init__(self, kind, v):
        self.kind, self.v = kind, v

    @property
    def is_lit(self):
        return self.kind == "lit"


def L(v):
    return Val("lit", v)


def B(i):
    return Val("blk", i)


INTRINSIC_REPORTERS = {
    "rand_int": ("operator_random", [("FROM", "num"), ("TO", "num")]),
    "mouse_x": ("sensing_mousex", []),
    "mouse_y": ("sensing_mousey", []),
    "timer": ("sensing_timer", []),
    "days_since_2000": ("sensing_dayssince2000", []),
    "answer": ("sensing_answer", []),
    "join": ("operator_join", [("STRING1", "text"), ("STRING2", "text")]),
    "letter_of": ("operator_letter_of", [("LETTER", "num"), ("STRING", "text")]),
    "length_of": ("operator_length", [("STRING", "text")]),
}
INTRINSIC_STATEMENTS = {
    "reset_timer": ("sensing_resettimer", []),
    "ask": ("sensing_askandwait", [("QUESTION", "text")]),
    "say": ("looks_say", [("MESSAGE", "text")]),
    "wait": ("control_wait", [("DURATION", "num")]),
}


class Fn:
    def __init__(self, node: ast.FunctionDef):
        self.node = node
        self.name = node.name
        self.params = [a.arg for a in node.args.args]
        self.warp = True
        self.flag = False
        self.proccode = None
        for d in node.decorator_list:
            if isinstance(d, ast.Name) and d.id == "nowarp":
                self.warp = False
            elif isinstance(d, ast.Name) and d.id == "when_flag":
                self.flag = True
            elif isinstance(d, ast.Call) and isinstance(d.func, ast.Name) and d.func.id == "api":
                self.proccode = ast.literal_eval(d.args[0])
        if self.proccode is None:
            self.proccode = ("ss_" + self.name.replace("_", " ")) + "".join(" %s" for _ in self.params)
        if self.proccode.count("%s") != len(self.params):
            raise SpyError("proccode/params mismatch in %s" % self.name)
        self.argids = ["%s_a%d" % (_hid(self.name), i) for i in range(len(self.params))]


class Ctx:
    def __init__(self, fn: Fn):
        self.fn = fn
        self.cenv: Dict[str, Any] = {}
        self.ntemp = 0
        # この関数の中で代入されるローカル名。ここに無い名前を読むのはタイプミスなのでエラーにする
        self.assigned = {n.id for n in ast.walk(fn.node) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}

    def new_temp(self):
        n = self.ntemp
        self.ntemp += 1
        return "%s._t%d" % (self.fn.name, n)


class Compiler:
    def __init__(self, source: str, list_overrides: Optional[Dict[str, List[Any]]] = None,
                 const_overrides: Optional[Dict[str, Any]] = None):
        self.tree = ast.parse(source)
        self.blocks: Dict[str, dict] = {}
        self.n = 0
        self.vars: Dict[str, str] = {}              # sprite 変数 name -> id
        self.var_init: Dict[str, Any] = {}
        self.cloud: Dict[str, str] = {}             # stage のクラウド変数 name -> id
        self.lists: Dict[str, Tuple[str, List[Any], str]] = {}   # python 名 -> (id, 初期値, 表示名)
        self.consts: Dict[str, Any] = dict(const_overrides or {})
        self.gvars: Dict[str, Any] = {}             # python 名 -> 表示名 | ("cloud", 名前)
        self.vararr: Dict[str, int] = {}
        self.fns: Dict[str, Fn] = {}
        self.scripts: List[Tuple[str, int]] = []    # (先頭ブロック ID, そのスクリプトのブロック数)
        self._declare(list_overrides or {})
        self.var_ref(RET, 0)

    # ------------------------------------------------------------ ブロック生成
    def newid(self) -> str:
        self.n += 1
        return "b%d" % self.n

    @staticmethod
    def _lit_input(v, kind):
        if isinstance(v, bool):
            v = int(v)
        if isinstance(v, float) and v == int(v) and abs(v) < 2 ** 53:
            v = int(v)
        return [4 if kind == "num" else 10, str(v)]

    def mk(self, opcode, inputs=None, fields=None, mutation=None, shadow=False, top=False):
        bid = self.newid()
        blk = {"opcode": opcode, "next": None, "parent": None, "inputs": {}, "fields": fields or {},
               "shadow": shadow, "topLevel": top}
        if mutation is not None:
            blk["mutation"] = mutation
        self.blocks[bid] = blk
        for name, (val, kind) in (inputs or {}).items():
            r = self._input(bid, val, kind)
            if r is not None:
                blk["inputs"][name] = r
        return bid

    def _input(self, parent, val, kind):
        if kind == "stack":
            if val is None:
                return None                        # 空の SUBSTACK は入力ごと省く
            self.blocks[val]["parent"] = parent
            return [2, val]
        if kind == "bool":
            if not (isinstance(val, Val) and val.kind == "blk"):
                raise SpyError("boolean input needs a block")
            self.blocks[val.v]["parent"] = parent
            return [2, val.v]
        if val.kind == "lit":
            return [1, self._lit_input(val.v, kind)]
        self.blocks[val.v]["parent"] = parent
        return [3, val.v, [4 if kind == "num" else 10, "0" if kind == "num" else ""]]

    def link(self, ids: List[str]) -> Optional[str]:
        ids = [i for i in ids if i]
        for a, b in zip(ids, ids[1:]):
            self.blocks[a]["next"] = b
            self.blocks[b]["parent"] = a
        return ids[0] if ids else None

    # ------------------------------------------------------------ 変数・リスト
    def var_ref(self, name: str, init: Any = 0, cloud: bool = False) -> Tuple[str, str]:
        if cloud:
            self.cloud.setdefault(name, "c" + _hid(name))
            return name, self.cloud[name]
        if name not in self.vars:
            self.vars[name] = "v" + _hid(name)
            self.var_init[name] = init
        return name, self.vars[name]

    def read_var(self, name, cloud=False) -> Val:
        n, i = self.var_ref(name, cloud=cloud)
        return B(self.mk("data_variable", fields={"VARIABLE": [n, i]}))

    def set_var(self, name, val: Val, cloud=False) -> str:
        n, i = self.var_ref(name, cloud=cloud)
        return self.mk("data_setvariableto", {"VALUE": (val, "text")}, {"VARIABLE": [n, i]})

    def change_var(self, name, val: Val, cloud=False) -> str:
        n, i = self.var_ref(name, cloud=cloud)
        return self.mk("data_changevariableby", {"VALUE": (val, "num")}, {"VARIABLE": [n, i]})

    def list_ref(self, name):
        if name not in self.lists:
            raise SpyError("unknown list %s" % name)
        return [self.lists[name][2], self.lists[name][0]]

    # ------------------------------------------------------------ 宣言の収集
    def _declare(self, list_overrides):
        for node in self.tree.body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                name, v = node.targets[0].id, node.value
                if isinstance(v, ast.Call) and isinstance(v.func, ast.Name):
                    f = v.func.id
                    if f == "Lst":
                        arg = v.args[0] if v.args else ast.Constant(0)
                        if isinstance(arg, ast.List):
                            items = [self.const_eval(e, {}) for e in arg.elts]
                        else:
                            items = [0] * self.const_eval(arg, {})
                        items = list_overrides.get(name, items)
                        display = ast.literal_eval(v.args[1]) if len(v.args) > 1 else name
                        self.lists[name] = ("l" + _hid(name), list(items), display)
                        continue
                    if f == "Var":
                        init = self.const_eval(v.args[0], {}) if v.args else 0
                        display = ast.literal_eval(v.args[1]) if len(v.args) > 1 else name
                        self.gvars[name] = display
                        self.var_ref(display, init)
                        self.var_init[display] = init
                        continue
                    if f == "Cloud":
                        cname = ast.literal_eval(v.args[0])
                        self.gvars[name] = ("cloud", cname)
                        self.var_ref(cname, cloud=True)
                        continue
                    if f == "Vars":
                        cnt = self.const_eval(v.args[0], {})
                        self.vararr[name] = cnt
                        for i in range(cnt):
                            self.var_ref("%s_%d" % (name, i), 0)
                        continue
                if name in self.consts:             # 外部指定の上書きを優先
                    continue
                self.consts[name] = self.const_eval(v, {})
            elif isinstance(node, ast.FunctionDef):
                self.fns[node.name] = Fn(node)
            elif isinstance(node, (ast.Import, ast.ImportFrom, ast.Expr)):
                continue
            else:
                raise SpyError("unsupported module-level statement at line %d" % node.lineno)

    # ------------------------------------------------------------ 定数評価
    def const_eval(self, node, cenv) -> Any:
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            if node.id in cenv:
                return cenv[node.id]
            if node.id in self.consts:
                return self.consts[node.id]
            raise _NotConst()
        if isinstance(node, ast.UnaryOp):
            v = self.const_eval(node.operand, cenv)
            if isinstance(node.op, ast.USub):
                return -v
            if isinstance(node.op, ast.Not):
                return not v
            if isinstance(node.op, ast.UAdd):
                return v
        if isinstance(node, ast.BinOp):
            a, b = self.const_eval(node.left, cenv), self.const_eval(node.right, cenv)
            op = node.op
            if isinstance(op, ast.Add): return a + b
            if isinstance(op, ast.Sub): return a - b
            if isinstance(op, ast.Mult): return a * b
            if isinstance(op, ast.FloorDiv): return a // b
            if isinstance(op, ast.Mod): return a % b
            if isinstance(op, ast.Pow): return a ** b
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            a, b = self.const_eval(node.left, cenv), self.const_eval(node.comparators[0], cenv)
            op = type(node.ops[0])
            table = {ast.Lt: lambda: a < b, ast.Gt: lambda: a > b, ast.Eq: lambda: a == b,
                     ast.NotEq: lambda: a != b, ast.LtE: lambda: a <= b, ast.GtE: lambda: a >= b}
            if op in table:
                return table[op]()
        if isinstance(node, ast.BoolOp):
            vals = [self.const_eval(x, cenv) for x in node.values]
            return all(vals) if isinstance(node.op, ast.And) else any(vals)
        raise _NotConst()

    def try_const(self, node, cenv):
        try:
            return True, self.const_eval(node, cenv)
        except _NotConst:
            return False, None
        except ZeroDivisionError:
            raise SpyError("division by zero in constant expression")

    # ------------------------------------------------------------ 式
    def expr(self, node, ctx: Ctx, pre: List[str]) -> Val:
        ok, c = self.try_const(node, ctx.cenv)
        if ok:
            return L(c)
        if isinstance(node, ast.Name):
            return self.name_read(node.id, ctx, node)
        if isinstance(node, ast.BinOp):
            return self.binop(node, ctx, pre)
        if isinstance(node, ast.UnaryOp):
            if isinstance(node.op, ast.USub):
                return B(self.mk("operator_subtract", {"NUM1": (L(0), "num"),
                                                       "NUM2": (self.expr(node.operand, ctx, pre), "num")}))
            if isinstance(node.op, ast.Not):
                return B(self.mk("operator_not", {"OPERAND": (self.boolexpr(node.operand, ctx, pre), "bool")}))
        if isinstance(node, (ast.Compare, ast.BoolOp)):
            return self.boolexpr(node, ctx, pre)
        if isinstance(node, ast.Subscript):
            return self.subscript_read(node, ctx, pre)
        if isinstance(node, ast.Call):
            return self.call_expr(node, ctx, pre)
        raise SpyError("unsupported expression %s (line %d)" % (type(node).__name__, node.lineno))

    def name_read(self, name, ctx: Ctx, node) -> Val:
        fn = ctx.fn
        if name in fn.params:
            return B(self.mk("argument_reporter_string_number", fields={"VALUE": [name, None]}))
        g = self.gvars.get(name)
        if g is not None:
            return self.read_var(g[1], cloud=True) if isinstance(g, tuple) else self.read_var(g)
        if name in self.lists or name in self.vararr:
            raise SpyError("list/array %s used as a scalar (line %d)" % (name, node.lineno))
        if name not in ctx.assigned:
            raise SpyError("undefined name %r in %s (line %d)" % (name, fn.name, node.lineno))
        return self.read_var("%s.%s" % (fn.name, name))

    def binop(self, node, ctx, pre) -> Val:
        op = type(node.op)
        a = self.expr(node.left, ctx, pre)
        b = self.expr(node.right, ctx, pre)
        if op is ast.Add:
            if b.is_lit and b.v == 0: return a
            if a.is_lit and a.v == 0: return b
            return B(self.mk("operator_add", {"NUM1": (a, "num"), "NUM2": (b, "num")}))
        if op is ast.Sub:
            if b.is_lit and b.v == 0: return a
            return B(self.mk("operator_subtract", {"NUM1": (a, "num"), "NUM2": (b, "num")}))
        if op is ast.Mult:
            if b.is_lit and b.v == 1: return a
            if a.is_lit and a.v == 1: return b
            return B(self.mk("operator_multiply", {"NUM1": (a, "num"), "NUM2": (b, "num")}))
        if op is ast.Mod:
            return B(self.mk("operator_mod", {"NUM1": (a, "num"), "NUM2": (b, "num")}))
        if op is ast.FloorDiv:                      # 注意: `x // 1` は床関数なので最適化で消してはいけない
            d = self.mk("operator_divide", {"NUM1": (a, "num"), "NUM2": (b, "num")})
            return B(self.mk("operator_mathop", {"NUM": (B(d), "num")}, {"OPERATOR": ["floor", None]}))
        raise SpyError("unsupported operator %s (line %d)" % (op.__name__, node.lineno))

    def boolexpr(self, node, ctx, pre) -> Val:
        ok, _c = self.try_const(node, ctx.cenv)
        if ok:
            raise SpyError("constant boolean in expression position (line %d)" % node.lineno)
        if isinstance(node, ast.BoolOp):
            n0 = len(pre)
            parts = [self.boolexpr(v, ctx, pre) for v in node.values]
            if len(pre) != n0:
                raise SpyError("function call inside and/or is not supported (line %d)" % node.lineno)
            opc = "operator_and" if isinstance(node.op, ast.And) else "operator_or"
            acc = parts[0]
            for p in parts[1:]:
                acc = B(self.mk(opc, {"OPERAND1": (acc, "bool"), "OPERAND2": (p, "bool")}))
            return acc
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return self.negate(self.boolexpr(node.operand, ctx, pre))
        if isinstance(node, ast.Compare):
            if len(node.ops) != 1:
                raise SpyError("chained comparison not supported (line %d)" % node.lineno)
            a = self.expr(node.left, ctx, pre)
            b = self.expr(node.comparators[0], ctx, pre)
            op = type(node.ops[0])
            base = {ast.Lt: "operator_lt", ast.GtE: "operator_lt", ast.Gt: "operator_gt",
                    ast.LtE: "operator_gt", ast.Eq: "operator_equals", ast.NotEq: "operator_equals"}.get(op)
            if base is None:
                raise SpyError("unsupported comparison (line %d)" % node.lineno)
            r = B(self.mk(base, {"OPERAND1": (a, "text"), "OPERAND2": (b, "text")}))
            return self.negate(r) if op in (ast.GtE, ast.LtE, ast.NotEq) else r
        raise SpyError("condition must be a comparison (line %d)" % node.lineno)

    def negate(self, v: Val) -> Val:
        blk = self.blocks[v.v]
        if blk["opcode"] == "operator_not":         # not not x -> x
            inner = blk["inputs"]["OPERAND"][1]
            self.blocks[inner]["parent"] = None
            del self.blocks[v.v]                    # 使われなくなった not を残さない
            return B(inner)
        return B(self.mk("operator_not", {"OPERAND": (v, "bool")}))

    def index_val(self, idx_node, ctx, pre) -> Val:
        """0 始まりの添字式 -> Scratch の 1 始まり添字"""
        ok, c = self.try_const(idx_node, ctx.cenv)
        if ok:
            return L(c + 1)
        if isinstance(idx_node, ast.BinOp) and isinstance(idx_node.op, ast.Add):
            ok2, c2 = self.try_const(idx_node.right, ctx.cenv)
            if ok2:
                return B(self.mk("operator_add", {"NUM1": (self.expr(idx_node.left, ctx, pre), "num"),
                                                  "NUM2": (L(c2 + 1), "num")}))
        return B(self.mk("operator_add", {"NUM1": (self.expr(idx_node, ctx, pre), "num"), "NUM2": (L(1), "num")}))

    def subscript_read(self, node, ctx, pre) -> Val:
        if not isinstance(node.value, ast.Name):
            raise SpyError("subscript base must be a name (line %d)" % node.lineno)
        name = node.value.id
        if name in self.vararr:
            ok, c = self.try_const(node.slice, ctx.cenv)
            if not ok:
                raise SpyError("index of %s must be a compile-time constant (line %d)" % (name, node.lineno))
            return self.read_var("%s_%d" % (name, c))
        idx = self.index_val(node.slice, ctx, pre)
        return B(self.mk("data_itemoflist", {"INDEX": (idx, "num")}, {"LIST": self.list_ref(name)}))

    # ------------------------------------------------------------ 呼び出し
    def call_expr(self, node, ctx, pre) -> Val:
        if not isinstance(node.func, ast.Name):
            raise SpyError("unsupported call (line %d)" % node.lineno)
        f = node.func.id
        if f == "len":
            return B(self.mk("data_lengthoflist", fields={"LIST": self.list_ref(node.args[0].id)}))
        if f == "list_index_of":
            lst = self.list_ref(node.args[0].id)
            v = self.expr(node.args[1], ctx, pre)
            return B(self.mk("data_itemnumoflist", {"ITEM": (v, "text")}, {"LIST": lst}))
        if f in INTRINSIC_REPORTERS:
            opc, spec = INTRINSIC_REPORTERS[f]
            ins = {nm: (self.expr(a, ctx, pre), k) for (nm, k), a in zip(spec, node.args)}
            return B(self.mk(opc, ins))
        if f in self.fns:
            self.call_stmt(node, ctx, pre)
            t = ctx.new_temp()
            pre.append(self.set_var(t, self.read_var(RET)))     # 戻り値をすぐ退避(次の呼び出しで上書きされる)
            return self.read_var(t)
        raise SpyError("unknown function %s (line %d)" % (f, node.lineno))

    def call_stmt(self, node, ctx, pre) -> None:
        fn = self.fns[node.func.id]
        if len(node.args) != len(fn.params):
            raise SpyError("wrong arg count calling %s (line %d)" % (fn.name, node.lineno))
        ins = {aid: (self.expr(a, ctx, pre), "text") for aid, a in zip(fn.argids, node.args)}
        mut = {"tagName": "mutation", "children": [], "proccode": fn.proccode,
               "argumentids": json.dumps(fn.argids), "warp": "true" if fn.warp else "false"}
        pre.append(self.mk("procedures_call", ins, mutation=mut))

    # ------------------------------------------------------------ 文
    def stmts(self, body, ctx: Ctx, tail: bool) -> List[str]:
        out: List[str] = []
        for i, s in enumerate(body):
            out += self.stmt(s, ctx, tail and i == len(body) - 1)
        return out

    def stack(self, body, ctx, tail=False) -> Optional[str]:
        return self.link(self.stmts(body, ctx, tail))

    def stmt(self, node, ctx: Ctx, tail: bool) -> List[str]:
        ctx.ntemp = 0
        pre: List[str] = []
        if isinstance(node, (ast.Pass, ast.Global, ast.Assert)):
            return []
        if isinstance(node, ast.Expr):
            if isinstance(node.value, ast.Constant):
                return []
            return self.expr_stmt(node.value, ctx, pre)
        if isinstance(node, ast.Assign):
            if len(node.targets) != 1:
                raise SpyError("multiple assignment targets (line %d)" % node.lineno)
            return self.assign(node.targets[0], node.value, ctx, pre)
        if isinstance(node, ast.AugAssign):
            return self.augassign(node, ctx, pre)
        if isinstance(node, ast.If):
            return self.if_stmt(node, ctx, pre, tail)
        if isinstance(node, ast.While):
            return self.while_stmt(node, ctx)
        if isinstance(node, ast.For):
            return self.for_stmt(node, ctx)
        if isinstance(node, ast.Return):
            if not tail:
                raise SpyError("return is only allowed at the end of a function (line %d)" % node.lineno)
            if node.value is None:
                return []
            v = self.expr(node.value, ctx, pre)
            return pre + [self.set_var(RET, v)]
        if isinstance(node, ast.Delete):
            t = node.targets[0]
            idx = self.index_val(t.slice, ctx, pre)
            return pre + [self.mk("data_deleteoflist", {"INDEX": (idx, "num")}, {"LIST": self.list_ref(t.value.id)})]
        raise SpyError("unsupported statement %s (line %d)" % (type(node).__name__, node.lineno))

    def expr_stmt(self, node, ctx, pre) -> List[str]:
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            lst, m = node.func.value.id, node.func.attr
            if m == "append":
                v = self.expr(node.args[0], ctx, pre)
                return pre + [self.mk("data_addtolist", {"ITEM": (v, "text")}, {"LIST": self.list_ref(lst)})]
            if m == "clear":
                return pre + [self.mk("data_deletealloflist", fields={"LIST": self.list_ref(lst)})]
            raise SpyError("unsupported method %s (line %d)" % (m, node.lineno))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            f = node.func.id
            if f in INTRINSIC_STATEMENTS:
                opc, spec = INTRINSIC_STATEMENTS[f]
                ins = {nm: (self.expr(a, ctx, pre), k) for (nm, k), a in zip(spec, node.args)}
                return pre + [self.mk(opc, ins)]
            if f in self.fns:
                self.call_stmt(node, ctx, pre)
                return pre
        raise SpyError("unsupported expression statement (line %d)" % node.lineno)

    def scalar_name(self, tgt, ctx):
        """Name / Vars[定数] -> (scratch 変数名, cloud?)。リスト要素などは None。"""
        if isinstance(tgt, ast.Name):
            if tgt.id in ctx.fn.params or tgt.id in ctx.cenv:
                return None
            g = self.gvars.get(tgt.id)
            if isinstance(g, tuple):
                return g[1], True
            if g is not None:
                return g, False
            return "%s.%s" % (ctx.fn.name, tgt.id), False
        if isinstance(tgt, ast.Subscript) and isinstance(tgt.value, ast.Name) and tgt.value.id in self.vararr:
            ok, c = self.try_const(tgt.slice, ctx.cenv)
            if not ok:
                raise SpyError("index of %s must be a compile-time constant (line %d)" % (tgt.value.id, tgt.lineno))
            return "%s_%d" % (tgt.value.id, c), False
        return None

    def target_set(self, tgt, val: Val, ctx, pre) -> List[str]:
        if isinstance(tgt, ast.Name) and tgt.id in ctx.fn.params:
            raise SpyError("assignment to parameter %s (line %d)" % (tgt.id, tgt.lineno))
        sn = self.scalar_name(tgt, ctx)
        if sn is not None:
            return pre + [self.set_var(sn[0], val, cloud=sn[1])]
        if isinstance(tgt, ast.Subscript) and isinstance(tgt.value, ast.Name):
            idx = self.index_val(tgt.slice, ctx, pre)
            return pre + [self.mk("data_replaceitemoflist", {"INDEX": (idx, "num"), "ITEM": (val, "text")},
                                  {"LIST": self.list_ref(tgt.value.id)})]
        raise SpyError("unsupported assignment target (line %d)" % tgt.lineno)

    def assign(self, tgt, value, ctx, pre) -> List[str]:
        # x = x + e  ->  change x by e   (スカラー変数のみ。ブロック数を減らして速くする)
        sn = self.scalar_name(tgt, ctx)
        if sn is not None and isinstance(value, ast.BinOp) and isinstance(value.op, (ast.Add, ast.Sub)) \
                and ast.dump(tgt).replace("Store()", "Load()") == ast.dump(value.left):
            return self.change(sn, value.right, isinstance(value.op, ast.Sub), ctx, pre)
        v = self.expr(value, ctx, pre)
        return self.target_set(tgt, v, ctx, pre)

    def change(self, sn, rhs, negative, ctx, pre) -> List[str]:
        r = self.expr(rhs, ctx, pre)
        if negative:
            r = L(-r.v) if r.is_lit else B(self.mk("operator_subtract", {"NUM1": (L(0), "num"), "NUM2": (r, "num")}))
        return pre + [self.change_var(sn[0], r, cloud=sn[1])]

    def augassign(self, node, ctx, pre) -> List[str]:
        sn = self.scalar_name(node.target, ctx)
        if sn is not None and isinstance(node.op, (ast.Add, ast.Sub)):
            return self.change(sn, node.value, isinstance(node.op, ast.Sub), ctx, pre)
        left = ast.parse(ast.unparse(node.target), mode="eval").body      # Store -> Load の読み取り式
        bin_ = ast.BinOp(left=left, op=node.op, right=node.value)
        ast.copy_location(bin_, node)
        ast.fix_missing_locations(bin_)
        v = self.expr(bin_, ctx, pre)
        return self.target_set(node.target, v, ctx, pre)

    def if_stmt(self, node, ctx, pre, tail) -> List[str]:
        ok, c = self.try_const(node.test, ctx.cenv)
        if ok:                                       # コンパイル時に分岐を確定(unroll 内の `if i < 15:` など)
            return self.stmts(node.body if c else node.orelse, ctx, tail)
        cond = self.boolexpr(node.test, ctx, pre)
        body = self.stack(node.body, ctx, tail)
        if node.orelse:
            els = self.stack(node.orelse, ctx, tail)
            b = self.mk("control_if_else", {"CONDITION": (cond, "bool"), "SUBSTACK": (body, "stack"),
                                            "SUBSTACK2": (els, "stack")})
        else:
            b = self.mk("control_if", {"CONDITION": (cond, "bool"), "SUBSTACK": (body, "stack")})
        return pre + [b]

    def while_stmt(self, node, ctx) -> List[str]:
        ok, c = self.try_const(node.test, ctx.cenv)
        if ok and c:
            return [self.mk("control_forever", {"SUBSTACK": (self.stack(node.body, ctx), "stack")})]
        pre: List[str] = []
        cond = self.boolexpr(node.test, ctx, pre)
        if pre:
            raise SpyError("function call in while-condition is not supported (line %d)" % node.lineno)
        body = self.stack(node.body, ctx)
        return [self.mk("control_repeat_until", {"CONDITION": (self.negate(cond), "bool"),
                                                 "SUBSTACK": (body, "stack")})]

    def for_stmt(self, node, ctx) -> List[str]:
        if not (isinstance(node.target, ast.Name) and isinstance(node.iter, ast.Call)
                and isinstance(node.iter.func, ast.Name) and node.iter.func.id in ("range", "unroll")):
            raise SpyError("only `for x in range(..)` / `unroll(..)` is supported (line %d)" % node.lineno)
        kind, args, var = node.iter.func.id, node.iter.args, node.target.id
        if kind == "unroll":
            vals = [self.const_eval(a, ctx.cenv) for a in args]
            out: List[str] = []
            saved = ctx.cenv.get(var, _MISSING)
            for i in range(*vals):
                ctx.cenv[var] = i
                out += self.stmts(node.body, ctx, False)
            if saved is _MISSING:
                ctx.cenv.pop(var, None)
            else:
                ctx.cenv[var] = saved
            return out
        pre: List[str] = []
        if len(args) == 1:
            start, stop, step = ast.Constant(0), args[0], ast.Constant(1)
        elif len(args) == 2:
            start, stop, step = args[0], args[1], ast.Constant(1)
        else:
            start, stop, step = args
        okstep, stepv = self.try_const(step, ctx.cenv)
        if not okstep:
            raise SpyError("range step must be constant (line %d)" % node.lineno)
        oks, sv = self.try_const(start, ctx.cenv)
        oke, ev = self.try_const(stop, ctx.cenv)
        if stepv == 1:
            if oks and oke:
                count = L(max(0, ev - sv))
            elif oks and sv == 0:
                count = self.expr(stop, ctx, pre)
            else:                                    # 同じブロックを 2 か所に使えないので、開始式は 2 回コンパイルする
                count = B(self.mk("operator_subtract", {"NUM1": (self.expr(stop, ctx, pre), "num"),
                                                        "NUM2": (self.expr(start, ctx, pre), "num")}))
        elif oks and oke:
            cnt = -(-(ev - sv) // stepv) if stepv > 0 else -(-(sv - ev) // -stepv)
            count = L(max(0, cnt))
        else:
            raise SpyError("range with step != 1 needs constant bounds (line %d)" % node.lineno)
        vname = "%s.%s" % (ctx.fn.name, var)
        setv = self.set_var(vname, self.expr(start, ctx, pre))
        body = self.stmts(node.body, ctx, False)
        inc = self.change_var(vname, L(stepv))
        loop = self.mk("control_repeat", {"TIMES": (count, "num"), "SUBSTACK": (self.link(body + [inc]), "stack")})
        return pre + [setv, loop]

    # ------------------------------------------------------------ 関数 -> スクリプト
    def compile_function(self, fn: Fn, x: int, y: int) -> int:
        n0 = self.n
        ctx = Ctx(fn)
        first = self.link(self.stmts(fn.node.body, ctx, True))
        if fn.flag:
            top = self.mk("event_whenflagclicked", top=True)
        else:
            proto = self.mk("procedures_prototype", shadow=True, mutation={
                "tagName": "mutation", "children": [], "proccode": fn.proccode,
                "argumentids": json.dumps(fn.argids), "argumentnames": json.dumps(fn.params),
                "argumentdefaults": json.dumps([""] * len(fn.params)), "warp": "true" if fn.warp else "false"})
            pb = self.blocks[proto]
            for aid, pname in zip(fn.argids, fn.params):
                rep = self.mk("argument_reporter_string_number", fields={"VALUE": [pname, None]}, shadow=True)
                self.blocks[rep]["parent"] = proto
                pb["inputs"][aid] = [1, rep]
            top = self.mk("procedures_definition", top=True)
            self.blocks[top]["inputs"]["custom_block"] = [1, proto]
            pb["parent"] = top
        self.blocks[top]["x"], self.blocks[top]["y"] = x, y
        if first:
            self.blocks[top]["next"] = first
            self.blocks[first]["parent"] = top
        count = self.n - n0
        self.scripts.append((top, count))
        return count

    def compile_all(self) -> None:
        """スクリプトを縦に並べ、長くなったら次の列へ(Scratch の「ブロックを整理」でも整う)。"""
        x, y = 0, 0
        for fn in self.fns.values():
            count = self.compile_function(fn, x, y)
            y += 90 + 7 * count
            if y > 6000:
                x, y = x + 900, 0
