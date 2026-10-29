#!/usr/bin/env python3
"""Derive the v1.0.0 Scratch client template from the compiled v0.1 client.

The cryptographic blocks (X25519, HChaCha20, ChaCha20-Poly1305 ...) are kept **byte for byte**
as compiled in v0.1 (they were verified against the standards; see tests/). Only the
connection layer is changed, by editing blocks directly:

1. ``🔒 connect`` re-sends the HELLO every 6 s (3 sends max) while no reply has arrived.
   (v0.1 sent it once; a single lost cloud-variable update meant a 30 s timeout.)
2. New block ``🔒 request (text) (max N sec)`` = send text + wait for message.
3. The text table (lists ``TXT_CHARS`` / ``TXT_CODES``) is extended with hiragana, katakana and
   Japanese punctuation (data only; the first 69 entries are asserted identical to v0.1).

Usage:  python tools/make_template.py [upstream.sb3] [out.json]
"""
from __future__ import annotations

import copy
import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from cloudiamond_scratch import text as scratch_text  # noqa: E402
DEFAULT_IN = ROOT / "tools" / "upstream" / "v0.1_DEMO.sb3"
DEFAULT_OUT = ROOT / "src" / "cloudiamond_scratch" / "data" / "client_template.json"

PREFIX = "cdv1"  # id prefix of every block / variable added by this tool


class Patcher:
    def __init__(self, project: dict):
        self.p = project
        self.sp = next(t for t in project["targets"] if not t["isStage"] and t["blocks"])
        self.B = self.sp["blocks"]
        self._n = 0

    # -- id / block helpers
    def bid(self) -> str:
        self._n += 1
        return f"{PREFIX}b{self._n:03d}"

    def add(self, opcode, parent, inputs=None, fields=None, nxt=None, **extra) -> str:
        i = self.bid()
        self.B[i] = {"opcode": opcode, "next": nxt, "parent": parent, "inputs": inputs or {},
                     "fields": fields or {}, "shadow": False, "topLevel": False, **extra}
        return i

    def add_var(self, name: str) -> str:
        vid = f"v{PREFIX}_{name.replace('.', '_')}"
        assert vid not in self.sp["variables"]
        self.sp["variables"][vid] = [name, 0]
        return vid

    def var_id(self, name: str) -> str:
        return next(k for k, v in self.sp["variables"].items() if v[0] == name)

    def proto(self, proccode: str) -> tuple[str, dict]:
        for k, b in self.B.items():
            if isinstance(b, dict) and b["opcode"] == "procedures_prototype" and b["mutation"]["proccode"] == proccode:
                return k, b
        raise KeyError(proccode)

    def call_mutation(self, proccode: str) -> dict:
        _, pr = self.proto(proccode)
        m = pr["mutation"]
        return {"tagName": "mutation", "children": [], "proccode": proccode,
                "argumentids": m["argumentids"], "warp": m["warp"]}

    # -- tiny expression constructors (formats copied from the v0.1 blocks)
    @staticmethod
    def var_in(name, vid):
        return [3, [12, name, vid], [10, ""]]

    @staticmethod
    def lit(s):
        return [1, [10, str(s)]]

    def timer(self, parent) -> str:
        return self.add("sensing_timer", parent)

    def set_var(self, parent, name, value_input, nxt=None) -> str:
        return self.add("data_setvariableto", parent, {"VALUE": value_input},
                        {"VARIABLE": [name, self.var_id(name)]}, nxt)

    # -- patch 1: HELLO retransmission ------------------------------------------------
    def patch_connect(self):
        sends = self.add_var("ss_connect.sends")
        tl = self.add_var("ss_connect.tl")
        t0 = next(k for k, b in self.B.items() if isinstance(b, dict) and b["opcode"] == "data_setvariableto"
                  and b["fields"]["VARIABLE"][0] == "ss_connect.t0")
        loop = self.B[t0]["next"]
        assert self.B[loop]["opcode"] == "control_repeat_until"

        # ss_connect.tl = timer ; ss_connect.sends = 1   (inserted before the loop)
        s1 = self.set_var(t0, "ss_connect.tl", None)
        tm = self.timer(s1)
        self.B[s1]["inputs"] = {"VALUE": [3, tm, [10, ""]]}
        s2 = self.set_var(s1, "ss_connect.sends", self.lit(1), nxt=loop)
        self.B[s1]["next"] = s2
        self.B[t0]["next"] = s1
        self.B[loop]["parent"] = s2

        # inside the loop, right after wait(0.1):
        #   if (SS_TRIES < 1) and (sends < 3) and ((timer - tl) > 6): resend HELLO
        wait = self.B[loop]["inputs"]["SUBSTACK"][1]
        assert self.B[wait]["opcode"] == "control_wait"
        old_next = self.B[wait]["next"]
        iff = self.add("control_if", wait, nxt=old_next)
        self.B[wait]["next"] = iff
        self.B[old_next]["parent"] = iff

        a1 = self.add("operator_and", iff)
        a2 = self.add("operator_and", a1)
        c_tries = self.add("operator_lt", a2, {"OPERAND1": self.var_in("SS_TRIES", self.var_id("SS_TRIES")),
                                                 "OPERAND2": self.lit(1)})
        c_sends = self.add("operator_lt", a2, {"OPERAND1": self.var_in("ss_connect.sends", sends),
                                                 "OPERAND2": self.lit(3)})
        self.B[a2]["inputs"] = {"OPERAND1": [2, c_tries], "OPERAND2": [2, c_sends]}
        gt = self.add("operator_gt", a1)
        sub = self.add("operator_subtract", gt)
        tm2 = self.timer(sub)
        self.B[sub]["inputs"] = {"NUM1": [3, tm2, [4, "0"]], "NUM2": [3, [12, "ss_connect.tl", tl], [4, "0"]]}
        self.B[gt]["inputs"] = {"OPERAND1": [3, sub, [10, ""]], "OPERAND2": self.lit(6)}
        self.B[a1]["inputs"] = {"OPERAND1": [2, a2], "OPERAND2": [2, gt]}

        resend = self.add("procedures_call", iff, mutation=self.call_mutation("ss_ss send frame"))
        inc = self.add("data_changevariableby", resend, {"VALUE": [1, [4, "1"]]},
                       {"VARIABLE": ["ss_connect.sends", sends]})
        tm3 = self.timer(None)
        setl = self.set_var(inc, "ss_connect.tl", [3, tm3, [10, ""]])
        self.B[tm3]["parent"] = setl
        self.B[resend]["next"] = inc
        self.B[inc]["next"] = setl
        self.B[iff]["inputs"] = {"CONDITION": [2, a1], "SUBSTACK": [2, resend]}

    # -- patch 3: text table -----------------------------------------------------------
    def patch_text_table(self):
        chars = next(v for v in self.sp["lists"].values() if v[0] == "TXT_CHARS")
        codes = next(v for v in self.sp["lists"].values() if v[0] == "TXT_CODES")
        n = len(chars[1])
        assert chars[1] == scratch_text.CHARS[:n], "ASCII part of the table must equal v0.1"
        assert [int(x) for x in codes[1]] == scratch_text.CODES[:n], "ASCII codes must equal v0.1"
        chars[1] = list(scratch_text.CHARS)
        codes[1] = list(scratch_text.CODES)

    # -- patch 2: 🔒 request ----------------------------------------------------------
    def add_request_block(self):
        code = "🔒 request %s (max %s sec)"
        d = f"{PREFIX}def_request"
        p = f"{PREFIX}proto_request"
        ids = [f"{PREFIX}req_a0", f"{PREFIX}req_a1"]
        self.B[d] = {"opcode": "procedures_definition", "next": None, "parent": None,
                     "inputs": {"custom_block": [2, p]}, "fields": {}, "shadow": False,
                     "topLevel": True, "x": 7225, "y": 15620}
        self.B[p] = {"opcode": "procedures_prototype", "next": None, "parent": d, "inputs": {}, "fields": {},
                     "shadow": False, "topLevel": False,
                     "mutation": {"tagName": "mutation", "children": [], "proccode": code,
                                  "argumentids": json.dumps(ids), "argumentnames": json.dumps(["text", "maxsec"]),
                                  "argumentdefaults": json.dumps(["", ""]), "warp": "false"}}

        def call(parent, proccode, arg_name):
            mut = self.call_mutation(proccode)
            cid = self.add("procedures_call", parent, mutation=mut)
            rep = self.add("argument_reporter_string_number", cid, fields={"VALUE": [arg_name, None]})
            key = json.loads(mut["argumentids"])[0]
            self.B[cid]["inputs"] = {key: [3, rep, [10, ""]]}
            return cid

        c1 = call(d, "🔒 send text %s", "text")
        c2 = call(c1, "🔒 wait for message (max %s sec)", "maxsec")
        self.B[d]["next"] = c1
        self.B[c1]["next"] = c2


def build_template(upstream_sb3: Path) -> dict:
    with zipfile.ZipFile(upstream_sb3) as z:
        project = json.loads(z.read("project.json"))
    pt = Patcher(project)
    pt.patch_connect()
    pt.add_request_block()
    pt.patch_text_table()
    return project


def main(argv: list[str]) -> int:
    src = Path(argv[1]) if len(argv) > 1 else DEFAULT_IN
    out = Path(argv[2]) if len(argv) > 2 else DEFAULT_OUT
    project = build_template(src)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(project, ensure_ascii=False, separators=(",", ":"), sort_keys=False), encoding="utf-8")
    print(f"wrote {out} ({out.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
