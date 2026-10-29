"""Build, lint, audit and verify the Scratch client (``.sb3``).

The client is a Scratch sprite (custom blocks ``🔒 connect`` / ``🔒 send text`` / ``🔒 request`` ...)
whose only per-deployment input is the server's **public** key. ``build_sb3`` is deterministic in
content: the same (public key, name, demo flag, package version) always yields the same
``project.json`` and assets.
"""
from __future__ import annotations

import copy
import hashlib
import io
import json
import re
import zipfile
from dataclasses import dataclass, field
from importlib import resources

from . import protocol as P
from ._version import __version__
from .crypto import fingerprint

__all__ = ["build_project", "build_sb3", "read_sb3", "embedded_public_key", "lint_project",
           "audit_project", "verify_project", "Finding", "AuditReport", "VerifyReport", "DEFAULT_NAME"]

DEFAULT_NAME = "Cloudiamond"
SPRITE_PREFIX = "\U0001F48E"        # 💎
_TEMPLATE_BASE_NAME = SPRITE_PREFIX + DEFAULT_NAME
_COMMENT_ID = "cdv1comment"
MAX_PROJECT_BYTES = 64 * 1024 * 1024

# --- which template lists are public constants / secrets / message residue -----------------
_CONSTANT_LISTS = {"XOR4", "BITP", "DIGITS", "TXT_CHARS", "TXT_CODES", "LBL_MASTER", "LBL_C2S", "LBL_S2C", "READYB", "SRV"}
_KEY_LISTS = {"EK", "DHES", "DHEE", "MASTER", "KC2S", "KS2C", "AK", "HCK", "CCK", "XK", "ZK", "PKEY", "XOUT", "HCO", "CCO"}
_MESSAGE_LISTS = {"BUF", "\U0001F512 TX bytes", "\U0001F512 RX bytes"}
_MESSAGE_VARS = {"\U0001F512 received text"}
_HEX64 = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")


# ---------------------------------------------------------------------------- template ----
def _data(name: str) -> bytes:
    return (resources.files("cloudiamond_scratch") / "data" / name).read_bytes()


def _template() -> dict:
    return json.loads(_data("client_template.json").decode("utf-8"))


def _assets() -> dict[str, bytes]:
    return {n.name: n.read_bytes() for n in (resources.files("cloudiamond_scratch") / "data").iterdir()
            if n.name.endswith(".svg")}


def _sprite(project: dict) -> dict:
    sprites = [t for t in project["targets"] if not t["isStage"] and t["blocks"]]
    if len(sprites) != 1:
        raise ValueError("expected exactly one client sprite")
    return sprites[0]


def _list_by_name(target: dict, name: str):
    for v in target["lists"].values():
        if v[0] == name:
            return v
    raise KeyError(name)


def embedded_public_key(project: dict) -> bytes:
    """The server public key embedded in the client (the ``SRV`` list)."""
    vals = _list_by_name(_sprite(project), "SRV")[1]
    try:
        key = bytes(int(float(x)) for x in vals)
    except (TypeError, ValueError, OverflowError):
        raise ValueError("SRV list does not hold a valid key") from None
    if len(key) != 32:
        raise ValueError("SRV list does not hold 32 bytes")
    return key


def _remove_script(blocks: dict, top_id: str) -> None:
    stack, seen = [top_id], set()
    while stack:
        i = stack.pop()
        if i in seen or i not in blocks:
            continue
        seen.add(i)
        b = blocks[i]
        if b.get("next"):
            stack.append(b["next"])
        for inp in b["inputs"].values():
            if isinstance(inp, list) and len(inp) > 1 and isinstance(inp[1], str):
                stack.append(inp[1])
    for i in seen:
        del blocks[i]


def _comment_text(pub: bytes) -> str:
    return (
        f"cloudiamond-scratch v{__version__} (protocol {P.CLOUD_PREFIX.strip()} SCRSEC1)\n"
        f"Server public key (not secret):\n{pub.hex()}\n"
        f"Fingerprint: {fingerprint(pub)}\n\n"
        "Blocks: \U0001F512 connect / \U0001F512 send text / \U0001F512 wait for message / \U0001F512 request / "
        "\U0001F512 wipe secrets / \U0001F512 disconnect\n"
        "Do NOT delete the variables and lists (the client needs them), and never put the server's "
        "SECRET key (server.key) in Scratch.\n"
        "BEFORE you save or share this project run \U0001F512 wipe secrets (or \U0001F512 disconnect)."
    )


def build_project(pub: bytes, *, name: str = DEFAULT_NAME, demo: bool = True) -> dict:
    """The ``project.json`` of the client for the server public key ``pub``."""
    if len(pub) != 32:
        raise ValueError("public key must be 32 bytes")
    name = name.strip()
    if not name or len(name) > 40 or any(ord(c) < 32 for c in name):
        raise ValueError("name must be 1..40 printable characters")
    project = _template()
    sp = _sprite(project)
    _list_by_name(sp, "SRV")[1] = list(pub)
    new_name = SPRITE_PREFIX + name
    sp["name"] = new_name
    for m in project["monitors"]:
        if m.get("spriteName") == _TEMPLATE_BASE_NAME:
            m["spriteName"] = new_name
    if not demo:
        for bid, b in list(sp["blocks"].items()):
            if isinstance(b, dict) and b["opcode"] == "event_whenflagclicked" and b.get("topLevel"):
                _remove_script(sp["blocks"], bid)
    sp["comments"] = {_COMMENT_ID: {"blockId": None, "x": 8300, "y": 14400, "width": 480, "height": 300,
                                    "minimized": False, "text": _comment_text(pub)}}
    return project


def _dump(project: dict) -> bytes:
    return json.dumps(project, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def build_sb3(pub: bytes, *, name: str = DEFAULT_NAME, demo: bool = True) -> bytes:
    """A ready-to-open ``.sb3`` (zip) for the server public key ``pub``."""
    if len(pub) != 32:
        raise ValueError("public key must be 32 bytes")
    if not any(pub):
        raise ValueError("public key must not be all zero")
    files = {"project.json": _dump(build_project(pub, name=name, demo=demo))}
    files.update(_assets())
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for fname in ["project.json"] + sorted(k for k in files if k != "project.json"):
            zi = zipfile.ZipInfo(fname, date_time=(2020, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.create_system = 3
            zi.external_attr = 0o644 << 16
            z.writestr(zi, files[fname], compresslevel=9)
    return buf.getvalue()


def read_sb3(data: bytes) -> tuple[dict, dict[str, bytes]]:
    """Parse an ``.sb3``. Returns ``(project, assets)``. Raises ``ValueError`` on a bad / oversized file."""
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise ValueError("not a zip file (.sb3)") from None
    with z:
        infos = {i.filename: i for i in z.infolist()}
        if "project.json" not in infos:
            raise ValueError("project.json missing")
        if sum(i.file_size for i in infos.values()) > MAX_PROJECT_BYTES:
            raise ValueError("project too large")
        project = json.loads(z.read("project.json").decode("utf-8"))
        assets = {n: z.read(n) for n in infos if n != "project.json" and not n.endswith("/")}
    if not isinstance(project, dict) or "targets" not in project:
        raise ValueError("not a Scratch 3 project")
    return project, assets


# ------------------------------------------------------------------------------- lint ----
def lint_project(project: dict) -> list[str]:
    """Structural sanity checks (the kind of damage that makes Scratch refuse to load a project)."""
    errs: list[str] = []
    stage = [t for t in project.get("targets", []) if t.get("isStage")]
    if len(stage) != 1:
        return ["project must have exactly one stage"]
    cloud = {v[0] for v in stage[0]["variables"].values() if len(v) > 2 and v[2]}
    want = {P.CLOUD_PREFIX + n for n in P.CLOUD_VARIABLES}
    if cloud != want:
        errs.append(f"cloud variables differ: missing={sorted(want - cloud)} extra={sorted(cloud - want)}")
    for t in project["targets"]:
        B = {k: v for k, v in t["blocks"].items() if isinstance(v, dict)}
        names = {}
        for vid, v in list(t["variables"].items()) + list(t["lists"].items()):
            names[vid] = v[0]
        for t2 in project["targets"]:
            if t2["isStage"]:
                for vid, v in list(t2["variables"].items()) + list(t2["lists"].items()):
                    names[vid] = v[0]
        protos = {}
        for i, b in B.items():
            if b["opcode"] == "procedures_prototype":
                protos[b["mutation"]["proccode"]] = b["mutation"]
        for i, b in B.items():
            where = f"{t['name']}:{i}"
            if (b["parent"] is None) != bool(b.get("topLevel")):
                errs.append(f"{where}: topLevel/parent mismatch")
            if b["parent"] is not None and b["parent"] not in B:
                errs.append(f"{where}: missing parent {b['parent']!r}")
            if b.get("topLevel") and ("x" not in b or "y" not in b):
                errs.append(f"{where}: top-level block without x/y")
            n = b["next"]
            if n is not None:
                if n not in B:
                    errs.append(f"{where}: missing next {n!r}")
                elif B[n]["parent"] != i:
                    errs.append(f"{where}: next block {n!r} has parent {B[n]['parent']!r}")
            for key, inp in b["inputs"].items():
                if not isinstance(inp, list) or len(inp) < 2:
                    errs.append(f"{where}: malformed input {key}")
                    continue
                ref = inp[1]
                if isinstance(ref, str):
                    if ref not in B:
                        errs.append(f"{where}: input {key} -> missing block {ref!r}")
                    elif B[ref]["parent"] != i:
                        errs.append(f"{where}: input {key} child {ref!r} has parent {B[ref]['parent']!r}")
                elif isinstance(ref, list) and ref and ref[0] in (12, 13):
                    if names.get(ref[2]) != ref[1]:
                        errs.append(f"{where}: input {key} variable {ref[1]!r} id mismatch")
            for fkey in ("VARIABLE", "LIST"):
                f = b["fields"].get(fkey)
                if f and names.get(f[1]) != f[0]:
                    errs.append(f"{where}: field {fkey} {f[0]!r} id mismatch")
            if b["opcode"] == "procedures_call":
                m = b["mutation"]
                pm = protos.get(m["proccode"])
                if pm is None:
                    errs.append(f"{where}: call to unknown procedure {m['proccode']!r}")
                else:
                    if m["argumentids"] != pm["argumentids"]:
                        errs.append(f"{where}: argument ids differ from prototype of {m['proccode']!r}")
                    if not set(b["inputs"]) <= set(json.loads(pm["argumentids"])):
                        errs.append(f"{where}: unknown argument input for {m['proccode']!r}")
            if b["opcode"] == "procedures_definition":
                cb = b["inputs"].get("custom_block", [None, None])[1]
                if cb not in B or B[cb]["opcode"] != "procedures_prototype" or B[cb]["parent"] != i:
                    errs.append(f"{where}: definition without its prototype")
    return errs


# ------------------------------------------------------------------------------ audit ----
@dataclass
class Finding:
    severity: str     # "critical" | "warning" | "info"
    what: str

    def __str__(self) -> str:
        return f"[{self.severity.upper()}] {self.what}"


@dataclass
class AuditReport:
    findings: list[Finding] = field(default_factory=list)
    public_key: bytes | None = None

    @property
    def ok(self) -> bool:
        return not any(f.severity in ("critical", "warning") for f in self.findings)

    @property
    def critical(self) -> bool:
        return any(f.severity == "critical" for f in self.findings)


def _norm(x) -> str:
    """Compare Scratch values the way a saved project stores them (numbers and numeric strings alike)."""
    try:
        f = float(x)
        return str(int(f)) if f == int(f) else repr(f)
    except (TypeError, ValueError, OverflowError):
        return str(x)


def audit_project(project: dict) -> AuditReport:
    """Is it safe to publish this project? Looks for session keys / plaintext left in a *saved* project.

    Variables and lists are compared with the pristine client; anything that differs is leftover
    state from a run. Also flags any 64-hex-character string (a secret key pasted by mistake).
    """
    rep = AuditReport()
    try:
        sp = _sprite(project)
    except ValueError as e:
        rep.findings.append(Finding("critical", f"cannot audit: {e}"))
        return rep
    try:
        rep.public_key = embedded_public_key(project)
    except (ValueError, KeyError) as e:
        rep.findings.append(Finding("warning", f"no valid embedded public key: {e}"))
    pristine = _sprite(_template())
    base_lists = {v[0]: v[1] for v in pristine["lists"].values()}
    base_vars = {v[0]: v[1] for v in pristine["variables"].values()}

    for lid, (name, values) in sp["lists"].items():
        if name in _CONSTANT_LISTS:
            if name != "SRV" and [_norm(x) for x in values] != [_norm(x) for x in base_lists.get(name, values)]:
                rep.findings.append(Finding("warning", f"constant table {name} was modified"))
            continue
        ref = base_lists.get(name)
        dirty = [_norm(x) for x in values] != [_norm(x) for x in ref] if ref is not None else bool(values)
        if not dirty:
            continue
        if name in _KEY_LISTS:
            rep.findings.append(Finding("critical", f"session key material left in list {name!r}: run '\U0001F512 wipe secrets' before saving"))
        elif name in _MESSAGE_LISTS:
            rep.findings.append(Finding("warning", f"message data left in list {name!r}"))
        else:
            rep.findings.append(Finding("info", f"state left in list {name!r}"))
    for vid, v in sp["variables"].items():
        name, val = v[0], v[1]
        base = base_vars.get(name)
        if base is not None and _norm(val) == _norm(base):
            continue
        if name in _MESSAGE_VARS and str(val) != "":
            rep.findings.append(Finding("warning", f"last received message left in variable {name!r}"))
        elif name in ("SS_SENDCTR", "SS_RECVLAST") and _norm(val) != "0":
            rep.findings.append(Finding("info", f"session counter {name} = {val} (harmless, wiped on next connect)"))
    stage = next(t for t in project["targets"] if t["isStage"])
    for vid, v in stage["variables"].items():
        if len(v) > 2 and v[2] and _norm(v[1]) != "0":
            rep.findings.append(Finding("info", f"cloud variable {v[0]!r} holds old data (public ciphertext)"))
    # a secret key pasted anywhere?
    pub_hex = rep.public_key.hex() if rep.public_key else ""
    text = json.dumps(project, ensure_ascii=False)
    for m in set(_HEX64.findall(text)):
        if m.lower() != pub_hex and m.lower() not in _comment_text(rep.public_key or b"\0" * 32).lower():
            rep.findings.append(Finding("critical", f"a 64-hex-character string ({m[:8]}...) is in the project: is it a secret key?"))
    return rep


# ---------------------------------------------------------------------------- verify ----
@dataclass
class VerifyReport:
    identical: bool = False            # project.json equals a fresh build
    client_unmodified: bool = False    # all blocks equal the v1 client (ignoring the demo script)
    public_key: bytes | None = None
    name: str | None = None
    demo: bool | None = None
    notes: list[str] = field(default_factory=list)
    assets_ok: bool = True

    @property
    def ok(self) -> bool:
        return self.client_unmodified and self.assets_ok


def _blocks_without_demo(sp: dict) -> dict:
    blocks = copy.deepcopy(sp["blocks"])
    for bid, b in list(blocks.items()):
        if isinstance(b, dict) and b["opcode"] == "event_whenflagclicked" and b.get("topLevel") and bid in blocks:
            _remove_script(blocks, bid)
    return blocks


def verify_project(project: dict, assets: dict[str, bytes] | None = None, *, expected_pub: bytes | None = None) -> VerifyReport:
    """Is this the unmodified client of this version? (Scratch code is public; anyone could publish a modified one.)"""
    rep = VerifyReport()
    try:
        sp = _sprite(project)
        rep.public_key = embedded_public_key(project)
    except (ValueError, KeyError) as e:
        rep.notes.append(f"not a ClouDiamond client: {e}")
        return rep
    rep.name = sp["name"][len(SPRITE_PREFIX):] if sp["name"].startswith(SPRITE_PREFIX) else sp["name"]
    rep.demo = any(isinstance(b, dict) and b["opcode"] == "event_whenflagclicked" for b in sp["blocks"].values())
    if expected_pub is not None and expected_pub != rep.public_key:
        rep.notes.append("embedded public key differs from the expected one")
    ref = _sprite(build_project(rep.public_key, name=rep.name, demo=False))
    got, want = _blocks_without_demo(sp), ref["blocks"]
    if got == want:
        rep.client_unmodified = True
    else:
        added, removed = set(got) - set(want), set(want) - set(got)
        changed = [k for k in set(got) & set(want) if got[k] != want[k]]
        rep.notes.append(f"client blocks differ from v{__version__}: {len(changed)} changed, {len(added)} added, {len(removed)} removed")
    for t in project["targets"]:
        if not t["isStage"] and t is not sp and t["blocks"]:
            rep.notes.append(f"extra sprite with blocks: {t['name']!r}")
    # variables/lists (apart from state) must be the same set
    ref_vars = {v[0] for v in ref["variables"].values()}
    if {v[0] for v in sp["variables"].values()} != ref_vars:
        rep.client_unmodified = False
        rep.notes.append("variable set differs from the client")
    fresh = build_project(rep.public_key, name=rep.name, demo=bool(rep.demo))
    rep.identical = _dump(project) == _dump(fresh)
    if assets is not None:
        want_assets = _assets()
        if {k: hashlib.sha256(v).hexdigest() for k, v in assets.items()} != \
                {k: hashlib.sha256(v).hexdigest() for k, v in want_assets.items()}:
            rep.assets_ok = False
            rep.notes.append("asset files differ")
    return rep
