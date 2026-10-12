"""build.py -- SPy ソース -> .sb3 (zip) を組み立てる。"""
from __future__ import annotations

import hashlib
import json
import zipfile
from io import BytesIO
from typing import Any, Dict, List, Optional

from .spy import Compiler

STAGE_SVG = (b'<svg version="1.1" width="2" height="2" viewBox="-1 -1 2 2" '
             b'xmlns="http://www.w3.org/2000/svg"></svg>')
ICON_SVG = (b'<svg version="1.1" width="64" height="64" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg">'
            b'<polygon points="32,4 60,28 32,60 4,28" fill="#4C97FF" stroke="#3373CC" stroke-width="3" stroke-linejoin="round"/>'
            b'<polygon points="4,28 60,28 32,4" fill="#85B8FF" opacity=".55"/>'
            b'<polyline points="20,28 32,60 44,28" fill="none" stroke="#fff" stroke-width="2" opacity=".6"/></svg>')

# 画面に出すモニター(Python の変数名 -> 位置)。表示名は program.py の Var(..., "表示名") で決まる。
DEFAULT_MONITORS = ("SS_STATUS", "SS_READY", "SS_TEXT")


def _costume(name: str, svg: bytes, cx: float, cy: float):
    md5 = hashlib.md5(svg).hexdigest()
    return md5, {"assetId": md5, "name": name, "md5ext": md5 + ".svg", "dataFormat": "svg",
                 "rotationCenterX": cx, "rotationCenterY": cy}


def build_project_json(comp: Compiler, sprite_name: str = "Cloudiamond",
                       monitors: tuple = DEFAULT_MONITORS) -> Dict[str, Any]:
    comp.compile_all()
    _m, stage_cos = _costume("backdrop1", STAGE_SVG, 1, 1)
    _m, icon_cos = _costume("diamond", ICON_SVG, 32, 32)
    stage = {
        "isStage": True, "name": "Stage",
        "variables": {cid: [name, 0, True] for name, cid in comp.cloud.items()},
        "lists": {}, "broadcasts": {}, "blocks": {}, "comments": {},
        "currentCostume": 0, "costumes": [stage_cos], "sounds": [], "volume": 100, "layerOrder": 0,
        "tempo": 60, "videoTransparency": 50, "videoState": "on", "textToSpeechLanguage": None,
    }
    sprite = {
        "isStage": False, "name": sprite_name,
        "variables": {vid: [name, comp.var_init.get(name, 0)] for name, vid in comp.vars.items()},
        "lists": {lid: [display, items] for _n, (lid, items, display) in comp.lists.items()},
        "broadcasts": {}, "blocks": comp.blocks, "comments": {},
        "currentCostume": 0, "costumes": [icon_cos], "sounds": [], "volume": 100, "layerOrder": 1,
        "visible": True, "x": 0, "y": 0, "size": 100, "direction": 90, "draggable": False,
        "rotationStyle": "all around",
    }
    mons = []
    for k, pyname in enumerate(monitors):
        display = comp.gvars.get(pyname)
        if not isinstance(display, str):
            continue
        mons.append({"id": comp.vars[display], "mode": "default", "opcode": "data_variable",
                     "params": {"VARIABLE": display}, "spriteName": sprite_name,
                     "value": comp.var_init.get(display, 0), "width": 0, "height": 0,
                     "x": 5, "y": 5 + 27 * k, "visible": True, "sliderMin": 0, "sliderMax": 100, "isDiscrete": True})
    return {"targets": [stage, sprite], "monitors": mons, "extensions": [],
            "meta": {"semver": "3.0.0", "vm": "0.2.0", "agent": "cloudiamond_scratch"}}


def build_sb3(source: str, *, list_overrides: Optional[Dict[str, List[Any]]] = None,
              const_overrides: Optional[Dict[str, Any]] = None, sprite_name: str = "Cloudiamond",
              monitors: tuple = DEFAULT_MONITORS):
    """-> (sb3 の bytes, Compiler)。"""
    comp = Compiler(source, list_overrides=list_overrides, const_overrides=const_overrides)
    proj = build_project_json(comp, sprite_name, monitors)
    buf = BytesIO()
    # 時刻やファイル順をバイトに混ぜない = 同じ入力から必ず同じ .sb3 ができる。
    # 配布された .sb3 を、公開鍵とこのパッケージから再生成して sha256 を突き合わせて検証できる。
    with zipfile.ZipFile(buf, "w") as z:
        entries = [("project.json", json.dumps(proj, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))]
        entries += sorted((hashlib.md5(svg).hexdigest() + ".svg", svg) for svg in (STAGE_SVG, ICON_SVG))
        for name, payload in entries:
            info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            z.writestr(info, payload, compresslevel=9)
    return buf.getvalue(), comp


def program_source() -> str:
    """Scratch に載せるクライアント本体(program.py)のソース。"""
    from . import program
    with open(program.__file__, encoding="utf-8") as f:
        return f.read()


def build_client_sb3(server_pub: bytes, sprite_name: str = "Cloudiamond") -> bytes:
    """サーバーの *公開鍵* を埋め込んだ Scratch クライアント(.sb3)を返す。秘密鍵は受け取らない。"""
    if len(server_pub) != 32:
        raise ValueError("server_pub must be 32 bytes")
    if not any(server_pub):
        raise ValueError("server_pub must not be all zero")
    data, _ = build_sb3(program_source(), list_overrides={"SRV": list(server_pub)}, sprite_name=sprite_name)
    return data
