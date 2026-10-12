"""
selftest.py -- インストール直後に実行できる自己診断(pytest 不要・Node 不要・数秒)。

  1. 暗号部品を、公式テストベクトルと cryptography の出力に照合する
  2. Scratch に載せるクライアント(program.py)を Python として動かし、実物のサーバーとハンドシェイクして往復する
  3. 生成する .sb3 が壊れていない(zip として正しく、プロジェクト JSON の参照が閉じている)ことを調べる

「Scratch の VM 上でも同じ結果になること」は Node と scratch-vm が必要なので tests/ 側(pytest)で検証する。
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import zipfile
from typing import Callable, List, Tuple


def _fresh_program():
    from .scratch import program
    spec = importlib.util.spec_from_file_location("cloudiamond_selftest_program", program.__file__)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _fill(lst, data):
    for i, b in enumerate(data):
        lst[i] = b


def check_x25519_rfc7748() -> None:
    P = _fresh_program()
    a = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
    u = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
    _fill(P.XK, a); _fill(P.XU, u); P.x25519()
    assert bytes(P.XOUT[:32]).hex() == "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"


def check_aead_vs_cryptography() -> None:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    P = _fresh_program()
    key, nonce, aad, pt = os.urandom(32), os.urandom(12), os.urandom(15), os.urandom(100)
    _fill(P.AK, key); _fill(P.AN, nonce); _fill(P.AAD, aad); P.AADL = 15
    _fill(P.BUF, pt); P.BUFL = 100
    P.aead_seal()
    assert bytes(P.BUF[:100]) + bytes(P.ATAG[:16]) == ChaCha20Poly1305(key).encrypt(nonce, pt, aad)


def check_hchacha20_vector() -> None:
    P = _fresh_program()
    _fill(P.HCK, bytes(range(32)))
    _fill(P.HCN, bytes.fromhex("000000090000004a0000000031415927"))
    P.hchacha20()
    assert bytes(P.HCO[:32]).hex() == "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"


def check_roundtrip_with_server() -> None:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from .server import SecureServer
    P = _fresh_program()
    got: List[bytes] = []
    server = SecureServer(X25519PrivateKey.generate(), on_message=lambda sid, d: (got.append(d), d[::-1])[1])
    _fill(P.SRV, server.public_key)
    _fill(P.EK, os.urandom(32))
    P.ss_reset_state(); P.ss_make_hello()
    reply = server.handle_frame(bytes(P.TXF[:P.TXL]))[0]
    P.RXL = len(reply); _fill(P.RXF, reply); P.ss_derive_and_verify()
    assert P.SS_READY == 1, "サーバー認証に失敗"
    P.SS_TX.clear()
    for b in b"selftest":
        P.SS_TX.append(b)
    P.ss_seal()
    out = server.handle_frame(bytes(P.TXF[:P.TXL]))
    assert got == [b"selftest"] and len(out) == 1
    P.RXL = len(out[0]); _fill(P.RXF, out[0]); P.ss_open()
    assert P.SS_RXOK == 1 and bytes(P.SS_RX) == b"tsetfles"


def check_sb3_is_well_formed() -> None:
    from .scratch.build import build_client_sb3
    pub = os.urandom(32)
    data = build_client_sb3(pub)
    z = zipfile.ZipFile(io.BytesIO(data))
    assert z.testzip() is None
    proj = json.loads(z.read("project.json"))
    blocks = proj["targets"][1]["blocks"]
    for bid, b in blocks.items():
        assert b["topLevel"] or b["parent"] in blocks
        for inp in b["inputs"].values():
            for ref in inp[1:]:
                if isinstance(ref, str):
                    assert ref in blocks
    lists = {v[0]: v[1] for v in proj["targets"][1]["lists"].values()}
    assert lists["SRV"] == list(pub)
    # 秘密になり得るリストが出荷物に最初から入っていない
    for name in ("EK", "KC2S", "KS2C", "DHES", "DHEE", "MASTER"):
        assert not any(lists[name]), name


CHECKS: List[Tuple[str, Callable[[], None]]] = [
    ("X25519 (RFC 7748 ベクトル)", check_x25519_rfc7748),
    ("HChaCha20 (公式ベクトル)", check_hchacha20_vector),
    ("ChaCha20-Poly1305 (cryptography と一致)", check_aead_vs_cryptography),
    ("クライアント <-> サーバー ハンドシェイクと往復", check_roundtrip_with_server),
    (".sb3 の整合性", check_sb3_is_well_formed),
]


def run(verbose: bool = True) -> int:
    failed = 0
    for name, fn in CHECKS:
        try:
            fn()
            ok = True
        except Exception as e:                 # 診断なので、何が壊れたかを必ず表示する
            ok = False
            err = "%s: %s" % (type(e).__name__, e)
        if verbose:
            print(("  OK    " if ok else "  FAIL  ") + name + ("" if ok else "\n        " + err))
        failed += 0 if ok else 1
    if verbose:
        print("selftest: %s" % ("すべて合格" if not failed else "%d 件失敗" % failed))
    return 1 if failed else 0
