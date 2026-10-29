"""
test_package.py -- パッケージとして出荷するもの(CLI・.sb3 の生成・クラウド橋渡し)の検証。

特に重要なのは「出荷物に秘密が入らないこと」と「同じ入力から同じ .sb3 ができること」。
"""
import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import zipfile

import pytest
import cloudiamond_scratch.protocol as P
import cloudiamond_scratch.server as ss
from cloudiamond_scratch.keys import parse_secret, public_key
from cloudiamond_scratch import cli
from cloudiamond_scratch.bridge import CloudBridge, short_name
from cloudiamond_scratch.protocol import (
    CLOUD_VARIABLES,
    VAR_C2S_HDR as C2S_HDR,
    VAR_C2S as C2S_SLOTS,
    VAR_S2C_HDR as S2C_HDR,
    VAR_S2C as S2C_SLOTS,
)
from cloudiamond_scratch.reference import client as cr
from cloudiamond_scratch.scratch.build import build_client_sb3


# ============================================================ CLI
def run_cli(*args):
    return cli.main(list(args))


def test_keygen_creates_private_key_with_0600_and_is_idempotent(tmp_path, capsys):
    key = tmp_path / "server.key"
    assert run_cli("keygen", str(key)) == 0
    out1 = capsys.readouterr().out
    assert stat.S_IMODE(os.stat(key).st_mode) == 0o600
    file_bytes = key.read_bytes()
    raw = parse_secret(file_bytes)
    assert len(raw) == 32
    pub = public_key(raw)
    assert pub.hex() in out1 and raw.hex() not in out1       # 画面に秘密鍵を出さない
    assert run_cli("keygen", str(key)) != 0                  # 既存の鍵は上書きしない
    assert key.read_bytes() == file_bytes
    assert run_cli("pubkey", "--key", str(key)) == 0 and pub.hex() in capsys.readouterr().out


def test_pubkey_and_build_require_existing_key(tmp_path):
    assert run_cli("pubkey", "--key", str(tmp_path / "missing.key")) != 0
    assert run_cli("build", "--key", str(tmp_path / "missing.key"), "-o", str(tmp_path / "x.sb3")) != 0
    assert not (tmp_path / "missing.key").exists()           # build が勝手に鍵を作ってしまわない
    assert not (tmp_path / "x.sb3").exists()


@pytest.mark.parametrize("bad", ["zz", "00" * 31, "00" * 33, "00" * 32, ""])
def test_build_rejects_bad_public_keys(tmp_path, bad):
    assert run_cli("build", "--pub", bad, "-o", str(tmp_path / "x.sb3")) != 0
    assert not (tmp_path / "x.sb3").exists()


def test_build_key_and_pub_are_mutually_exclusive(tmp_path):
    with pytest.raises(SystemExit):
        run_cli("build", "--key", "a", "--pub", "00" * 32)


def test_built_sb3_embeds_only_the_public_key_and_never_the_private_key(tmp_path):
    key = tmp_path / "server.key"
    run_cli("keygen", str(key))
    key_file_bytes = key.read_bytes()
    priv = parse_secret(key_file_bytes)
    pub = public_key(priv)
    out = tmp_path / "client.sb3"
    assert run_cli("build", "--key", str(key), "-o", str(out)) == 0
    z = zipfile.ZipFile(out)
    blob = b"".join(z.read(n) for n in z.namelist())
    text = blob.decode("utf-8", "ignore")
    # 秘密鍵が、生バイト・16 進・10 進リスト・数字列のどの形でも入っていない
    assert priv not in blob and priv.hex() not in text
    assert json.dumps(list(priv)) not in text and ",".join(map(str, priv)) not in text
    assert P.encode_slot(priv) not in text
    # 公開鍵は SRV リストに入っている
    proj = json.loads(z.read("project.json"))
    sprite = next(target for target in proj["targets"] if not target["isStage"] and target["blocks"])
    lists = {v[0]: v[1] for v in sprite["lists"].values()}
    assert lists["SRV"] == list(pub)
    # --pub でも同じ .sb3 が得られる
    out2 = tmp_path / "client2.sb3"
    run_cli("build", "--pub", pub.hex(), "-o", str(out2))
    assert out.read_bytes() == out2.read_bytes()


def test_build_is_deterministic_and_reproducible():
    pub = bytes(range(1, 33))
    a, b = build_client_sb3(pub), build_client_sb3(pub)
    assert a == b and hashlib.sha256(a).hexdigest() == hashlib.sha256(b).hexdigest()
    assert build_client_sb3(bytes(range(2, 34))) != a       # 公開鍵が違えば別物


def test_sb3_ships_with_no_secret_state_and_expected_cloud_variables():
    data = build_client_sb3(os.urandom(32))
    proj = json.loads(zipfile.ZipFile(io.BytesIO(data)).read("project.json"))
    stage, sprite = proj["targets"]
    lists = {v[0]: v[1] for v in sprite["lists"].values()}
    for name in ("EK", "EP", "RP", "DHES", "DHEE", "MASTER", "KC2S", "KS2C", "HCK", "HCO", "CCK", "PKEY",
                 "AK", "XK", "XU", "XOUT", "ZK", "BUF", "TXF", "RXF", "PMSG", "GFM"):
        assert not any(lists[name]), name
    assert lists["🔒 TX bytes"] == [] and lists["🔒 RX bytes"] == []
    cloud = [v for v in stage["variables"].values()]
    assert sorted(short_name(v[0]) for v in cloud) == sorted(CLOUD_VARIABLES) and all(v[2] is True for v in cloud)
    assert len(cloud) == 10                                  # Scratch の上限ちょうど
    vars_ = {v[0]: v[1] for v in sprite["variables"].values()}
    assert vars_["🔒 connected"] == 0 and vars_["🔒 received text"] == ""


def test_build_client_rejects_bad_key_sizes():
    for bad in (b"", bytes(31), bytes(33), bytes(32)):
        with pytest.raises(ValueError):
            build_client_sb3(bad)


def test_selftest_passes():
    from cloudiamond_scratch import selftest
    assert selftest.run(verbose=False) == 0


def test_module_entry_point_runs():
    r = subprocess.run([sys.executable, "-m", "cloudiamond_scratch", "--version"], capture_output=True, text=True)
    assert r.returncode == 0 and "cloudiamond-scratch" in r.stdout


# ============================================================ CloudBridge
class Wire:
    """クラウド変数の代わりに、書き込みを順番に記録する。"""

    def __init__(self):
        self.writes = []

    def __call__(self, name, value):
        self.writes.append((name, value))

    def last_frame(self):
        hdr = [v for name, v in self.writes if short_name(name) == S2C_HDR][-1]
        n = int(hdr[-2:])
        cur = {}
        for name, value in self.writes:                 # 最後の HDR の直前までに書かれた slot を使う
            cur[short_name(name)] = value
        return from_slots(hdr, [cur[S2C_SLOTS[i]] for i in range(n)])


def to_slots(frame, seq):
    slots = P.frame_to_slots(frame)
    return slots, P.make_hdr(seq, len(slots))


def from_slots(hdr, slots):
    parsed = P.parse_hdr(hdr)
    assert parsed is not None
    seq, count = parsed
    frame = P.slots_to_frame(slots[:count])
    assert frame is not None
    return seq, frame


def feed(bridge, frame, seq):
    slots, hdr = to_slots(frame, seq)
    for i, s in enumerate(slots):
        bridge.on_variable(C2S_SLOTS[i], s)
    bridge.on_variable(C2S_HDR, hdr)


def new_bridge(**kw):
    got = []
    server = ss.SecureServer(os.urandom(32), on_message=lambda sid, d: (got.append(d), d[::-1])[1], **kw)
    wire = Wire()
    return CloudBridge(server, wire), server, wire, got


def test_bridge_full_session_through_cloud_variable_encoding():
    bridge, server, wire, got = new_bridge()
    client = cr.ScratchClient(list(server.public_key), list(os.urandom(32)))
    feed(bridge, bytes(client.hello()), 1)
    _seq, reply = wire.last_frame()
    assert client.on_reply(list(reply))
    feed(bridge, bytes(client.seal(list(b"over the cloud"))), 2)
    assert got == [b"over the cloud"]
    _seq, data = wire.last_frame()
    assert bytes(client.open(list(data))) == b"over the cloud"[::-1]
    # 書き込み順: 返信ごとに「slot をすべて書いてから、HDR を最後に書く」(HDR の変化 = コミット)
    groups, cur = [], []
    for name, value in wire.writes:
        cur.append((name, value))
        if short_name(name) == S2C_HDR:
            groups.append(cur)
            cur = []
    assert cur == [] and len(groups) == 2                  # 最後の HDR の後に書き込みが残っていない
    for g in groups:
        *slots, (hname, hval) = g
        assert short_name(hname) == S2C_HDR and [short_name(n) for n, _ in slots] == list(S2C_SLOTS[:int(hval[-2:])])


def test_bridge_header_always_changes_even_across_sessions():
    bridge, server, wire, _ = new_bridge()
    hdrs = []
    for seq in range(1, 6):
        client = cr.ScratchClient(list(server.public_key), list(os.urandom(32)))
        feed(bridge, bytes(client.hello()), seq)
        hdrs.append([v for n, v in wire.writes if short_name(n) == S2C_HDR][-1])
    assert len(set(hdrs)) == 5                                  # 新しいセッションの最初の返信でも HDR は前回と違う
    b2 = CloudBridge(server, Wire())
    b2.core._seq = 999_999
    h1 = b2.core._writes(b"x" * 41)[-1][1]
    h2 = b2.core._writes(b"y" * 41)[-1][1]
    assert h1 != h2                                                # 上限で巡回しても連続して同じ値にならない


def test_bridge_ignores_unrelated_garbage_and_duplicates():
    bridge, server, wire, got = new_bridge()
    client = cr.ScratchClient(list(server.public_key), list(os.urandom(32)))
    bridge.on_variable("☁ something_else", "123")
    bridge.on_variable(S2C_HDR, "100000101")                    # 自分が書く側の変数は読まない
    for bad in ("", "x", "1", "100000101", "1999999ab", "100000199", "1000001000"):
        bridge.on_variable(C2S_HDR, bad)                        # 壊れた HDR で例外を出さない
    assert wire.writes == []
    hello = bytes(client.hello())
    feed(bridge, hello, 2)
    prior_reply = wire.last_frame()[1]
    n = len(wire.writes)
    bridge.on_variable(C2S_HDR, to_slots(hello, 2)[1])    # 同じ HELLO の再送
    assert len(wire.writes) > n
    assert wire.last_frame()[1] == prior_reply             # cached reply is replayed unchanged
    assert server.stats["hello_retransmit"] == 1
    client.on_reply(list(wire.last_frame()[1]))
    for junk in (os.urandom(80), os.urandom(200)):
        feed(bridge, junk, 7)
    assert got == [] and len(server.sessions) == 1


def test_bridge_push_from_server():
    bridge, server, wire, _ = new_bridge()
    client = cr.ScratchClient(list(server.public_key), list(os.urandom(32)))
    feed(bridge, bytes(client.hello()), 1)
    assert client.on_reply(list(wire.last_frame()[1]))
    assert bridge.push(bytes(client.sid), b"hello from server") is None
    assert bytes(client.open(list(wire.last_frame()[1]))) == b"hello from server"
    with pytest.raises(ss.UnknownSession):
        bridge.push(b"\0" * 8, b"nobody")                       # 存在しないセッション
    with pytest.raises(ss.MessageTooLarge):
        bridge.push(bytes(client.sid), b"x" * 400)               # スロットに入らない長さ
