"""
test_program_vm.py -- 生成した Scratch プロジェクトを「本物の Scratch VM(scratch-vm)」で実行して検証する。

ここで通れば、Scratch のブロックとして実際に動いている(Python の見かけ上の正しさではない)ことの証拠になる。
  1. 暗号部品: 公式テストベクトル・標準実装の出力と VM 上の結果が一致する(所要時間も記録)
  2. 通しの E2E: VM 上のクライアント <-> 実物の SecureServer を、クラウド変数の挙動そのままで接続し、
     乱数収集 -> 鍵交換 -> サーバー認証 -> 暗号化メッセージの往復までを行う

Node.js と scratch-vm(環境変数 CLOUDIAMOND_SCRATCH_VM = node_modules のパス)が無ければ skip される。
遅いテストは `-m "not slow"` で除外できる。
"""
import json
import os
import queue
import subprocess
import tempfile
import threading
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

import vm
import cloudiamond_scratch.scratch.program as _program_mod
import cloudiamond_scratch.server as ss
from cloudiamond_scratch.bridge import CloudBridge
from cloudiamond_scratch.scratch.build import build_sb3
from test_core import _x25519_bigint, _poly1305_bigint

pytestmark = pytest.mark.skipif(not vm.vm_available(), reason="Node.js と scratch-vm が必要(CLOUDIAMOND_SCRATCH_VM)")

_SRC = open(_program_mod.__file__, encoding="utf-8").read()
_MAIN_MARK = "@when_flag\ndef main():"
LIB_SRC = _SRC[:_SRC.index(_MAIN_MARK)]          # デモの main を除いたライブラリ部分
TIMINGS = {}


def num(x):
    return int(float(x))


def run_driver(driver: str, lists: dict, timeout=300):
    """ライブラリ + driver を .sb3 にして VM で実行する。-> (VM の結果, driver 内で記録した秒数のリスト)"""
    src = LIB_SRC + "\ndone = Var(0)\nTIMES = Lst(8)\n" + driver
    data, _ = build_sb3(src, list_overrides=lists)
    r = vm.run_project(data, timeout=timeout)
    assert not r["timedOut"], "VM がタイムアウト: %s" % json.dumps({k: v for k, v in r["vars"].items() if "." not in k})[:400]
    return r, [float(t) for t in r["lists"]["TIMES"]]


def out(r, name, n):
    return bytes(num(x) for x in r["lists"][name][:n])


def test_scratch_comparison_semantics_match_python_model():
    """Python 実行側のモデル(spyrt)が Scratch の比較・文字処理と一致していることを VM で確かめる。"""
    r, _ = run_driver("""
OUT = Lst(8)

@when_flag
def drv():
    global done
    OUT[0] = xor32(4023233417, 2654435769)
    OUT[1] = xor8(202, 85)
    OUT[2] = list_index_of(TXT_CHARS, "h")
    OUT[3] = list_index_of(TXT_CHARS, "H")
    OUT[4] = list_index_of(TXT_CHARS, " ")
    OUT[5] = list_index_of(TXT_CHARS, "7")
    OUT[6] = list_index_of(TXT_CHARS, "é")
    OUT[7] = letter_of(1, "1abc") * 100 + letter_of(2, "1abc") * 10 + 5
    done = 1
""", {})
    got = [num(x) for x in r["lists"]["OUT"]]
    chars = _program_mod.TXT_CHARS
    assert got[0] == 4023233417 ^ 2654435769 and got[1] == 202 ^ 85
    assert got[2] == chars.index("h") + 1
    assert got[3] == chars.index("h") + 1          # Scratch は大文字小文字を区別しない
    assert got[4] == chars.index(" ") + 1          # 空白は数 0 とは見なされない
    assert got[5] == chars.index("7") + 1
    assert got[6] == 0
    assert got[7] == 105                           # "a" * 10 は 0(= Scratch の黙った 0 化。parse_slot が明示検査する理由)


def test_hchacha20_vector_in_vm():
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a0000000031415927")
    r, t = run_driver("""
@when_flag
def drv():
    global done
    reset_timer()
    hchacha20()
    TIMES[0] = timer()
    done = 1
""", {"HCK": list(key), "HCN": list(nonce)})
    assert out(r, "HCO", 32).hex() == "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"
    TIMINGS["HChaCha20"] = t[0]


def test_aead_in_vm_matches_cryptography():
    key, nonce = bytes(range(32)), bytes(range(100, 112))
    aad = bytes(range(15))
    pt = bytes((i * 7 + 3) % 256 for i in range(100))
    ref = ChaCha20Poly1305(key).encrypt(nonce, pt, aad)
    r, t = run_driver("""
@when_flag
def drv():
    global done, AADL, BUFL
    AADL = 15
    BUFL = 100
    reset_timer()
    aead_seal()
    TIMES[0] = timer()
    done = 1
""", {"AK": list(key), "AN": list(nonce), "AAD": list(aad), "BUF": list(pt)})
    assert out(r, "BUF", 100) + out(r, "ATAG", 16) == ref
    TIMINGS["AEAD seal 100 B"] = t[0]
    # 復号: 正しいタグなら平文に戻り、1 bit 違えば拒否される
    for tag, ok in ((ref[100:], 1), (bytes([ref[100] ^ 1]) + ref[101:], 0)):
        r, _ = run_driver("""
@when_flag
def drv():
    global done, AADL, BUFL
    AADL = 15
    BUFL = 100
    aead_open()
    done = 1
""", {"AK": list(key), "AN": list(nonce), "AAD": list(aad), "BUF": list(ref[:100]), "TAGIN": list(tag)})
        assert num(r["vars"]["AOK"]) == ok
        if ok:
            assert out(r, "BUF", 100) == pt
        else:
            assert out(r, "BUF", 100) == ref[:100]      # 検証に失敗したら復号しない


def test_poly1305_edge_cases_in_vm():
    cases = []
    for r_, k in ((1, 0), (4, 0), (4, 7), (255, 3), (16, 11), (256, 20)):
        key = r_.to_bytes(16, "little") + bytes(16)
        blk = ((1 << 128) - 1 - k).to_bytes(16, "little")
        cases.append((key, blk * 2))
        cases.append((key, blk + b"\xff" * (1 + k % 15)))
    cases.append((bytes.fromhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"),
                  b"Cryptographic Forum Research Group"))
    for key, msg in cases:
        r, _ = run_driver("""
@when_flag
def drv():
    global done, PLEN
    PLEN = %d
    poly1305()
    done = 1
""" % len(msg), {"PKEY": list(key), "PMSG": list(msg) + [0] * (400 - len(msg))})
        assert out(r, "PTAG", 16) == _poly1305_bigint(key, msg), (key.hex(), msg.hex())


@pytest.mark.slow
def test_x25519_in_vm():
    """RFC 7748 のテストベクトル + 乱数 + 端の入力(巨大整数の参照実装と照合)。所要時間も記録する。"""
    a = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
    u = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
    r, t = run_driver("""
@when_flag
def drv():
    global done
    reset_timer()
    x25519()
    TIMES[0] = timer()
    done = 1
""", {"XK": list(a), "XU": list(u)}, timeout=600)
    assert out(r, "XOUT", 32).hex() == "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
    TIMINGS["X25519"] = t[0]
    p = 2 ** 255 - 19
    for k, uu in ((os.urandom(32), os.urandom(32)), (b"\xff" * 32, (p - 1).to_bytes(32, "little")),
                  (os.urandom(32), (2 ** 256 - 1).to_bytes(32, "little"))):
        r, _ = run_driver("""
@when_flag
def drv():
    global done
    x25519()
    done = 1
""", {"XK": list(k), "XU": list(uu)}, timeout=600)
        assert out(r, "XOUT", 32) == _x25519_bigint(k, uu)
    # 公開鍵の生成も X25519
    sk = X25519PrivateKey.generate()
    r, _ = run_driver("""
@when_flag
def drv():
    global done
    x25519_base()
    done = 1
""", {"XK": list(sk.private_bytes_raw())}, timeout=600)
    assert out(r, "XOUT", 32) == sk.public_key().public_bytes_raw()


# ============================================================ 通しの E2E(VM 上のクライアント <-> 実物のサーバー)
class CloudRelay:
    """VM の bridge モードと SecureServer を、パッケージの CloudBridge 経由でつなぐ(クラウド変数と同じ挙動)。"""

    def __init__(self, server, sb3_bytes, timeout):
        self.server, self.said, self.asked = server, [], []
        self.q = queue.Queue()
        self.frames_in, self.frames_out = [], []
        orig = server.handle_frame

        def tap(frame):                          # 盗聴者視点の記録: クラウド変数に流れた全フレーム
            self.frames_in.append(frame)
            replies = orig(frame)
            self.frames_out.extend(replies)
            return replies
        server.handle_frame = tap
        self.bridge = CloudBridge(server, lambda name, value: self.send({"t": "set", "name": name, "value": value}),
                                  seq_start=5000)
        d = tempfile.mkdtemp()
        self.path = os.path.join(d, "p.sb3")
        with open(self.path, "wb") as f:
            f.write(sb3_bytes)
        self.p = subprocess.Popen(["node", vm.HARNESS, "bridge", self.path, str(timeout)], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, text=True, bufsize=1, env=vm.env())
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in self.p.stdout:
            try:
                self.q.put(json.loads(line))
            except ValueError:
                pass
        self.q.put({"t": "eof"})

    def send(self, obj):
        self.p.stdin.write(json.dumps(obj) + "\n")
        self.p.stdin.flush()

    def run(self, answers, until, timeout):
        """answers: ask が来るたびに順に返す回答。until(said) が真になるまで動かす。"""
        deadline = time.time() + timeout
        answers = list(answers)
        while time.time() < deadline:
            try:
                m = self.q.get(timeout=1)
            except queue.Empty:
                continue
            if m["t"] == "cloud":
                self.bridge.on_variable(m["name"], m["value"])
            elif m["t"] == "say":
                self.said.append(m["text"])
            elif m["t"] == "ask":
                self.asked.append(m["text"])
                if answers:
                    self.send({"t": "answer", "text": answers.pop(0)})
            elif m["t"] in ("timeout", "eof"):
                break
            if until(self.said):
                return True
        return False

    def dump(self):
        self.send({"t": "dump"})
        end = time.time() + 20
        while time.time() < end:
            try:
                m = self.q.get(timeout=1)
            except queue.Empty:
                continue
            if m["t"] == "dump":
                return m
        raise RuntimeError("no dump")

    def close(self):
        try:
            self.send({"t": "quit"})
        except Exception:
            pass
        self.p.kill()


@pytest.mark.slow
def test_end_to_end_handshake_and_messages_in_real_scratch_vm():
    got = []
    server = ss.SecureServer(X25519PrivateKey.generate(), on_message=lambda sid, d: (got.append(d), d[::-1])[1])
    data, comp = build_sb3(_SRC, list_overrides={"SRV": list(server.public_key)})
    relay = CloudRelay(server, data, timeout=900)
    t0 = time.time()
    try:
        ok = relay.run(["hello, world 123!", "second message: 42"],
                       until=lambda said: sum(1 for s in said if s in ("!321 dlrow ,olleh", "24 :egassem dnoces")) >= 2,
                       timeout=880)
        elapsed = time.time() - t0
        assert ok, "E2E が完了しなかった: said=%r asked=%r" % (relay.said, relay.asked)
        TIMINGS["E2E connect + 2 messages"] = elapsed
        assert got == [b"hello, world 123!", b"second message: 42"]
        assert "connected (server verified)" in relay.said
        # 盗聴者視点: クラウド変数に流れた全フレームに平文が含まれない
        wire = b"".join(relay.frames_in + relay.frames_out)
        assert b"hello" not in wire and b"world" not in wire and b"second" not in wire
        # 暗号化されたメッセージは長さが 32 の倍数に揃っている
        assert all((len(f) - 31) % 32 == 0 for f in relay.frames_in[1:])
        # 通信が終わった後も、VM 内に鍵素材(e / DH 結果 / master)が残っていない
        d = relay.dump()
        for name in ("EK", "DHES", "DHEE", "MASTER", "XK", "XOUT"):
            assert not any(num(x) for x in d["lists"][name]), name + " に秘密が残っている"
        assert any(num(x) for x in d["lists"]["KC2S"]) and num(d["vars"]["🔒 connected"]) == 1
        assert [num(x) for x in d["lists"]["SRV"]] == list(server.public_key)
    finally:
        relay.close()


@pytest.mark.slow
def test_end_to_end_wrong_server_key_is_refused_in_real_scratch_vm():
    server = ss.SecureServer(X25519PrivateKey.generate(), on_message=lambda sid, d: d)
    wrong = X25519PrivateKey.generate().public_key().public_bytes_raw()        # クライアントが信じている鍵
    data, _ = build_sb3(_SRC, list_overrides={"SRV": list(wrong)})
    relay = CloudRelay(server, data, timeout=900)
    try:
        ok = relay.run([], until=lambda said: any(s.startswith("FAILED") for s in said), timeout=880)
        assert ok, "失敗が報告されなかった: %r" % relay.said
        assert "connected (server verified)" not in relay.said
        d = relay.dump()
        assert num(d["vars"]["🔒 connected"]) == 0
        assert not any(num(x) for x in d["lists"]["KC2S"]) and not any(num(x) for x in d["lists"]["EK"])
    finally:
        relay.close()


def test_zz_report_timings():
    """実測値を表示する(`-s` 付きで実行)。Scratch の実際の速度の目安になる。"""
    if TIMINGS:
        print("\n== scratch-vm (Node, interpreter) measured ==")
        for k, v in TIMINGS.items():
            print("  %-28s %8.3f s" % (k, v))
