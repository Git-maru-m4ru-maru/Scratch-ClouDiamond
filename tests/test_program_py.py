"""
test_program_py.py -- Scratch に載せるクライアント本体(scratch/program.py)を *Python として* 実行して検証する。

program.py は SPy ソースで、同じファイルが Scratch ブロックにコンパイルされる。ここでは
  ・暗号部品を標準実装(cryptography)および巨大整数の参照実装と照合
  ・実物の SecureServer と相互にハンドシェイク・暗号通信
  ・攻撃シナリオ(偽サーバー / 返信の差し替え / 再送 / 改ざん / 返信フラッド)
を行う。本物の Scratch VM 上での同じ検証は test_program_vm.py。
"""
import importlib.util
import os
import random

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

import cloudiamond_scratch.scratch.program as _program_mod
import cloudiamond_scratch.server as ss
from test_core import _x25519_bigint, _poly1305_bigint

PROGRAM_PATH = _program_mod.__file__


@pytest.fixture
def P():
    """状態が混ざらないよう、テストごとに program.py を新しく読み込む。"""
    spec = importlib.util.spec_from_file_location("program_fresh", PROGRAM_PATH)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def fill(lst, data):
    for i, b in enumerate(data):
        lst[i] = b


def read(lst, n):
    return bytes(lst[:n])


# ============================================================ 暗号部品
def test_tables_match_server_constants(P):
    assert bytes(P.LBL_MASTER) == ss.LABEL_MASTER and bytes(P.LBL_C2S) == ss.LABEL_C2S
    assert bytes(P.LBL_S2C) == ss.LABEL_S2C and bytes(P.READYB) == ss.READY
    assert all(P.XOR4[a * 16 + b] == a ^ b for a in range(16) for b in range(16))
    assert len(P.TXT_CHARS) == len(P.TXT_CODES) == len(set(P.TXT_CHARS))
    assert all(chr(c) == ch for ch, c in zip(P.TXT_CHARS, P.TXT_CODES))
    # Scratch の比較は大文字小文字を区別しない -> 表に大文字が混ざっていてはいけない
    assert all(ch == ch.lower() for ch in P.TXT_CHARS)


def test_xor32_xor8_random(P):
    rnd = random.Random(5)
    for _ in range(300):
        a, b = rnd.getrandbits(32), rnd.getrandbits(32)
        assert P.xor32(a, b) == a ^ b
        a8, b8 = rnd.getrandbits(8), rnd.getrandbits(8)
        assert P.xor8(a8, b8) == a8 ^ b8


def test_x25519_rfc7748_and_random(P):
    a = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
    u = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
    fill(P.XK, a); fill(P.XU, u); P.x25519()
    assert read(P.XOUT, 32).hex() == "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
    for _ in range(3):
        x, y = X25519PrivateKey.generate(), X25519PrivateKey.generate()
        fill(P.XK, x.private_bytes_raw()); P.x25519_base()
        assert read(P.XOUT, 32) == x.public_key().public_bytes_raw()
        fill(P.XU, y.public_key().public_bytes_raw()); P.x25519()
        assert read(P.XOUT, 32) == x.exchange(y.public_key())


def test_x25519_edge_inputs_vs_bigint(P):
    p = 2 ** 255 - 19
    for u in (0, 1, 2, 9, p - 1, p, p + 1, 2 ** 255 - 1, 2 ** 256 - 1, 2 ** 255, (p - 1) // 2):
        for k in (os.urandom(32), bytes(32), b"\xff" * 32):
            ub = u.to_bytes(32, "little")
            fill(P.XK, k); fill(P.XU, ub); P.x25519()
            assert read(P.XOUT, 32) == _x25519_bigint(k, ub), (u, k.hex())


def test_hchacha20_vector(P):
    fill(P.HCK, bytes(range(32)))
    fill(P.HCN, bytes.fromhex("000000090000004a0000000031415927"))
    P.hchacha20()
    assert read(P.HCO, 32).hex() == "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"
    key, nonce = os.urandom(32), os.urandom(16)
    fill(P.HCK, key); fill(P.HCN, nonce); P.hchacha20()
    assert read(P.HCO, 32) == ss.hchacha20(key, nonce)


def test_poly1305_rfc_vector(P):
    key = bytes.fromhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
    msg = b"Cryptographic Forum Research Group"
    fill(P.PKEY, key); fill(P.PMSG, msg); P.PLEN = len(msg); P.poly1305()
    assert read(P.PTAG, 16).hex() == "a8061dc1305136c6c22b8baf0c0127a9"


def test_poly1305_final_reduction_edge_cases(P):
    n = 0
    for r in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 16, 64, 255, 256):
        for k in range(40):
            for nblk in (1, 2, 3):
                key = r.to_bytes(16, "little") + bytes(16)
                blk = ((1 << 128) - 1 - k).to_bytes(16, "little")
                for msg in (blk * nblk, blk * (nblk - 1) + b"\xff" * (1 + k % 15)):
                    fill(P.PKEY, key); fill(P.PMSG, msg); P.PLEN = len(msg); P.poly1305()
                    assert read(P.PTAG, 16) == _poly1305_bigint(key, msg)
                    n += 1
    assert n == 3600


@pytest.mark.parametrize("n,aadn", [(0, 0), (1, 5), (31, 15), (64, 15), (65, 73), (288, 15)])
def test_aead_matches_cryptography(P, n, aadn):
    key, nonce, aad, pt = os.urandom(32), os.urandom(12), os.urandom(aadn), os.urandom(n)
    fill(P.AK, key); fill(P.AN, nonce); fill(P.AAD, aad); P.AADL = aadn
    fill(P.BUF, pt); P.BUFL = n
    P.aead_seal()
    ref = ChaCha20Poly1305(key).encrypt(nonce, pt, aad)
    assert read(P.BUF, n) + read(P.ATAG, 16) == ref
    fill(P.BUF, ref[:n]); P.BUFL = n; fill(P.TAGIN, ref[n:])
    P.aead_open()
    assert P.AOK == 1 and read(P.BUF, n) == pt
    fill(P.BUF, ref[:n]); P.BUFL = n; fill(P.TAGIN, bytes([ref[n] ^ 1]) + ref[n + 1:])
    P.aead_open()
    assert P.AOK == 0


# ============================================================ ハンドシェイク + 暗号通信(実物のサーバーと)
def connect(P, server, pinned_pub=None):
    """クライアントから HELLO を作り、サーバーの返信を検証する。-> (hello, reply)"""
    fill(P.SRV, pinned_pub or server.public_key)
    fill(P.EK, os.urandom(32))
    P.ss_reset_state()
    P.ss_make_hello()
    hello = read(P.TXF, P.TXL)
    out = server.handle_frame(hello)
    assert out is not None
    P.RXL = len(out); fill(P.RXF, out)
    P.ss_derive_and_verify()
    return hello, out


def make_server(**kw):
    """受け取った内容を記録し、同じ長さの逆順を返すサーバー(最大長でも往復できる)。"""
    got = []
    srv = ss.SecureServer(X25519PrivateKey.generate(),
                          on_message=lambda sid, d: (got.append(d), d[::-1])[1], **kw)
    return srv, got


def client_send(P, server, data: bytes):
    P.SS_TX.clear()
    for b in data:
        P.SS_TX.append(b)
    P.ss_seal()
    return read(P.TXF, P.TXL), server.handle_frame(read(P.TXF, P.TXL))


def client_receive(P, frame: bytes):
    P.RXL = len(frame); fill(P.RXF, frame)
    P.ss_open()
    return bytes(P.SS_RX) if P.SS_RXOK == 1 else None


def test_handshake_and_both_directions(P):
    server, got = make_server()
    connect(P, server)
    assert P.SS_READY == 1
    for msg in (b"hello", b"", b"x" * 31, b"\x00\xff" * 70, bytes(range(256)) + b"z" * 30):   # 最後は最大長 286 byte
        frame, replies = client_send(P, server, msg)
        assert got[-1] == msg and len(frame) <= 336
        assert replies is not None
        assert client_receive(P, replies) == msg[::-1]
    pushed = server.send(read(P.SID, 8), b"server-push")
    assert client_receive(P, pushed) == b"server-push"


def test_handshake_secrets_are_cleared_after_success(P):
    server, _ = make_server()
    connect(P, server)
    assert P.SS_READY == 1
    for name in ("EK", "DHES", "DHEE", "MASTER", "XK", "XOUT", "HCK", "HCO"):
        assert not any(getattr(P, name)), name + " still holds secret material"
    assert any(P.KC2S) and any(P.KS2C)                 # 通信用の鍵だけが残る


def test_wipe_clears_everything_secret_but_keeps_server_public_key(P):
    server, _ = make_server()
    connect(P, server)
    client_send(P, server, b"secret message")
    P.SS_TEXT = "secret text"
    P.ss_wipe()
    secret_lists = ("EK", "EP", "RP", "DHES", "DHEE", "MASTER", "KC2S", "KS2C", "HCK", "HCO", "CCK", "PKEY",
                    "AK", "XK", "XU", "XOUT", "ZK", "CCO", "ST", "INI", "HCN", "TAGIN", "ATAG", "PTAG", "GFM",
                    "BUF", "TXF", "RXF", "PMSG", "AN", "AAD", "PR", "PH", "PC", "PX", "PG")
    for name in secret_lists:
        assert not any(getattr(P, name)), name
    assert not any(P.MA) and not any(P.MB) and not any(P.MT)
    assert len(P.SS_TX) == 0 and len(P.SS_RX) == 0 and P.SS_READY == 0 and P.SS_TEXT == ""
    assert read(P.SRV, 32) == server.public_key       # 公開鍵は消さない(消すと接続できなくなる)


def test_eavesdropper_view_has_no_plaintext(P):
    server, _ = make_server()
    hello, reply = connect(P, server)
    frames = [hello, reply]
    secret = b"TOP-SECRET-PASSWORD-1234567890"
    f, replies = client_send(P, server, secret)
    assert replies is not None
    frames.extend([f, replies])
    assert all(b"TOP-SECRET" not in x for x in frames)


def test_replayed_and_tampered_frames_are_rejected_by_server(P):
    server, got = make_server()
    connect(P, server)
    f1, _ = client_send(P, server, b"one")
    assert got == [b"one"]
    assert server.handle_frame(f1) is None             # 再送
    P.SS_TX.clear(); P.SS_TX.append(1); P.ss_seal()
    good = read(P.TXF, P.TXL)
    rnd = random.Random(2)
    for _ in range(40):
        i, bit = rnd.randrange(len(good)), 1 << rnd.randrange(8)
        t = bytearray(good); t[i] ^= bit
        assert server.handle_frame(bytes(t)) is None
    assert got == [b"one"]                             # 改ざんは 1 件も届かない
    assert server.handle_frame(good) is not None and got[-1] == b"\x01"   # 本物は通る(状態が壊れていない)


def test_client_rejects_replayed_tampered_and_reflected_frames(P):
    server, _ = make_server()
    connect(P, server)
    _, r = client_send(P, server, b"ping")
    assert r is not None
    assert client_receive(P, r) == b"gnip"
    assert client_receive(P, r) is None                # 再送
    _, reply2 = client_send(P, server, b"pong")
    assert reply2 is not None
    rnd = random.Random(9)
    for _ in range(30):
        i, bit = rnd.randrange(len(reply2)), 1 << rnd.randrange(8)
        t = bytearray(reply2); t[i] ^= bit
        assert client_receive(P, bytes(t)) is None
    assert client_receive(P, reply2) == b"gnop"           # 本物はまだ通る(状態が壊れていない)
    own, _ = client_send(P, server, b"mine")
    assert client_receive(P, own) is None              # 自分の送信フレームを受信として反射しても通らない


def test_fake_server_with_other_key_is_rejected(P):
    real, _ = make_server()
    fake, _ = make_server()
    connect(P, fake, pinned_pub=real.public_key)
    assert P.SS_READY == 0


def test_mitm_replacing_R_with_static_key_is_rejected(P):
    server, _ = make_server()
    fill(P.SRV, server.public_key); fill(P.EK, os.urandom(32))
    P.ss_reset_state(); P.ss_make_hello()
    initial_reply = server.handle_frame(read(P.TXF, P.TXL))
    assert initial_reply is not None
    reply = bytearray(initial_reply)
    for bad_R in (server.public_key, bytes(32), (1).to_bytes(32, "little")):
        reply[9:41] = bad_R
        P.RXL = len(reply); fill(P.RXF, bytes(reply))
        P.ss_derive_and_verify()
        assert P.SS_READY == 0


def test_attacker_forged_reply_is_rejected(P):
    server, _ = make_server()
    fill(P.SRV, server.public_key); fill(P.EK, os.urandom(32))
    P.ss_reset_state(); P.ss_make_hello()
    E = read(P.EP, 32); sid = read(P.SID, 8)
    r = X25519PrivateKey.generate()
    dh = r.exchange(X25519PublicKey.from_public_bytes(E))
    _master, k_c2s, k_s2c = ss.derive_keys(dh, dh)     # 攻撃者が自分で作れる鍵
    R = r.public_key().public_bytes_raw()
    confirm = ChaCha20Poly1305(k_s2c).encrypt(ss.nonce_for(0), ss.READY, sid + bytes([2]) + E + R)
    forged = sid + bytes([2]) + R + confirm
    P.RXL = len(forged); fill(P.RXF, forged); P.ss_derive_and_verify()
    assert P.SS_READY == 0


def test_reply_flood_is_bounded(P):
    server, _ = make_server()
    fill(P.SRV, server.public_key); fill(P.EK, os.urandom(32))
    P.ss_reset_state(); P.ss_make_hello()
    real = server.handle_frame(read(P.TXF, P.TXL))
    assert real is not None
    fake = bytearray(real); fake[-1] ^= 1
    for _ in range(3):
        P.RXL = 73; fill(P.RXF, bytes(fake)); P.ss_derive_and_verify()
        assert P.SS_READY == 0
    assert P.SS_TRIES == 3          # ss_connect は SS_TRIES < 3 の間しか試さない = 3 回で打ち切る


def test_foreign_session_id_is_ignored(P):
    server, _ = make_server()
    fill(P.SRV, server.public_key); fill(P.EK, os.urandom(32))
    P.ss_reset_state(); P.ss_make_hello()
    initial_reply = server.handle_frame(read(P.TXF, P.TXL))
    assert initial_reply is not None
    reply = bytearray(initial_reply)
    reply[0] ^= 1
    P.RXL = 73; fill(P.RXF, bytes(reply)); P.ss_derive_and_verify()
    assert P.SS_READY == 0 and P.SS_TRIES == 0         # 自分宛てでなければ計算もしない


def test_nothing_is_sent_before_the_server_is_verified(P):
    server, _ = make_server()
    real, _ = make_server()
    connect(P, server, pinned_pub=real.public_key)          # 鍵が違う = 認証失敗
    assert P.SS_READY == 0
    P.ss_send_text("secret")
    assert P.CLOUD_C2S_HDR == 0 and P.CLOUD_C2S_0 == 0     # クラウド変数には何も書かれない
    assert P.TXL == 41 or P.TXL == 0                        # 新しい暗号フレームは作られない(HELLO のまま)


def test_failed_connection_leaves_no_keys_after_wipe(P):
    server, _ = make_server()
    real, _ = make_server()
    connect(P, server, pinned_pub=real.public_key)
    assert any(P.KC2S)                                      # 認証前に導出した鍵が一旦は存在する
    P.ss_wipe()                                             # ss_connect は失敗時にこれを呼ぶ
    assert not any(P.KC2S) and not any(P.KS2C) and not any(P.AK) and not any(P.EK)
    assert read(P.SRV, 32) == real.public_key


def test_reply_with_valid_tag_but_wrong_confirmation_text_is_rejected(P):
    """サーバー鍵を持つ側が、タグは正しいが READY ではない文面を返してきた場合も拒否する(照合は AEAD とは別の確認)。"""
    sk = X25519PrivateKey.generate()
    fill(P.SRV, sk.public_key().public_bytes_raw()); fill(P.EK, os.urandom(32))
    P.ss_reset_state(); P.ss_make_hello()
    E = read(P.EP, 32); sid = read(P.SID, 8)
    r = X25519PrivateKey.generate()
    Ek = X25519PublicKey.from_public_bytes(E)
    _master, k_c2s, k_s2c = ss.derive_keys(sk.exchange(Ek), r.exchange(Ek))
    R = r.public_key().public_bytes_raw()
    aad = sid + bytes([2]) + E + R
    for text in (b"NOT-THE-READY!!!", bytes(16), ss.READY[:15] + b"X"):
        sealed = ChaCha20Poly1305(k_s2c).encrypt(ss.nonce_for(0), text, aad)
        frame = sid + bytes([2]) + R + sealed
        P.RXL = len(frame); fill(P.RXF, frame); P.ss_derive_and_verify()
        assert P.SS_READY == 0, text
    sealed = ChaCha20Poly1305(k_s2c).encrypt(ss.nonce_for(0), ss.READY, aad)   # 正しい文面なら通る(テスト自体の健全性)
    frame = sid + bytes([2]) + R + sealed
    P.SS_TRIES = 0; P.RXL = len(frame); fill(P.RXF, frame); P.ss_derive_and_verify()
    assert P.SS_READY == 1


# ============================================================ クラウド変数の入出力 + テキスト
def test_send_frame_writes_slots_then_header_and_server_decodes(P):
    server, got = make_server()
    connect(P, server)
    msg = os.urandom(200)
    P.SS_TX.clear()
    for b in msg:
        P.SS_TX.append(b)
    P.ss_seal()
    frame = read(P.TXF, P.TXL)
    P.SS_SEQ = 41
    P.ss_send_frame()
    nslots = (len(frame) + 83) // 84
    slots = [str(P.CLOUD_C2S_0), str(P.CLOUD_C2S_1), str(P.CLOUD_C2S_2), str(P.CLOUD_C2S_3)]
    hdr = str(P.CLOUD_C2S_HDR)
    assert hdr == "1%06d%02d" % (42, nslots)
    assert all(len(s) <= 256 and s.isdigit() for s in slots[:nslots])
    seq, back = ss.from_slots(hdr, slots)
    assert seq == 42 and back == frame
    server.handle_frame(back)
    assert got == [msg]


@pytest.mark.parametrize("n", [1, 41, 73, 84, 85, 168, 169, 252, 253, 336])
def test_read_frame_decodes_server_slots(P, n):
    frame = os.urandom(n)
    slots, hdr = ss.to_slots(frame, 7)
    padded = slots + ["0"] * (4 - len(slots))
    P.CLOUD_S2C_HDR = int(hdr)
    P.CLOUD_S2C_0, P.CLOUD_S2C_1, P.CLOUD_S2C_2, P.CLOUD_S2C_3 = padded
    P.ss_read_frame()
    assert P.RXOK == 1 and P.RXL == n and read(P.RXF, n) == frame


@pytest.mark.parametrize("bad", ["", "2123", "1999", "1256", "1abc", "112", "1" + "9" * 300])
def test_read_frame_rejects_malformed_slots(P, bad):
    P.CLOUD_S2C_HDR = 100000101
    P.CLOUD_S2C_0 = bad
    P.ss_read_frame()
    assert P.RXOK == 0 or P.RXL == 0


def test_text_conversion(P):
    P.ss_text_to_tx("hello, world 123!")
    assert bytes(P.SS_TX) == b"hello, world 123!"
    P.ss_text_to_tx("HELLO")                            # 大文字は小文字として扱われる(Scratch の比較の仕様)
    assert bytes(P.SS_TX) == b"hello"
    P.ss_text_to_tx("café")                             # 表に無い文字は '?'
    assert bytes(P.SS_TX) == b"caf?"
    P.ss_text_to_tx("a" * 500)
    assert len(P.SS_TX) == 286
    P.SS_RX.clear()
    for b in b"echo: 42 ok?":
        P.SS_RX.append(b)
    P.ss_rx_to_text()
    assert P.SS_TEXT == "echo: 42 ok?"
    P.SS_RX.clear(); P.SS_RX.append(200); P.SS_RX.append(97)
    P.ss_rx_to_text()
    assert P.SS_TEXT == "?a"
