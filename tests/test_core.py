"""
test_core.py -- 検証スイート   実行: python -m pytest -q tests/test_core.py

1) 暗号部品: RFC 7748 / RFC 8439 のテストベクトル + 独立実装(cryptography, PyCryptodome)との照合
2) 相互運用: 「Scratch 制約版クライアント」 <-> 「本番ライブラリのサーバー」
3) 攻撃シナリオ: 盗聴 / 改ざん / 再送 / 中間者(R 差し替え) / 偽サーバー / 小さい位数の点 / 前方秘匿性
4) Scratch 制約の監査: 全演算が 2^53 未満・ビット演算ゼロ
(最後のテストは use_checked() で定数表を差し替えるため、ファイルの末尾に置いてある)
"""
import os
import random
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from cloudiamond_scratch.reference import client as cr
from cloudiamond_scratch.reference import prims as sp
import cloudiamond_scratch.server as ss

L = list


# ============================================================ 1) 暗号部品
def test_poly1305_rfc8439_2_5_2():
    key = bytes.fromhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
    tag = sp.poly1305(L(key), L(b"Cryptographic Forum Research Group"))
    assert bytes(tag).hex() == "a8061dc1305136c6c22b8baf0c0127a9"


@pytest.mark.parametrize("n", [0, 1, 15, 16, 17, 63, 64, 65, 200])
def test_poly1305_random_lengths_vs_aead(n):
    # 独立実装の AEAD と全長で一致する = Poly1305 の境界処理も正しい
    k, nn, aad, pt = os.urandom(32), os.urandom(12), os.urandom(n % 29), os.urandom(n)
    assert bytes(sp.aead_seal(L(k), L(nn), L(aad), L(pt))) == ChaCha20Poly1305(k).encrypt(nn, pt, aad)


def test_chacha20_vs_cryptography():
    for n in (1, 63, 64, 65, 130):
        k, nn, data = os.urandom(32), os.urandom(12), os.urandom(n)
        ref = Cipher(algorithms.ChaCha20(k, (1).to_bytes(4, "little") + nn), mode=None).encryptor().update(data)
        assert bytes(sp.chacha20_xor(L(k), 1, L(nn), L(data))) == ref


def test_hchacha20_draft_vector_and_independent_impl():
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a0000000031415927")
    want = "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"   # draft-irtf-cfrg-xchacha 2.2.1
    assert bytes(sp.hchacha20(L(key), L(nonce))).hex() == want
    assert ss.hchacha20(key, nonce).hex() == want
    try:                                    # 独立実装(PyCryptodome の XChaCha20)でも照合
        from Crypto.Cipher import ChaCha20 as C
    except ImportError:
        return
    k, n24, data = os.urandom(32), os.urandom(24), os.urandom(100)
    ref = C.new(key=k, nonce=n24).encrypt(data)
    sub = ss.hchacha20(k, n24[:16])
    mine = Cipher(algorithms.ChaCha20(sub, (0).to_bytes(4, "little") + b"\0" * 4 + n24[16:]), mode=None) \
        .encryptor().update(data)
    assert mine == ref


def test_x25519_rfc7748_vectors():
    cases = [
        ("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
         "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
         "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
        ("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
         "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
         "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"),
    ]
    for a, u, want in cases:
        assert bytes(sp.x25519(L(bytes.fromhex(a)), L(bytes.fromhex(u)))).hex() == want


def test_x25519_random_vs_cryptography():
    for _ in range(25):
        a, b = X25519PrivateKey.generate(), X25519PrivateKey.generate()
        raw = a.private_bytes_raw()
        pub_b = b.public_key().public_bytes_raw()
        assert bytes(sp.x25519_base(L(raw))) == a.public_key().public_bytes_raw()
        assert bytes(sp.x25519(L(raw), L(pub_b))) == a.exchange(b.public_key())


# ---- 境界値: 通常のランダム入力では踏まない「最終還元」の分岐を、巨大整数の参照実装と照合して通す
_P1305 = (1 << 130) - 5


def _poly1305_bigint(key, msg):
    r = int.from_bytes(key[:16], "little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
    acc = 0
    for i in range(0, len(msg), 16):
        acc = (acc + int.from_bytes(msg[i:i + 16] + b"\x01", "little")) * r % _P1305
    return ((acc + int.from_bytes(key[16:], "little")) % (1 << 128)).to_bytes(16, "little")


def test_poly1305_final_reduction_edge_cases():
    n = 0
    for r in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 16, 64, 255, 256):
        for k in range(40):
            for nblk in (1, 2, 3):
                key = r.to_bytes(16, "little") + bytes(16)
                blk = ((1 << 128) - 1 - k).to_bytes(16, "little")
                for msg in (blk * nblk, blk * (nblk - 1) + b"\xff" * (1 + k % 15)):
                    assert bytes(sp.poly1305(L(key), L(msg))) == _poly1305_bigint(key, msg)
                    n += 1
    assert n == 3600


def _x25519_bigint(k_bytes, u_bytes):                      # RFC 7748 section 5 の疑似コードそのまま
    p, a24 = 2 ** 255 - 19, 121665
    k = int.from_bytes(k_bytes, "little")
    k = (k & ~7 & ((1 << 255) - 1)) | (1 << 254)
    u = int.from_bytes(u_bytes, "little") & ((1 << 255) - 1)
    x1, x2, z2, x3, z3, swap = u, 1, 0, u, 1, 0
    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        A, B, C, D = (x2 + z2) % p, (x2 - z2) % p, (x3 + z3) % p, (x3 - z3) % p
        AA, BB, DA, CB = A * A % p, B * B % p, D * A % p, C * B % p
        E = (AA - BB) % p
        x3, z3 = pow(DA + CB, 2, p), x1 * pow(DA - CB, 2, p) % p
        x2, z2 = AA * BB % p, E * (AA + a24 * E) % p
    if swap:
        x2, x3, z2, z3 = x3, x2, z3, z2
    return (x2 * pow(z2, p - 2, p) % p).to_bytes(32, "little")


def test_x25519_edge_inputs_vs_bigint_reference():
    p = 2 ** 255 - 19
    us = [0, 1, 2, 9, p - 1, p, p + 1, p + 9, 2 ** 255 - 1, 2 ** 256 - 1, 2 ** 255, (p - 1) // 2]
    rnd = random.Random(3)
    for u in us:
        for k in (os.urandom(32), bytes(32), b"\xff" * 32, bytes([255]) * 31 + bytes([127])):
            ub = u.to_bytes(32, "little")
            assert bytes(sp.x25519(L(k), L(ub))) == _x25519_bigint(k, ub), (u, k.hex())
    one_iter = bytes(sp.x25519(L(b"\x09" + bytes(31)), L(b"\x09" + bytes(31)))).hex()
    assert one_iter == "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"   # RFC 7748 6.1 (1 iteration)
    for _ in range(10):
        k, u = rnd.randbytes(32), rnd.randbytes(32)
        assert bytes(sp.x25519(L(k), L(u))) == _x25519_bigint(k, u)


# ============================================================ 2) 相互運用 + 3) 攻撃シナリオ
def make_pair(server_key=None, pinned_pub=None, on_message=None):
    sk = server_key or X25519PrivateKey.generate()
    got = []
    server = ss.SecureServer(sk, on_message=on_message or (lambda sid, d: (got.append(d), b"echo:" + d)[1]))
    client = cr.ScratchClient(L(pinned_pub or server.public_key), L(os.urandom(32)))
    return server, client, got


def handshake(server, client):
    out = server.handle_frame(bytes(client.hello()))
    assert out is not None and len(out) == 73
    return out, client.on_reply(L(out))


def test_full_session_interop_both_directions():
    server, client, got = make_pair()
    _, ok = handshake(server, client)
    assert ok
    for msg in (b"hello", b"", b"x" * 31, b"\x00\xff" * 70, "日本語のメッセージ🔐".encode()):
        frame = bytes(client.seal(L(msg)))
        reply = server.handle_frame(frame)
        assert got[-1] == msg and reply is not None
        assert bytes(client.open(L(reply))) == b"echo:" + msg
    pushed = server.send(bytes(client.sid), b"server-push")          # サーバー起点
    assert bytes(client.open(L(pushed))) == b"server-push"


def test_eavesdropper_sees_no_plaintext_and_cannot_decrypt():
    server, client, _ = make_pair()
    transcript = [bytes(client.hello())]
    r, ok = handshake(server, client)
    transcript.append(r)
    assert ok
    secret = b"TOP-SECRET-PASSWORD-1234567890"
    f = bytes(client.seal(L(secret)))
    transcript.append(f)
    reply = server.handle_frame(f)
    assert reply is not None
    transcript.append(reply)
    assert all(secret not in t and b"TOP-SECRET" not in t for t in transcript)
    # 盗聴者が持つ情報だけ(E, R, S, 全フレーム)から鍵を作ろうとしても復号できない
    E, R = transcript[0][9:], transcript[1][9:41]
    for guess in (E, R, server.public_key, bytes(32)):
        ks = ss.derive_keys(guess, guess)[0]
        with pytest.raises(Exception):
            ChaCha20Poly1305(ks).decrypt(ss.nonce_for(1), f[15:], f[:15])


def test_length_hidden_by_padding():
    server, client, _ = make_pair()
    handshake(server, client)
    a = bytes(client.seal(L(b"a")))
    b = bytes(client.seal(L(b"b" * 25)))
    assert len(a) == len(b)


def test_tamper_any_bit_is_dropped_and_session_survives():
    server, client, got = make_pair()
    handshake(server, client)
    good = bytes(client.seal(L(b"payload")))
    rnd = random.Random(1)
    for _ in range(80):
        i, bit = rnd.randrange(len(good)), 1 << rnd.randrange(8)
        bad = bytearray(good); bad[i] ^= bit
        assert server.handle_frame(bytes(bad)) is None
    assert got == []                                       # 1回も届いていない
    assert server.handle_frame(good) is not None and got == [b"payload"]   # 本物は通る(状態が壊れていない)


def test_replay_rejected_both_directions():
    server, client, got = make_pair()
    handshake(server, client)
    f1 = bytes(client.seal(L(b"one")))
    reply = server.handle_frame(f1)
    assert reply is not None
    assert server.handle_frame(f1) is None and got == [b"one"]          # c2s の再送
    assert client.open(L(reply)) is not None
    assert client.open(L(reply)) is None                               # s2c の再送
    f2, f3 = bytes(client.seal(L(b"two"))), bytes(client.seal(L(b"three")))
    server.handle_frame(f3)
    assert server.handle_frame(f2) is None                               # 巻き戻し(古い ctr)


def test_wrong_direction_or_reflection_rejected():
    server, client, _ = make_pair()
    handshake(server, client)
    f = bytes(client.seal(L(b"hi")))
    assert client.open(L(f)) is None                                   # 自分の送信を「受信」として反射
    refl = bytearray(f); refl[8] = ss.T_S2C
    assert server.handle_frame(bytes(refl)) is None


def test_mitm_replaces_R_with_server_static_key():
    """R := S にすると dh_ee == dh_es になる(XOR 型の鍵結合ならここで鍵がゼロに崩壊する)。"""
    server, client, _ = make_pair()
    first_reply = server.handle_frame(bytes(client.hello()))
    assert first_reply is not None
    reply = bytearray(first_reply)
    reply[9:41] = server.public_key
    assert client.on_reply(L(bytes(reply))) is False and not client.ready


def test_fake_server_with_different_key_rejected():
    real = X25519PrivateKey.generate()
    fake_server = ss.SecureServer(X25519PrivateKey.generate(), on_message=lambda s, d: d)
    client = cr.ScratchClient(L(real.public_key().public_bytes_raw()), L(os.urandom(32)))
    reply = fake_server.handle_frame(bytes(client.hello()))
    assert reply is not None
    assert client.on_reply(L(reply)) is False


def test_active_attacker_cannot_forge_reply_without_server_key():
    server, client, _ = make_pair()
    attacker_r = X25519PrivateKey.generate()
    E = bytes(client.hello())[9:]
    dh = attacker_r.exchange(X25519PublicKey.from_public_bytes(E))
    _master, k_c2s, k_s2c = ss.derive_keys(dh, dh)         # 攻撃者が自分で作れる鍵
    R = attacker_r.public_key().public_bytes_raw()
    sid = bytes(client.sid)
    confirm = ChaCha20Poly1305(k_s2c).encrypt(ss.nonce_for(0), ss.READY, sid + bytes([2]) + E + R)
    assert client.on_reply(L(sid + bytes([2]) + R + confirm)) is False


def test_low_order_points_rejected_by_server_and_client():
    server, client, _ = make_pair()
    for bad in (bytes(32), (1).to_bytes(32, "little")):    # u=0, u=1 は位数が小さい
        E = bad
        assert server.handle_frame(E[:8] + b"\x01" + E) is None
    assert server.session_count() == 0
    # クライアント側: サーバー(攻撃者)が R=0 を返してきた
    first_reply = server.handle_frame(bytes(client.hello()))
    assert first_reply is not None
    reply = bytearray(first_reply)
    reply[9:41] = bytes(32)
    assert client.on_reply(L(bytes(reply))) is False


def test_hello_rules():
    server, client, _ = make_pair()
    h = bytes(client.hello())
    assert server.handle_frame(h) is not None
    assert server.handle_frame(h) is None                    # 同じ sid の 2 回目は無視
    other = cr.ScratchClient(L(server.public_key), L(os.urandom(32)))
    hh = bytearray(other.hello()); hh[0] ^= 1              # sid != E[:8]
    assert server.handle_frame(bytes(hh)) is None
    assert server.handle_frame(h[:-1]) is None and server.handle_frame(b"") is None   # 壊れた入力で落ちない


def test_garbage_never_crashes_server():
    server, client, _ = make_pair()
    handshake(server, client)
    rnd = random.Random(7)
    for _ in range(300):
        n = rnd.randrange(0, 120)
        junk = bytearray(rnd.randrange(256) for _ in range(n))
        if n > 9 and rnd.random() < .7:
            junk[:8] = bytes(client.sid); junk[8] = rnd.choice([1, 2, 3, 4])
        assert server.handle_frame(bytes(junk)) is None


def test_forward_secrecy_static_key_leak_is_not_enough():
    """サーバー秘密鍵 s が後で漏れても、記録された通信は復号できない(r は破棄済み)。"""
    sk = X25519PrivateKey.generate()
    server, client, _ = make_pair(server_key=sk)
    r, ok = handshake(server, client)
    assert ok
    f = bytes(client.seal(L(b"old secret")))
    server.handle_frame(f)
    E, R = bytes(client.hello())[9:], r[9:41]
    dh_es = sk.exchange(X25519PublicKey.from_public_bytes(E))       # 漏れた s から計算できる
    for dh_ee_guess in (dh_es, bytes(32), R, E):                    # dh_ee は計算できない
        k = ss.derive_keys(dh_es, dh_ee_guess)[0]
        with pytest.raises(Exception):
            ChaCha20Poly1305(k).decrypt(ss.nonce_for(1), f[15:], f[:15])


def test_session_expiry_and_limits():
    t = [0.0]
    srv = ss.SecureServer(os.urandom(32), on_message=lambda s, d: d, idle_timeout=10, max_sessions=2, clock=lambda: t[0])
    c1 = cr.ScratchClient(L(srv.public_key), L(os.urandom(32)))
    c2 = cr.ScratchClient(L(srv.public_key), L(os.urandom(32)))
    c3 = cr.ScratchClient(L(srv.public_key), L(os.urandom(32)))
    for c in (c1, c2):
        reply = srv.handle_frame(bytes(c.hello()))
        assert reply is not None and c.on_reply(L(reply))
    assert srv.handle_frame(bytes(c3.hello())) is None      # 満員
    t[0] = 11                                               # アイドル超過 -> 掃除される
    assert srv.handle_frame(bytes(c1.seal(L(b"late")))) is None
    assert srv.handle_frame(bytes(c3.hello())) is not None


def test_hello_rate_limit():
    srv = ss.SecureServer(os.urandom(32), hello_burst=3, hello_per_sec=0.0, clock=lambda: 0.0)
    n = 0
    for _ in range(10):
        c = cr.ScratchClient(L(srv.public_key), L(os.urandom(32)))
        n += int(srv.handle_frame(bytes(c.hello())) is not None)
    assert n == 3


def test_client_limits_reply_flood():
    server, client, _ = make_pair()
    real = server.handle_frame(bytes(client.hello()))
    assert real is not None
    fake = bytearray(real); fake[-1] ^= 1
    for _ in range(cr.MAX_REPLY_TRIES):
        assert client.on_reply(L(bytes(fake))) is False
    assert client.on_reply(L(real)) is False                # 計算を打ち切った(クライアント DoS 対策)


# ============================================================ クラウド変数コーデック
def test_digits_and_slots_roundtrip_within_256_digits():
    with pytest.raises(ValueError):
        ss.to_slots(b"", 0)
    for n in (1, 41, 73, 84, 85, 168, 300, 336):
        frame = os.urandom(n)
        slots, hdr = ss.to_slots(frame, seq=123456 + n)
        assert all(len(s) <= 256 and s.isdigit() for s in slots) and hdr.isdigit()
        seq, back = ss.from_slots(hdr, slots)
        assert seq == (123456 + n) % 10 ** 6 and back == frame
    with pytest.raises(ValueError):
        ss.to_slots(os.urandom(337), 0)
    for bad in ("", "2000", "1999999", "1256", "1abc"):
        with pytest.raises(ValueError):
            ss.from_digits(bad)


def test_max_message_size_fits_in_slots():
    assert ss.DEFAULT_MAX_PLAIN == 286
    server, client, got = make_pair(on_message=lambda sid, d: b"ok")
    handshake(server, client)
    msg = os.urandom(ss.DEFAULT_MAX_PLAIN)
    frame = bytes(client.seal(L(msg)))
    assert len(frame) <= ss.MAX_SLOTS * ss.SLOT_BYTES
    ss.to_slots(frame, 0)                                  # 4 slot に収まる
    reply = server.handle_frame(frame)
    assert reply is not None and bytes(client.open(L(reply))) == b"ok"
    # サーバーが上限超えの返信を作ろうとしたら黙って捨てる(スロットに入らないため)
    assert server.send(bytes(client.sid), b"x" * (ss.DEFAULT_MAX_PLAIN + 1)) is None


def test_full_session_over_cloud_variable_encoding():
    server, client, got = make_pair()
    slots, hdr = ss.to_slots(bytes(client.hello()), 1)
    out = server.handle_frame(ss.from_slots(hdr, slots)[1])
    assert out is not None
    slots, hdr = ss.to_slots(out, 1)
    assert slots and client.on_reply(L(ss.from_slots(hdr, slots)[1]))
    msg = os.urandom(200)
    slots, hdr = ss.to_slots(bytes(client.seal(L(msg))), 2)
    server.handle_frame(ss.from_slots(hdr, slots)[1])
    assert got == [msg]


# ============================================================ 4) Scratch 制約の監査(最後に置く)
def test_zz_scratch_constraints_audit():
    """別プロセスで実行: 全プリミティブを Chk(2^53 検査 + ビット演算禁止)で動かし、結果が通常実行と一致することを確認。"""
    code = r'''
import os
from cloudiamond_scratch.reference import prims as sp
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
plain = {}
k, n, aad, pt = os.urandom(32), os.urandom(12), os.urandom(20), os.urandom(100)
sc = list(os.urandom(32)); pt_u = list(X25519PrivateKey.generate().public_key().public_bytes_raw())
hn = list(os.urandom(16))
want = (sp.x25519(sc, pt_u), sp.hchacha20(list(k), hn), sp.aead_seal(list(k), list(n), list(aad), list(pt)))
sp.use_checked()
C = sp.Chk
c = lambda b: [C(x) for x in b]
before = sp.OPCOUNT
got_x = sp.x25519(c(sc), c(pt_u)); ops_x = sp.OPCOUNT - before
before = sp.OPCOUNT
got_h = sp.hchacha20(c(k), c(hn)); ops_h = sp.OPCOUNT - before
before = sp.OPCOUNT
got_a = sp.aead_seal(c(k), c(n), c(aad), c(pt)); ops_a = sp.OPCOUNT - before
assert [int(v) for v in got_x] == want[0]
assert [int(v) for v in got_h] == want[1]
assert [int(v) for v in got_a] == want[2]
assert bytes(want[2]) == ChaCha20Poly1305(k).encrypt(n, pt, aad)
print("OK maxseen=2^%.1f x25519_ops=%d hchacha20_ops=%d aead100B_ops=%d" % (
    __import__("math").log2(sp.MAXSEEN), ops_x, ops_h, ops_a))
'''
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[-2000:]
    print(r.stdout.strip())


if __name__ == "__main__":
    sys.exit(pytest.main(["-q", "-s", __file__]))
