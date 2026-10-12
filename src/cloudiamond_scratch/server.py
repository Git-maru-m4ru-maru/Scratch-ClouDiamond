"""
cloudiamond_scratch.server -- Python サーバー側 + 通信プロトコル定義 (Scratch クライアントと対になる)

設計の大前提(Kerckhoffs の原理):
    Scratch のコードは全員に見える。だから「アルゴリズムや鍵を隠す」設計は成立しない。
    安全性は *数学的に隠れる秘密* だけに依存させる = 公開鍵方式の鍵交換。
    ・サーバーの公開鍵 S は Scratch プロジェクトに埋め込んでよい(公開情報)。
    ・クライアントは接続のたびに使い捨ての秘密鍵 e を生成する。e は誰にも送られない。
    ・プロジェクトのコード、全通信、サーバー公開鍵をすべて知っていても、鍵は計算できない。

プロトコル(Noise_NK 風 + サーバー一時鍵による前方秘匿性):
    C → S : sid | 01 | E                       E = e·G        (41 byte)
    S → C : sid | 02 | R | AEAD(READY)          R = r·G        (73 byte)
    鍵:   dh_es = X25519(e, S) = X25519(s, E)    ← サーバー認証(s を持つ者だけが計算できる)
          dh_ee = X25519(e, R) = X25519(r, E)    ← 前方秘匿性(r は使用後に破棄)
          master = HChaCha20(dh_ee, HChaCha20(dh_es, "master")[:16])
          k_c2s  = HChaCha20(master, "c2s"),  k_s2c = HChaCha20(master, "s2c")
    データ: sid | 03/04 | ctr(6) | ChaCha20-Poly1305(pad(msg))   AAD = ヘッダ

    sid = E の先頭 8 byte(他人が別の E で同じ sid を先取りできない)。
    HELLO_REPLY の AEAD が E と R をAADで認証する = 鍵確認 + 中間者による R 差し替えの検出。

使っているのは X25519 / ChaCha20-Poly1305 (RFC 8439) / HChaCha20(XChaCha20 の一部)のみ。
独自暗号は一つもありません。唯一の「組み立て」は上の 2 段 KDF で、README に理由を書きました。
"""
from __future__ import annotations

import os
import threading
import time
from typing import Callable, Dict, List, Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# ---------------------------------------------------------------- 定数
T_HELLO, T_REPLY, T_C2S, T_S2C = 1, 2, 3, 4
SID_LEN, CTR_LEN, TAG_LEN = 8, 6, 16
LABEL_MASTER = b"SCRSEC1-master\0\0"
LABEL_C2S = b"SCRSEC1-c2s\0\0\0\0\0"
LABEL_S2C = b"SCRSEC1-s2c\0\0\0\0\0"
READY = b"SCRSEC1-READY\0\0\0"
PAD_BUCKET = 32            # 平文長を 32 byte 単位に丸めて長さを隠す
MAX_CTR = 2 ** 40
assert all(len(x) == 16 for x in (LABEL_MASTER, LABEL_C2S, LABEL_S2C, READY))


# ---------------------------------------------------------------- HChaCha20 (サーバー側は素直に書く)
def _rotl(x: int, n: int) -> int:
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))


def hchacha20(key: bytes, nonce16: bytes) -> bytes:
    assert len(key) == 32 and len(nonce16) == 16
    s = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    s += [int.from_bytes(key[i:i + 4], "little") for i in range(0, 32, 4)]
    s += [int.from_bytes(nonce16[i:i + 4], "little") for i in range(0, 16, 4)]

    def qr(a, b, c, d):
        s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rotl(s[d] ^ s[a], 16)
        s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rotl(s[b] ^ s[c], 12)
        s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rotl(s[d] ^ s[a], 8)
        s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rotl(s[b] ^ s[c], 7)

    for _ in range(10):
        qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)
        qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14)
    return b"".join(s[i].to_bytes(4, "little") for i in (0, 1, 2, 3, 12, 13, 14, 15))


def derive_keys(dh_es: bytes, dh_ee: bytes):
    """(k_c2s, k_s2c)。dh_es / dh_ee のどちらか一方が秘密なら master は予測できない。"""
    inner = hchacha20(dh_es, LABEL_MASTER)[:16]
    master = hchacha20(dh_ee, inner)
    return hchacha20(master, LABEL_C2S), hchacha20(master, LABEL_S2C)


# ---------------------------------------------------------------- フレーム
def nonce_for(ctr: int) -> bytes:
    return b"\0\0\0\0" + ctr.to_bytes(8, "big")


def pad_plain(data: bytes) -> bytes:
    body = len(data).to_bytes(2, "big") + data
    return body + b"\0" * (-len(body) % PAD_BUCKET)


def unpad_plain(p: bytes) -> bytes:
    n = int.from_bytes(p[:2], "big")
    if 2 + n > len(p):
        raise ValueError("bad padding")
    return p[2:2 + n]


# ---------------------------------------------------------------- クラウド変数用コーデック
# Scratch のクラウド変数は「数字だけ・最大256桁」。1 byte = 3 桁、先頭に '1' を付けて 0 落ちを防ぐ。
SLOT_BYTES = 84            # 1 + 84*3 = 253 桁 <= 256
MAX_SLOTS = 4              # クラウド変数は 1 プロジェクトに最大 10 個: (HDR + 4 slot) × 2 方向 = 10
# 1 フレームの最大長 = 4 slot × 84 = 336 byte -> 平文(2 byte 長さ + データ)は 32 の倍数で 288 まで -> データは 286 byte まで
DEFAULT_MAX_PLAIN = (MAX_SLOTS * SLOT_BYTES - (SID_LEN + 1 + CTR_LEN) - TAG_LEN) // PAD_BUCKET * PAD_BUCKET - 2


def to_digits(b: bytes) -> str:
    return "1" + "".join("%03d" % x for x in b)


def from_digits(s: str) -> bytes:
    if not s or s[0] != "1" or (len(s) - 1) % 3 or not s.isdigit():
        raise ValueError("bad digits")
    vals = [int(s[i:i + 3]) for i in range(1, len(s), 3)]
    if any(v > 255 for v in vals):
        raise ValueError("bad digits")
    return bytes(vals)


def to_slots(frame: bytes, seq: int):
    """frame -> (slot 文字列のリスト, ヘッダ文字列)。slot を全部書いた「後で」ヘッダを書く(= コミット)。"""
    chunks = [frame[i:i + SLOT_BYTES] for i in range(0, len(frame), SLOT_BYTES)] or [b""]
    if len(chunks) > MAX_SLOTS:
        raise ValueError("frame too large for %d slots" % MAX_SLOTS)
    return [to_digits(c) for c in chunks], "1%06d%02d" % (seq % 10 ** 6, len(chunks))


def from_slots(hdr: str, slots: List[str]):
    """(seq, frame)。"""
    if len(hdr) != 9 or hdr[0] != "1" or not hdr.isdigit():
        raise ValueError("bad header")
    seq, n = int(hdr[1:7]), int(hdr[7:9])
    if not 1 <= n <= min(MAX_SLOTS, len(slots)):
        raise ValueError("bad slot count")
    return seq, b"".join(from_digits(s) for s in slots[:n])


# ---------------------------------------------------------------- 鍵の保存
def load_or_create_static_key(path: str) -> X25519PrivateKey:
    if os.path.exists(path):
        with open(path, "rb") as f:
            return X25519PrivateKey.from_private_bytes(f.read())
    key = X25519PrivateKey.generate()
    raw = key.private_bytes_raw()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)   # 自分だけ読める
    with os.fdopen(fd, "wb") as f:
        f.write(raw)
    return key


def public_bytes(key: X25519PrivateKey) -> bytes:
    return key.public_key().public_bytes_raw()


# ---------------------------------------------------------------- サーバー
class _Session:
    __slots__ = ("sid", "k_c2s", "k_s2c", "c2s_last", "s2c_next", "created", "last_seen", "n_msgs")

    def __init__(self, sid, k_c2s, k_s2c, now):
        self.sid, self.k_c2s, self.k_s2c = sid, k_c2s, k_s2c
        self.c2s_last, self.s2c_next = 0, 1
        self.created = self.last_seen = now
        self.n_msgs = 0


class SecureServer:
    """
    transport 非依存。受信フレーム(bytes)を handle_frame() に渡すと、送信すべきフレームのリストが返る。
    on_message(sid, data) -> bytes | None  が bytes を返せば、自動で暗号化して返信フレームになる。
    不正なフレームはすべて「黙って捨てる」(攻撃者に判定材料=オラクルを与えない)。
    """

    def __init__(self, static_key: Optional[X25519PrivateKey] = None,
                 on_message: Optional[Callable[[bytes, bytes], Optional[bytes]]] = None,
                 max_sessions: int = 512, idle_timeout: float = 600.0, max_lifetime: float = 3600.0,
                 max_messages: int = 100_000, max_plain: int = DEFAULT_MAX_PLAIN,
                 hello_burst: int = 20, hello_per_sec: float = 5.0,
                 clock: Callable[[], float] = time.monotonic):
        self._sk = static_key or X25519PrivateKey.generate()
        self.on_message = on_message
        self.max_sessions, self.idle_timeout, self.max_lifetime = max_sessions, idle_timeout, max_lifetime
        self.max_messages, self.max_plain = max_messages, max_plain
        self._clock = clock
        self._sessions: Dict[bytes, _Session] = {}
        self._lock = threading.Lock()
        self._tokens, self._burst, self._rate, self._t_last = float(hello_burst), hello_burst, hello_per_sec, clock()

    @property
    def public_key(self) -> bytes:
        return public_bytes(self._sk)

    # -- 内部
    def _purge(self, now):
        dead = [k for k, s in self._sessions.items()
                if now - s.last_seen > self.idle_timeout or now - s.created > self.max_lifetime
                or s.n_msgs >= self.max_messages]
        for k in dead:
            del self._sessions[k]

    def _take_token(self, now) -> bool:
        self._tokens = min(self._burst, self._tokens + (now - self._t_last) * self._rate)
        self._t_last = now
        if self._tokens < 1:
            return False
        self._tokens -= 1
        return True

    def session_count(self) -> int:
        with self._lock:
            return len(self._sessions)

    # -- 受信
    def handle_frame(self, frame: bytes) -> List[bytes]:
        with self._lock:
            try:
                return self._handle(bytes(frame))
            except Exception:           # どんな異常入力でも落ちない・情報を出さない
                return []

    def _handle(self, f: bytes) -> List[bytes]:
        if len(f) < SID_LEN + 1:
            return []
        now = self._clock()
        sid, typ = f[:SID_LEN], f[SID_LEN]
        if typ == T_HELLO:
            return self._on_hello(sid, f, now)
        if typ == T_C2S:
            return self._on_data(sid, f, now)
        return []

    def _on_hello(self, sid, f, now):
        if len(f) != SID_LEN + 1 + 32:
            return []
        E = f[SID_LEN + 1:]
        if sid != E[:SID_LEN]:
            return []
        self._purge(now)
        if sid in self._sessions or len(self._sessions) >= self.max_sessions or not self._take_token(now):
            return []
        r = X25519PrivateKey.generate()
        try:                                   # 位数の小さい点(全ゼロ出力)は ValueError で弾かれる
            Ek = X25519PublicKey.from_public_bytes(E)
            dh_es = self._sk.exchange(Ek)
            dh_ee = r.exchange(Ek)
        except ValueError:
            return []
        R = r.public_key().public_bytes_raw()
        del r                                   # 一時秘密鍵を保持しない(= 前方秘匿性)
        k_c2s, k_s2c = derive_keys(dh_es, dh_ee)
        confirm = ChaCha20Poly1305(k_s2c).encrypt(nonce_for(0), READY, sid + bytes([T_REPLY]) + E + R)
        self._sessions[sid] = _Session(sid, k_c2s, k_s2c, now)
        return [sid + bytes([T_REPLY]) + R + confirm]

    def _on_data(self, sid, f, now):
        s = self._sessions.get(sid)
        hdr_len = SID_LEN + 1 + CTR_LEN
        if s is None or len(f) < hdr_len + PAD_BUCKET + TAG_LEN:
            return []
        if now - s.last_seen > self.idle_timeout or now - s.created > self.max_lifetime:
            del self._sessions[sid]
            return []
        ctr = int.from_bytes(f[SID_LEN + 1:hdr_len], "big")
        if ctr <= s.c2s_last or ctr >= MAX_CTR:           # 再送(リプレイ)・巻き戻しを拒否
            return []
        try:
            plain = ChaCha20Poly1305(s.k_c2s).decrypt(nonce_for(ctr), f[hdr_len:], f[:hdr_len])
            data = unpad_plain(plain)
        except Exception:
            return []
        s.c2s_last, s.last_seen = ctr, now                # 認証に成功した後でだけ状態を進める
        s.n_msgs += 1
        if self.on_message is None:
            return []
        reply = self.on_message(sid, data)
        out = self._seal(s, reply) if reply is not None else None
        return [out] if out else []

    # -- 送信
    def _seal(self, s: _Session, data: bytes) -> Optional[bytes]:
        if len(data) > self.max_plain or s.s2c_next >= MAX_CTR:
            return None
        ctr = s.s2c_next
        s.s2c_next += 1
        hdr = s.sid + bytes([T_S2C]) + ctr.to_bytes(CTR_LEN, "big")
        return hdr + ChaCha20Poly1305(s.k_s2c).encrypt(nonce_for(ctr), pad_plain(data), hdr)

    def send(self, sid: bytes, data: bytes) -> Optional[bytes]:
        """サーバー起点の送信(push)。セッションが無ければ None。"""
        with self._lock:
            s = self._sessions.get(sid)
            return self._seal(s, data) if s else None

