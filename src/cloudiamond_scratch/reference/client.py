"""
cloudiamond_scratch.reference.client -- Scratch クライアントの参照実装(= 移植元の仕様書)

ここで使っているのは cloudiamond_scratch.reference.prims の関数と「リスト・数値・if・ループ」だけ。
バイト列は Python の list[int](0..255)で扱う = Scratch のリストそのもの。
各メソッドが、Scratch の「定義 ◯◯」カスタムブロック(実行中に画面を再描画しない)に1対1で対応する。
"""
from __future__ import annotations

from typing import List, Optional

from . import prims as sp

T_HELLO, T_REPLY, T_C2S, T_S2C = 1, 2, 3, 4
LABEL_MASTER = list(b"SCRSEC1-master\0\0")
LABEL_C2S = list(b"SCRSEC1-c2s\0\0\0\0\0")
LABEL_S2C = list(b"SCRSEC1-s2c\0\0\0\0\0")
READY = list(b"SCRSEC1-READY\0\0\0")
PAD_BUCKET = 32
MAX_REPLY_TRIES = 3          # 偽の返信を大量に送り付けられても計算を無限にやらない


def mix_entropy(*streams: List[int]) -> List[int]:
    """複数の乱数源を byte ごとに足して mod 256。どれか1つが予測不能なら結果も予測不能。
    Scratch では: [pick random 0〜255] + [timer と mouse x/y の細かい桁から作った byte] + [ユーザーが
    3 秒間マウスを振った軌跡] + [days since 2000 の小数下位桁] ... を足し合わせる。"""
    return [sum(s[i] for s in streams) % 256 for i in range(32)]


def _all_zero(v) -> bool:
    return sum(v) == 0


def _ctr6(n) -> List[int]:
    return [n // 256 ** (5 - i) % 256 for i in range(6)]


def _pad(data: List[int]) -> List[int]:
    n = len(data)
    body = [n // 256, n % 256] + list(data)
    return body + [0] * ((PAD_BUCKET - len(body) % PAD_BUCKET) % PAD_BUCKET)


def _unpad(p: List[int]) -> Optional[List[int]]:
    n = p[0] * 256 + p[1]
    return None if 2 + n > len(p) else p[2:2 + n]


class ScratchClient:
    def __init__(self, server_pub: List[int], entropy32: List[int]):
        self.S = list(server_pub)                 # プロジェクトに埋め込んだサーバー公開鍵(公開情報)
        self.e = list(entropy32)                  # 使い捨ての秘密鍵。送信しない・保存しない
        self.E = sp.x25519_base(self.e)           # 重い処理 #1
        self.sid = self.E[:8]
        self.dh_es = None
        self.ready = False
        self.tries = 0
        self.send_ctr = 0
        self.recv_last = 0
        self.k_c2s = self.k_s2c = None

    # ---- 定義 HELLOを作る
    def hello(self) -> List[int]:
        return self.sid + [T_HELLO] + self.E

    # ---- 定義 返信を処理する
    def on_reply(self, f: List[int]) -> bool:
        if self.ready or self.tries >= MAX_REPLY_TRIES or len(f) != 73 or f[8] != T_REPLY or f[:8] != self.sid:
            return False
        self.tries += 1
        R, sealed = f[9:41], f[41:]
        if self.dh_es is None:
            self.dh_es = sp.x25519(self.e, self.S)      # 重い処理 #2(1回だけ。サーバー認証の要)
            if _all_zero(self.dh_es):
                return False
        dh_ee = sp.x25519(self.e, R)                    # 重い処理 #3(偽返信 1 個につき 1 回)
        if _all_zero(dh_ee):                            # R が位数の小さい点 -> 拒否
            return False
        inner = sp.hchacha20(self.dh_es, LABEL_MASTER)[:16]
        master = sp.hchacha20(dh_ee, inner)
        k_c2s = sp.hchacha20(master, LABEL_C2S)
        k_s2c = sp.hchacha20(master, LABEL_S2C)
        aad = self.sid + [T_REPLY] + self.E + R         # E と R を認証 = 差し替え検出
        pt = sp.aead_open(k_s2c, [0] * 12, aad, sealed)
        if pt is None or pt != READY:
            return False
        self.k_c2s, self.k_s2c, self.ready = k_c2s, k_s2c, True
        self.dh_es = dh_ee = master = None              # 不要になった秘密を消す
        return True

    # ---- 定義 暗号化して送るフレームを作る
    def seal(self, data: List[int]) -> List[int]:
        assert self.ready
        self.send_ctr = self.send_ctr + 1
        hdr = self.sid + [T_C2S] + _ctr6(self.send_ctr)
        nonce = [0, 0, 0, 0] + [self.send_ctr // 256 ** (7 - i) % 256 for i in range(8)]
        return hdr + sp.aead_seal(self.k_c2s, nonce, hdr, _pad(data))

    # ---- 定義 受信フレームを復号する(失敗なら None)
    def open(self, f: List[int]) -> Optional[List[int]]:
        if not self.ready or len(f) < 15 + PAD_BUCKET + 16 or f[8] != T_S2C or f[:8] != self.sid:
            return None
        ctr = 0
        for i in range(6):
            ctr = ctr * 256 + f[9 + i]
        if ctr <= self.recv_last:
            return None
        nonce = [0, 0, 0, 0] + [ctr // 256 ** (7 - i) % 256 for i in range(8)]
        pt = sp.aead_open(self.k_s2c, nonce, f[:15], f[15:])
        if pt is None:
            return None
        self.recv_last = ctr
        return _unpad(pt)
