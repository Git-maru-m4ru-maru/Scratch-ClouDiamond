"""
bridge.py -- クラウド変数(Scratch / TurboWarp)と SecureServer をつなぐ、通信手段に依存しない橋渡し。

CloudBridge は WebSocket も scratchattach も知らない。使う側が次の 2 つだけ用意する。
    on_variable(name, value)    クラウド変数が更新されたら呼ぶ(受信)
    write(name, value)          クラウド変数を書く関数を渡す(送信。slot を全部書いた「後で」HDR を書く)

Scratch 側(scratch/program.py)との約束:
    C2S = クライアント -> サーバー: "☁ C2S_0".."☁ C2S_3"(slot) と "☁ C2S_HDR"(コミット)
    S2C = サーバー -> クライアント: "☁ S2C_0".."☁ S2C_3" と "☁ S2C_HDR"
    HDR の値が「変わった」ことが「slot が揃った」合図。だから HDR は書くたびに必ず変わる(seq を増やす)。
    seq はサーバー全体で単調増加させる。セッションごとに 1 から数え直すと、新しい接続の最初の返信の HDR が
    前の接続の最後の HDR と同じ値になり、クライアントが「変化なし」と見なしてしまう。

安全性: クラウド変数は誰でも書ける。壊れた値・他人の値は暗号(AEAD)の検証で必ず捨てられる(= 安全側)。
        捨てられるだけで届かなくはできる(妨害は防げない)。
"""
from __future__ import annotations

import random
import threading
from typing import Callable, Dict, List, Optional

from .server import MAX_SLOTS, SecureServer, from_slots, to_slots

C2S_HDR = "☁ C2S_HDR"
C2S_SLOTS = ["☁ C2S_%d" % i for i in range(MAX_SLOTS)]
S2C_HDR = "☁ S2C_HDR"
S2C_SLOTS = ["☁ S2C_%d" % i for i in range(MAX_SLOTS)]
CLOUD_VARIABLES = [C2S_HDR] + C2S_SLOTS + [S2C_HDR] + S2C_SLOTS     # プロジェクトに必要な 10 個


class CloudBridge:
    def __init__(self, server: SecureServer, write: Callable[[str, str], None],
                 seq_start: Optional[int] = None):
        self.server = server
        self._write = write
        self._values: Dict[str, str] = {}
        self._seq = seq_start if seq_start is not None else random.SystemRandom().randrange(1, 900000)
        self._lock = threading.Lock()

    # ---------------------------------------------------------------- 受信
    def on_variable(self, name: str, value) -> None:
        """クラウド変数の更新を 1 件渡す。名前が C2S_* 以外なら無視する。"""
        if name not in C2S_SLOTS and name != C2S_HDR:
            return
        with self._lock:
            self._values[name] = str(value)
            if name != C2S_HDR:
                return
            # 同じ HDR を「重複」として捨てない: 別クライアントの正規フレームが偶然同じ HDR 値になり得るため。
            # 再接続時の現在値の再送などで同じフレームが再度来ても、サーバーのリプレイ防止
            # (既存 sid の HELLO・古いカウンタは拒否)が無害化する。
            frames = self._decode(self._values[C2S_HDR])
        if frames is None:
            return
        for reply in self.server.handle_frame(frames):
            self._emit(reply)

    def _decode(self, hdr: str) -> Optional[bytes]:
        try:
            n = int(hdr[-2:])
            slots = [self._values[C2S_SLOTS[i]] for i in range(n)]
            return from_slots(hdr, slots)[1]
        except (ValueError, KeyError, IndexError):
            return None                          # 壊れた値は黙って捨てる

    # ---------------------------------------------------------------- 送信
    def push(self, sid: bytes, data: bytes) -> bool:
        """サーバー起点でクライアントへ送る(セッションが無い・長すぎる場合は False)。"""
        frame = self.server.send(sid, data)
        if frame is None:
            return False
        self._emit(frame)
        return True

    def _emit(self, frame: bytes) -> None:
        with self._lock:
            self._seq = self._seq % 999999 + 1   # 1..999999 を巡回。毎回必ず変わる
            seq = self._seq
        slots, hdr = to_slots(frame, seq)
        for i, s in enumerate(slots):
            self._write(S2C_SLOTS[i], s)
        self._write(S2C_HDR, hdr)                # HDR を最後に書く = コミット
