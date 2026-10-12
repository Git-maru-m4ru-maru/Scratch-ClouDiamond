"""
cloudiamond_scratch.reference.prims -- Scratch で実装できる演算だけで書いた暗号プリミティブ(実行可能な仕様書)

【制約】Scratch の数値は倍精度浮動小数点(double)で、使える演算は
    + - *   floor(a / 2^k)   mod   比較   リスト(配列)アクセス
だけ。ビット演算(& | ^ << >>)も、64bit整数も、巨大整数もありません。
このファイルは「その制約の中で」次を実装します。

    X25519        (RFC 7748)     ... TweetNaCl の 16bit×16 limb 方式
    ChaCha20      (RFC 8439)
    HChaCha20     (XChaCha20 の鍵導出部)
    Poly1305      (RFC 8439)     ... 8bit×17 limb 方式
    AEAD ChaCha20-Poly1305 (RFC 8439)

【機械的な強制】
    Chk クラスを使うと、(1) どの中間値も 2^53 未満であること(= double で厳密)、
    (2) ビット演算を一切使っていないこと を実行時に検査できます。
    tests/test_core.py は全プリミティブを Chk 経由で1回ずつ実行し、検査します。

    各関数は「普通の int」でも「Chk」でも動きます(同じコードをそのままブロックに移植できます)。

【Scratch への移植時の注意】
    floor(a / 2^k) は 2 の冪での除算なので double でも厳密です(ここでは // と書いています)。
    Scratch の mod は「符号が除数側の mod(floored mod)」で Python の % と同じ意味です。
"""

LIMIT = 2 ** 53          # double が整数を厳密に表せる上限
OPCOUNT = 0              # Chk 経由の演算回数(ブロック数の見積り用)
MAXSEEN = 0              # Chk 経由で観測した最大の絶対値


def _w(v):
    global OPCOUNT, MAXSEEN
    OPCOUNT += 1
    a = -v if v < 0 else v
    if a >= LIMIT:
        raise OverflowError("intermediate value >= 2^53: Scratch(double) cannot hold it exactly")
    if a > MAXSEEN:
        MAXSEEN = a
    return Chk(v)


def _no_bitwise(*_a, **_k):
    raise TypeError("Scratch has no bitwise operators")


class Chk(int):
    """2^53 未満チェック付き整数。ビット演算・/・** は禁止。"""
    __slots__ = ()

    def __add__(s, o): return _w(int(s) + int(o))
    __radd__ = __add__
    def __sub__(s, o): return _w(int(s) - int(o))
    def __rsub__(s, o): return _w(int(o) - int(s))
    def __mul__(s, o): return _w(int(s) * int(o))
    __rmul__ = __mul__
    def __floordiv__(s, o): return _w(int(s) // int(o))
    def __rfloordiv__(s, o): return _w(int(o) // int(s))
    def __mod__(s, o): return _w(int(s) % int(o))
    def __rmod__(s, o): return _w(int(o) % int(s))
    def __neg__(s): return _w(-int(s))
    __and__ = __rand__ = __or__ = __ror__ = __xor__ = __rxor__ = _no_bitwise
    __lshift__ = __rlshift__ = __rshift__ = __rrshift__ = __invert__ = _no_bitwise
    __truediv__ = __rtruediv__ = __pow__ = __rpow__ = _no_bitwise


# ------------------------------------------------------------------ bit helpers
def _build_xor4():
    """4bit XOR 表(256要素のリスト)。起動時に Scratch でも算術だけで作れる。"""
    t = []
    for a in range(16):
        for b in range(16):
            r = 0
            for k in range(4):
                bit = ((a // 2 ** k) % 2 + (b // 2 ** k) % 2) % 2
                r += bit * 2 ** k
            t.append(r)
    return t


XOR4 = _build_xor4()            # Scratch: リスト "XOR4" (256個)
P16 = [16 ** k for k in range(8)]
M32 = 2 ** 32


def xor32(a, b):
    """32bit XOR = 4bit ずつ表引き(8回)。"""
    r = 0
    for k in range(8):
        r = r + XOR4[(a // P16[k]) % 16 * 16 + (b // P16[k]) % 16] * P16[k]
    return r


def xor8(a, b):
    return XOR4[a // 16 * 16 + b // 16] * 16 + XOR4[a % 16 * 16 + b % 16]


def rotl32(x, n):
    return (x * 2 ** n) % M32 + x // 2 ** (32 - n)


def le32(b, i):
    return b[i] + b[i + 1] * 256 + b[i + 2] * 65536 + b[i + 3] * 16777216


def put_le32(w):
    return [w % 256, w // 256 % 256, w // 65536 % 256, w // 16777216 % 256]


def use_checked():
    """定数表を Chk に差し替え、以降の全演算を 2^53 検査・ビット演算禁止の対象にする(監査用)。"""
    global XOR4, P16, M32, _SIGMA, _MINUSP, _121665
    XOR4 = [Chk(v) for v in XOR4]
    P16 = [Chk(v) for v in P16]
    M32 = Chk(M32)
    _SIGMA = [Chk(v) for v in _SIGMA]
    _MINUSP = [Chk(v) for v in _MINUSP]
    _121665 = [Chk(v) for v in _121665]


# ------------------------------------------------------------------ ChaCha20
_SIGMA = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]


def _qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) % M32; s[d] = rotl32(xor32(s[d], s[a]), 16)
    s[c] = (s[c] + s[d]) % M32; s[b] = rotl32(xor32(s[b], s[c]), 12)
    s[a] = (s[a] + s[b]) % M32; s[d] = rotl32(xor32(s[d], s[a]), 8)
    s[c] = (s[c] + s[d]) % M32; s[b] = rotl32(xor32(s[b], s[c]), 7)


def _rounds(s):
    for _ in range(10):
        _qr(s, 0, 4, 8, 12); _qr(s, 1, 5, 9, 13); _qr(s, 2, 6, 10, 14); _qr(s, 3, 7, 11, 15)
        _qr(s, 0, 5, 10, 15); _qr(s, 1, 6, 11, 12); _qr(s, 2, 7, 8, 13); _qr(s, 3, 4, 9, 14)


def chacha20_block(key, counter, nonce):
    """key: 32要素, counter: 数値, nonce: 12要素 -> 64要素のキーストリーム"""
    init = list(_SIGMA) + [le32(key, 4 * i) for i in range(8)] + [counter] + \
        [le32(nonce, 4 * i) for i in range(3)]
    s = list(init)
    _rounds(s)
    out = []
    for i in range(16):
        out += put_le32((s[i] + init[i]) % M32)
    return out


def hchacha20(key, nonce16):
    """key: 32要素, nonce16: 16要素 -> 32要素(XChaCha20 の HChaCha20)"""
    s = list(_SIGMA) + [le32(key, 4 * i) for i in range(8)] + [le32(nonce16, 4 * i) for i in range(4)]
    _rounds(s)
    out = []
    for i in (0, 1, 2, 3, 12, 13, 14, 15):
        out += put_le32(s[i])
    return out


def chacha20_xor(key, counter, nonce, data):
    out = []
    n = len(data)
    pos = 0
    while pos < n:
        ks = chacha20_block(key, counter, nonce)
        counter = counter + 1
        for j in range(64):
            if pos >= n:
                break
            out.append(xor8(data[pos], ks[j]))
            pos = pos + 1
    return out


# ------------------------------------------------------------------ Poly1305
_MINUSP = [5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252]   # 2^136 - (2^130 - 5)


def _add1305(h, c):
    u = 0
    out = []
    for j in range(17):
        u = u + h[j] + c[j]
        out.append(u % 256)
        u = u // 256
    return out


def poly1305(key, msg):
    """key: 32要素(r||s), msg: 任意長 -> 16要素のタグ。8bit×17 limb。"""
    r = [0] * 17
    h = [0] * 17
    for j in range(16):
        r[j] = key[j]
    for j in (3, 7, 11, 15):
        r[j] = r[j] % 16                 # & 15
    for j in (4, 8, 12):
        r[j] = r[j] - r[j] % 4           # & 252
    n = len(msg)
    pos = 0
    while n > 0:
        c = [0] * 17
        j = 0
        while j < 16 and j < n:
            c[j] = msg[pos + j]
            j = j + 1
        c[j] = 1
        pos = pos + j
        n = n - j
        h = _add1305(h, c)
        x = []
        for i in range(17):
            acc = 0
            for j in range(17):
                acc = acc + h[j] * (r[i - j] if j <= i else 320 * r[i + 17 - j])   # 2^136 ≡ 320 (mod 2^130-5)
            x.append(acc)
        h = x
        u = 0
        for j in range(16):
            u = u + h[j]
            h[j] = u % 256
            u = u // 256
        u = u + h[16]
        h[16] = u % 4
        u = 5 * (u // 4)
        for j in range(16):
            u = u + h[j]
            h[j] = u % 256
            u = u // 256
        u = u + h[16]
        h[16] = u
    g = list(h)
    h = _add1305(h, _MINUSP)
    if h[16] >= 128:                      # h - p < 0  なので元の h を採用
        h = g
    c = [key[16 + j] for j in range(16)] + [0]
    h = _add1305(h, c)
    return h[:16]


# ------------------------------------------------------------------ AEAD (RFC 8439)
def _pad16(n):
    return [0] * ((16 - n % 16) % 16)


def _le64(n):
    return [n // 256 ** i % 256 for i in range(8)]


def _mac_data(aad, ct):
    return list(aad) + _pad16(len(aad)) + list(ct) + _pad16(len(ct)) + _le64(len(aad)) + _le64(len(ct))


def aead_seal(key, nonce, aad, pt):
    otk = chacha20_block(key, 0, nonce)[:32]
    ct = chacha20_xor(key, 1, nonce, pt)
    return ct + poly1305(otk, _mac_data(aad, ct))


def aead_open(key, nonce, aad, sealed):
    """成功なら平文(list)、失敗なら None。"""
    if len(sealed) < 16:
        return None
    ct, tag = sealed[:-16], sealed[-16:]
    otk = chacha20_block(key, 0, nonce)[:32]
    exp = poly1305(otk, _mac_data(aad, ct))
    diff = 0
    for i in range(16):
        diff = diff + (1 if exp[i] != tag[i] else 0)
    if diff != 0:
        return None
    return chacha20_xor(key, 1, nonce, ct)


# ------------------------------------------------------------------ X25519 (TweetNaCl 方式)
# GF(2^255-19) の元を 16bit × 16 要素のリストで表す。各 limb は 2^53 に十分収まる。
_121665 = [0xdb41, 1] + [0] * 14


def _car(o):
    o = list(o)
    for i in range(16):
        o[i] = o[i] + 65536
        c = o[i] // 65536
        if i < 15:
            o[i + 1] = o[i + 1] + (c - 1)
        else:
            o[0] = o[0] + 38 * (c - 1)
        o[i] = o[i] - c * 65536
    return o


def _A(a, b): return [a[i] + b[i] for i in range(16)]
def _Z(a, b): return [a[i] - b[i] for i in range(16)]


def _M(a, b):
    t = [0] * 31
    for i in range(16):
        ai = a[i]
        for j in range(16):
            t[i + j] = t[i + j] + ai * b[j]
    for i in range(15):
        t[i] = t[i] + 38 * t[i + 16]
    return _car(_car(t[:16]))


def _S(a): return _M(a, a)


def _inv(i):
    c = list(i)
    for a in range(253, -1, -1):
        c = _S(c)
        if a != 2 and a != 4:
            c = _M(c, i)
    return c


def _unpack(n):
    o = [n[2 * i] + n[2 * i + 1] * 256 for i in range(16)]
    o[15] = o[15] % 32768
    return o


def _pack(n):
    t = _car(_car(_car(n)))
    for _ in range(2):
        m = [0] * 16
        m[0] = t[0] - 0xffed
        for i in range(1, 15):
            m[i] = t[i] - 0xffff - (1 if m[i - 1] < 0 else 0)
            m[i - 1] = m[i - 1] % 65536
        m[15] = t[15] - 0x7fff - (1 if m[14] < 0 else 0)
        b = 1 if m[15] < 0 else 0
        m[14] = m[14] % 65536
        if b == 0:
            t = m
    o = []
    for i in range(16):
        o.append(t[i] % 256)
        o.append(t[i] // 256)
    return o


def x25519(scalar, point):
    """scalar: 32要素, point: 32要素(u座標) -> 32要素。Montgomery ladder 255 回。"""
    z = list(scalar)
    z[31] = z[31] % 64 + 64              # (z31 & 127) | 64
    z[0] = z[0] - z[0] % 8               # z0 & 248
    x = _unpack(point)
    zero = [0] * 16
    one = [1] + [0] * 15
    a, b, c, d = list(one), list(x), list(zero), list(one)
    for i in range(254, -1, -1):
        r = (z[i // 8] // 2 ** (i % 8)) % 2
        if r == 1:
            a, b = b, a
            c, d = d, c
        e = _A(a, c); a = _Z(a, c); c = _A(b, d); b = _Z(b, d)
        d = _S(e); f = _S(a)
        a = _M(c, a); c = _M(b, e)
        e = _A(a, c); a = _Z(a, c)
        b = _S(a); c = _Z(d, f)
        a = _M(c, _121665); a = _A(a, d)
        c = _M(c, a); a = _M(d, f)
        d = _M(b, x); b = _S(e)
        if r == 1:
            a, b = b, a
            c, d = d, c
    return _pack(_M(a, _inv(c)))


BASEPOINT = [9] + [0] * 31


def x25519_base(scalar):
    return x25519(scalar, BASEPOINT)
