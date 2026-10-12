"""
program.py -- Scratch クライアント本体(SPy ソース)

このファイルは「普通の Python」としても実行でき(テスト用)、同時に Scratch のブロックへコンパイルされる。
プロトコルの設計は cloudiamond_scratch.server と README を参照。実装しているもの:
    ChaCha20 / HChaCha20 / Poly1305 / AEAD / X25519 / ハンドシェイク / フレーム化 / クラウド変数の入出力

数値の約束: すべての整数演算の結果は 2^53 未満(Scratch の double で厳密)。ビット演算は使わない。
(tests/test_program_py.py が Python 実行で全関数を標準実装と照合し、
 tests/test_program_vm.py が本物の Scratch VM 上でも同じ結果になることを確かめる)
"""
from cloudiamond_scratch.scratch.spyrt import *

# ====================================================================== 定数・テーブル
M32 = 4294967296
SIGMA0 = 1634760805
SIGMA1 = 857760878
SIGMA2 = 2036477234
SIGMA3 = 1797285236
R_A = 0
R_B = 16
R_C = 32
R_D = 48
R_E = 64
R_F = 80
R_X = 96
R_I = 112

# 4bit XOR 表(Scratch にはビット演算が無いので表引きで代用)
XOR4 = Lst([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14, 2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13, 3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12, 4, 5, 6, 7, 0, 1, 2, 3, 12, 13, 14, 15, 8, 9, 10, 11, 5, 4, 7, 6, 1, 0, 3, 2, 13, 12, 15, 14, 9, 8, 11, 10, 6, 7, 4, 5, 2, 3, 0, 1, 14, 15, 12, 13, 10, 11, 8, 9, 7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 9, 8, 11, 10, 13, 12, 15, 14, 1, 0, 3, 2, 5, 4, 7, 6, 10, 11, 8, 9, 14, 15, 12, 13, 2, 3, 0, 1, 6, 7, 4, 5, 11, 10, 9, 8, 15, 14, 13, 12, 3, 2, 1, 0, 7, 6, 5, 4, 12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3, 13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2, 14, 15, 12, 13, 10, 11, 8, 9, 6, 7, 4, 5, 2, 3, 0, 1, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0])
BITP = Lst([1, 2, 4, 8, 16, 32, 64, 128])
DIGITS = Lst([0, 1, 2, 3, 4, 5, 6, 7, 8, 9])
# テキスト <-> バイト変換表(Scratch の比較は大文字小文字を区別しないので小文字のみ)
TXT_CHARS = Lst([' ', '!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '_', '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~'])
TXT_CODES = Lst([32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126])
LBL_MASTER = Lst([83, 67, 82, 83, 69, 67, 49, 45, 109, 97, 115, 116, 101, 114, 0, 0])
LBL_C2S = Lst([83, 67, 82, 83, 69, 67, 49, 45, 99, 50, 115, 0, 0, 0, 0, 0])
LBL_S2C = Lst([83, 67, 82, 83, 69, 67, 49, 45, 115, 50, 99, 0, 0, 0, 0, 0])
READYB = Lst([83, 67, 82, 83, 69, 67, 49, 45, 82, 69, 65, 68, 89, 0, 0, 0])

# ====================================================================== 作業用リスト(秘密を含むものは ss_wipe で消す)
ST = Lst(16)
INI = Lst(16)
CCK = Lst(32)
CCN = Lst(12)
CCO = Lst(64)
HCK = Lst(32)
HCN = Lst(16)
HCO = Lst(32)
PKEY = Lst(32)
PMSG = Lst(400)
PTAG = Lst(16)
PR = Lst(17)
PH = Lst(17)
PC = Lst(17)
PX = Lst(17)
PG = Lst(17)
AK = Lst(32)
AN = Lst(12)
AAD = Lst(80)
BUF = Lst(320)
TAGIN = Lst(16)
ATAG = Lst(16)
GFM = Lst(256)
XK = Lst(32)
XU = Lst(32)
XOUT = Lst(32)
ZK = Lst(32)
PT = Lst(16)
PM = Lst(16)
MA = Vars(16)
MB = Vars(16)
MT = Vars(31)
SRV = Lst(32)
EK = Lst(32)
EP = Lst(32)
RP = Lst(32)
SID = Lst(8)
DHES = Lst(32)
DHEE = Lst(32)
MASTER = Lst(32)
KC2S = Lst(32)
KS2C = Lst(32)
TXF = Lst(344)
RXF = Lst(344)

# 利用者が使うリスト・変数(Scratch 上の表示名つき)
SS_TX = Lst(0, "🔒 TX bytes")
SS_RX = Lst(0, "🔒 RX bytes")
SS_READY = Var(0, "🔒 connected")
SS_STATUS = Var("idle", "🔒 status")
SS_TEXT = Var("", "🔒 received text")
SS_GOT = Var(0, "🔒 got message")

# 内部状態
PLEN = Var(0)
AADL = Var(0)
BUFL = Var(0)
AOK = Var(0)
TXL = Var(0)
RXL = Var(0)
RXOK = Var(0)
SLOTOK = Var(0)
SS_TRIES = Var(0)
SS_HAVE_DHES = Var(0)
SS_SENDCTR = Var(0)
SS_RECVLAST = Var(0)
SS_SEQ = Var(0)
SS_SEEN = Var(0)
SS_RXOK = Var(0)

# クラウド変数(Scratch の上限は 1 プロジェクト 10 個: HDR + 4 slot を 2 方向)
CLOUD_C2S_HDR = Cloud("☁ C2S_HDR")
CLOUD_C2S_0 = Cloud("☁ C2S_0")
CLOUD_C2S_1 = Cloud("☁ C2S_1")
CLOUD_C2S_2 = Cloud("☁ C2S_2")
CLOUD_C2S_3 = Cloud("☁ C2S_3")
CLOUD_S2C_HDR = Cloud("☁ S2C_HDR")
CLOUD_S2C_0 = Cloud("☁ S2C_0")
CLOUD_S2C_1 = Cloud("☁ S2C_1")
CLOUD_S2C_2 = Cloud("☁ S2C_2")
CLOUD_S2C_3 = Cloud("☁ S2C_3")


# ====================================================================== ビット演算の代用品
def xor32(a, b):
    r = 0
    for k in unroll(8):
        r = r + XOR4[a // 16 ** k % 16 * 16 + b // 16 ** k % 16] * 16 ** k
    return r


def xor8(a, b):
    return XOR4[a // 16 * 16 + b // 16] * 16 + XOR4[a % 16 * 16 + b % 16]


# ====================================================================== ChaCha20 / HChaCha20
def qr(ia, ib, ic, id_):
    a = ST[ia]
    b = ST[ib]
    c = ST[ic]
    d = ST[id_]
    a = (a + b) % M32
    d = xor32(d, a)
    d = d * 65536 % M32 + d // 65536
    c = (c + d) % M32
    b = xor32(b, c)
    b = b * 4096 % M32 + b // 1048576
    a = (a + b) % M32
    d = xor32(d, a)
    d = d * 256 % M32 + d // 16777216
    c = (c + d) % M32
    b = xor32(b, c)
    b = b * 128 % M32 + b // 33554432
    ST[ia] = a
    ST[ib] = b
    ST[ic] = c
    ST[id_] = d


def chacha_rounds():
    for rnd in range(10):
        qr(0, 4, 8, 12)
        qr(1, 5, 9, 13)
        qr(2, 6, 10, 14)
        qr(3, 7, 11, 15)
        qr(0, 5, 10, 15)
        qr(1, 6, 11, 12)
        qr(2, 7, 8, 13)
        qr(3, 4, 9, 14)


def hchacha20():
    """HCK(32 byte) + HCN(16 byte) -> HCO(32 byte)"""
    ST[0] = SIGMA0
    ST[1] = SIGMA1
    ST[2] = SIGMA2
    ST[3] = SIGMA3
    for i in unroll(8):
        ST[4 + i] = HCK[4 * i] + HCK[4 * i + 1] * 256 + HCK[4 * i + 2] * 65536 + HCK[4 * i + 3] * 16777216
    for i in unroll(4):
        ST[12 + i] = HCN[4 * i] + HCN[4 * i + 1] * 256 + HCN[4 * i + 2] * 65536 + HCN[4 * i + 3] * 16777216
    chacha_rounds()
    for i in unroll(4):
        w = ST[i]
        HCO[4 * i] = w % 256
        HCO[4 * i + 1] = w // 256 % 256
        HCO[4 * i + 2] = w // 65536 % 256
        HCO[4 * i + 3] = w // 16777216 % 256
    for i in unroll(4):
        w = ST[12 + i]
        HCO[16 + 4 * i] = w % 256
        HCO[17 + 4 * i] = w // 256 % 256
        HCO[18 + 4 * i] = w // 65536 % 256
        HCO[19 + 4 * i] = w // 16777216 % 256


def chacha_block(counter):
    """CCK(32) + counter + CCN(12) -> CCO(64)"""
    ST[0] = SIGMA0
    ST[1] = SIGMA1
    ST[2] = SIGMA2
    ST[3] = SIGMA3
    for i in unroll(8):
        ST[4 + i] = CCK[4 * i] + CCK[4 * i + 1] * 256 + CCK[4 * i + 2] * 65536 + CCK[4 * i + 3] * 16777216
    ST[12] = counter
    for i in unroll(3):
        ST[13 + i] = CCN[4 * i] + CCN[4 * i + 1] * 256 + CCN[4 * i + 2] * 65536 + CCN[4 * i + 3] * 16777216
    for i in unroll(16):
        INI[i] = ST[i]
    chacha_rounds()
    for i in unroll(16):
        w = (ST[i] + INI[i]) % M32
        CCO[4 * i] = w % 256
        CCO[4 * i + 1] = w // 256 % 256
        CCO[4 * i + 2] = w // 65536 % 256
        CCO[4 * i + 3] = w // 16777216 % 256


def chacha_xor(counter):
    """BUF[0..BUFL) を CCK/CCN のキーストリームと XOR(その場で)"""
    c = counter
    pos = 0
    while pos < BUFL:
        chacha_block(c)
        m = BUFL - pos
        if m > 64:
            m = 64
        for j in range(m):
            BUF[pos + j] = xor8(BUF[pos + j], CCO[j])
        pos += 64
        c += 1


# ====================================================================== Poly1305 (8bit x 17 limb)
def p_add():
    u = 0
    for j in range(17):
        u = u + PH[j] + PC[j]
        PH[j] = u % 256
        u = u // 256


def poly1305():
    """PKEY(32) + PMSG[0..PLEN) -> PTAG(16)"""
    for j in range(17):
        PR[j] = 0
        PH[j] = 0
    for j in range(16):
        PR[j] = PKEY[j]
    PR[3] = PR[3] % 16
    PR[7] = PR[7] % 16
    PR[11] = PR[11] % 16
    PR[15] = PR[15] % 16
    PR[4] = PR[4] - PR[4] % 4
    PR[8] = PR[8] - PR[8] % 4
    PR[12] = PR[12] - PR[12] % 4
    pos = 0
    n = PLEN
    while n > 0:
        for j in range(17):
            PC[j] = 0
        m = 16
        if n < 16:
            m = n
        for j in range(m):
            PC[j] = PMSG[pos + j]
        PC[m] = 1
        pos += m
        n -= m
        p_add()
        for i in range(17):
            acc = 0
            for j in range(17):
                if j > i:
                    acc = acc + PH[j] * (320 * PR[i + 17 - j])
                else:
                    acc = acc + PH[j] * PR[i - j]
            PX[i] = acc
        for i in range(17):
            PH[i] = PX[i]
        u = 0
        for j in range(16):
            u = u + PH[j]
            PH[j] = u % 256
            u = u // 256
        u = u + PH[16]
        PH[16] = u % 4
        u = 5 * (u // 4)
        for j in range(16):
            u = u + PH[j]
            PH[j] = u % 256
            u = u // 256
        u = u + PH[16]
        PH[16] = u
    for j in range(17):
        PG[j] = PH[j]
        PC[j] = 0
    PC[0] = 5
    PC[16] = 252
    p_add()
    if PH[16] > 127:
        for j in range(17):
            PH[j] = PG[j]
    for j in range(16):
        PC[j] = PKEY[16 + j]
    PC[16] = 0
    p_add()
    for j in range(16):
        PTAG[j] = PH[j]


# ====================================================================== AEAD (RFC 8439 ChaCha20-Poly1305)
def aead_mac(ctlen):
    """AAD[0..AADL) と BUF[0..ctlen)(暗号文)から PMSG を組み、PKEY で Poly1305"""
    global PLEN
    n = 0
    for i in range(AADL):
        PMSG[n] = AAD[i]
        n += 1
    while n % 16 != 0:
        PMSG[n] = 0
        n += 1
    for i in range(ctlen):
        PMSG[n] = BUF[i]
        n += 1
    while n % 16 != 0:
        PMSG[n] = 0
        n += 1
    for i in unroll(8):
        PMSG[n + i] = AADL // 256 ** i % 256
    n += 8
    for i in unroll(8):
        PMSG[n + i] = ctlen // 256 ** i % 256
    n += 8
    PLEN = n
    poly1305()


def aead_keys():
    for i in range(32):
        CCK[i] = AK[i]
    for i in range(12):
        CCN[i] = AN[i]
    chacha_block(0)
    for i in range(32):
        PKEY[i] = CCO[i]


def aead_seal():
    """AK / AN / AAD(AADL) / BUF(BUFL: 平文 -> 暗号文) -> ATAG"""
    aead_keys()
    chacha_xor(1)
    aead_mac(BUFL)
    for i in range(16):
        ATAG[i] = PTAG[i]


def aead_open():
    """AK / AN / AAD(AADL) / BUF(BUFL: 暗号文) / TAGIN -> 検証成功なら AOK=1 かつ BUF が平文"""
    global AOK
    aead_keys()
    aead_mac(BUFL)
    diff = 0
    for i in range(16):
        if PTAG[i] != TAGIN[i]:
            diff += 1
    AOK = 0
    if diff == 0:
        chacha_xor(1)
        AOK = 1


# ====================================================================== X25519 (16bit x 16 limb, TweetNaCl 方式)
def gf_car():
    for i in unroll(16):
        MT[i] = MT[i] + 65536
        cc = MT[i] // 65536
        if i < 15:
            MT[i + 1] = MT[i + 1] + (cc - 1)
        else:
            MT[0] = MT[0] + 38 * (cc - 1)
        MT[i] = MT[i] - cc * 65536


def gf_mul(o, a, b):
    for i in unroll(16):
        MA[i] = GFM[a + i]
        MB[i] = GFM[b + i]
    for i in unroll(16):
        for j in unroll(16):
            if i == 0 or j == 15:
                MT[i + j] = MA[i] * MB[j]
            else:
                MT[i + j] = MT[i + j] + MA[i] * MB[j]
    for k in unroll(15):
        MT[k] = MT[k] + 38 * MT[k + 16]
    gf_car()
    gf_car()
    for i in unroll(16):
        GFM[o + i] = MT[i]


def gf_scale(o, a):
    for i in unroll(16):
        MT[i] = GFM[a + i] * 121665
    gf_car()
    gf_car()
    for i in unroll(16):
        GFM[o + i] = MT[i]


def gf_add(o, a, b):
    for i in unroll(16):
        GFM[o + i] = GFM[a + i] + GFM[b + i]


def gf_sub(o, a, b):
    for i in unroll(16):
        GFM[o + i] = GFM[a + i] - GFM[b + i]


def gf_pack(o):
    """GFM[o..o+15] を正規化して XOUT(32 byte) へ"""
    for i in unroll(16):
        MT[i] = GFM[o + i]
    gf_car()
    gf_car()
    gf_car()
    for i in unroll(16):
        PT[i] = MT[i]
    for rep in range(2):
        PM[0] = PT[0] - 65517
        for i in range(1, 15):
            bw = 0
            if PM[i - 1] < 0:
                bw = 1
            PM[i] = PT[i] - 65535 - bw
            PM[i - 1] = PM[i - 1] % 65536
        bw = 0
        if PM[14] < 0:
            bw = 1
        PM[15] = PT[15] - 32767 - bw
        b = 0
        if PM[15] < 0:
            b = 1
        PM[14] = PM[14] % 65536
        if b == 0:
            for i in range(16):
                PT[i] = PM[i]
    for i in range(16):
        XOUT[2 * i] = PT[i] % 256
        XOUT[2 * i + 1] = PT[i] // 256


def x25519():
    """XK(32 byte のスカラー) と XU(32 byte の点) -> XOUT(32 byte)"""
    for i in range(32):
        ZK[i] = XK[i]
    ZK[31] = ZK[31] % 64 + 64
    ZK[0] = ZK[0] - ZK[0] % 8
    for i in unroll(16):
        GFM[R_X + i] = XU[2 * i] + XU[2 * i + 1] * 256
    GFM[R_X + 15] = GFM[R_X + 15] % 32768
    for i in unroll(16):
        GFM[R_A + i] = 0
        GFM[R_B + i] = GFM[R_X + i]
        GFM[R_C + i] = 0
        GFM[R_D + i] = 0
    GFM[R_A] = 1
    GFM[R_D] = 1
    ra = R_A
    rb = R_B
    rc = R_C
    rd = R_D
    prev = 0
    for step in range(255):
        i = 254 - step
        r = ZK[i // 8] // BITP[i % 8] % 2
        if r != prev:
            t = ra
            ra = rb
            rb = t
            t = rc
            rc = rd
            rd = t
            prev = r
        gf_add(R_E, ra, rc)
        gf_sub(ra, ra, rc)
        gf_add(rc, rb, rd)
        gf_sub(rb, rb, rd)
        gf_mul(rd, R_E, R_E)
        gf_mul(R_F, ra, ra)
        gf_mul(ra, rc, ra)
        gf_mul(rc, rb, R_E)
        gf_add(R_E, ra, rc)
        gf_sub(ra, ra, rc)
        gf_mul(rb, ra, ra)
        gf_sub(rc, rd, R_F)
        gf_scale(ra, rc)
        gf_add(ra, ra, rd)
        gf_mul(rc, rc, ra)
        gf_mul(ra, rd, R_F)
        gf_mul(rd, rb, R_X)
        gf_mul(rb, R_E, R_E)
    if prev == 1:
        t = ra
        ra = rb
        rb = t
        t = rc
        rc = rd
        rd = t
    for i in unroll(16):
        GFM[R_I + i] = GFM[rc + i]
    for k in range(254):
        e = 253 - k
        gf_mul(R_I, R_I, R_I)
        if e != 2 and e != 4:
            gf_mul(R_I, R_I, rc)
    gf_mul(ra, ra, R_I)
    gf_pack(ra)


def x25519_base():
    XU[0] = 9
    for i in range(1, 32):
        XU[i] = 0
    x25519()


# ====================================================================== クラウド変数 <-> フレーム
def slot_string(k):
    """TXF[k*84 .. ) を '1' + 3 桁/byte の数字列にする"""
    s = "1"
    j = k * 84
    e = j + 84
    if e > TXL:
        e = TXL
    while j < e:
        b = TXF[j]
        s = join(s, join(b // 100, join(b // 10 % 10, b % 10)))
        j += 1
    return s


@nowarp
def ss_send_frame():
    """TXF[0..TXL) を C2S の slot に書き、最後に HDR を書く(HDR の変化 = 全 slot が揃った合図)"""
    global SS_SEQ, CLOUD_C2S_0, CLOUD_C2S_1, CLOUD_C2S_2, CLOUD_C2S_3, CLOUD_C2S_HDR
    n = 0
    left = TXL
    while left > 0:
        n += 1
        left -= 84
    for k in range(n):
        s = slot_string(k)
        if k == 0:
            CLOUD_C2S_0 = s
        if k == 1:
            CLOUD_C2S_1 = s
        if k == 2:
            CLOUD_C2S_2 = s
        if k == 3:
            CLOUD_C2S_3 = s
        wait(0.12)
    SS_SEQ += 1
    CLOUD_C2S_HDR = 100000000 + SS_SEQ % 1000000 * 100 + n


def parse_slot(s):
    global RXL, SLOTOK
    ln = length_of(s)
    m = (ln - 1) // 3
    if letter_of(1, s) != 1 or (ln - 1) % 3 != 0 or m > 85:
        SLOTOK = 0
        m = 0
    j = 0
    while j < m:
        # Scratch は "a" * 100 を黙って 0 にするので、数字かどうかを明示的に確かめる(1 始まりの位置 = 数字 + 1)
        a = list_index_of(DIGITS, letter_of(2 + 3 * j, s))
        b = list_index_of(DIGITS, letter_of(3 + 3 * j, s))
        c = list_index_of(DIGITS, letter_of(4 + 3 * j, s))
        v = a * 100 + b * 10 + c - 111
        if a == 0 or b == 0 or c == 0 or v > 255:
            SLOTOK = 0
            v = 0
        RXF[RXL] = v
        RXL += 1
        j += 1


def ss_read_frame():
    """S2C の HDR/slot -> RXF[0..RXL)。成功なら RXOK=1"""
    global RXL, RXOK, SLOTOK
    RXL = 0
    RXOK = 0
    SLOTOK = 1
    n = CLOUD_S2C_HDR % 100
    if n >= 1 and n <= 4:
        for k in range(n):
            s = ""
            if k == 0:
                s = CLOUD_S2C_0
            if k == 1:
                s = CLOUD_S2C_1
            if k == 2:
                s = CLOUD_S2C_2
            if k == 3:
                s = CLOUD_S2C_3
            parse_slot(s)
        RXOK = SLOTOK


# ====================================================================== プロトコル
def ss_reset_state():
    global SS_READY, SS_TRIES, SS_HAVE_DHES, SS_SENDCTR, SS_RECVLAST, SS_GOT
    SS_READY = 0
    SS_TRIES = 0
    SS_HAVE_DHES = 0
    SS_SENDCTR = 0
    SS_RECVLAST = 0
    SS_GOT = 0


def ss_seed_random():
    for i in range(32):
        EK[i] = rand_int(0, 255)


def ss_mix_sample():
    """乱数プールに 1 サンプル(マウス・時刻・乱数)を HChaCha20 で混ぜる"""
    HCN[0] = (mouse_x() + 256) % 256
    HCN[1] = (mouse_y() + 256) % 256
    t = timer() * 1000000
    HCN[2] = t // 1 % 256
    HCN[3] = t // 256 % 256
    HCN[4] = t // 65536 % 256
    d = days_since_2000() * 100000000000
    HCN[5] = d // 1 % 256
    HCN[6] = d // 256 % 256
    HCN[7] = d // 65536 % 256
    HCN[8] = d // 16777216 % 256
    for i in range(9, 16):
        HCN[i] = rand_int(0, 255)
    for i in range(32):
        HCK[i] = EK[i]
    hchacha20()
    for i in range(32):
        EK[i] = HCO[i]


@nowarp
def ss_gather():
    global SS_STATUS
    SS_STATUS = "gathering randomness: move the mouse"
    say(SS_STATUS)
    ss_seed_random()
    reset_timer()
    n = 0
    while n < 90:
        ss_mix_sample()
        wait(0.03)
        n += 1


def ss_make_hello():
    global TXL
    for i in range(32):
        XK[i] = EK[i]
    x25519_base()
    for i in range(32):
        EP[i] = XOUT[i]
    for i in range(8):
        SID[i] = EP[i]
        TXF[i] = EP[i]
    TXF[8] = 1
    for i in range(32):
        TXF[9 + i] = EP[i]
    TXL = 41


def ss_clear_handshake():
    """ハンドシェイクで使った秘密(e・DH 結果・master)を消す。使い終わったら残さない"""
    for i in range(32):
        EK[i] = 0
        DHES[i] = 0
        DHEE[i] = 0
        MASTER[i] = 0
        HCK[i] = 0
        HCO[i] = 0
        XK[i] = 0
        XOUT[i] = 0


def ss_derive_and_verify():
    """RXF の HELLO_REPLY を検証し、成功なら SS_READY=1 と方向別の鍵を確定する"""
    global SS_READY, SS_TRIES, SS_HAVE_DHES, AADL, BUFL
    sidok = 1
    for i in range(8):
        if RXF[i] != SID[i]:
            sidok = 0
    if sidok == 1:
        SS_TRIES += 1
        if SS_HAVE_DHES == 0:
            for i in range(32):
                XK[i] = EK[i]
                XU[i] = SRV[i]
            x25519()
            z = 0
            for i in range(32):
                DHES[i] = XOUT[i]
                z += XOUT[i]
            if z != 0:
                SS_HAVE_DHES = 1
        if SS_HAVE_DHES == 1:
            for i in range(32):
                RP[i] = RXF[9 + i]
                XK[i] = EK[i]
                XU[i] = RXF[9 + i]
            x25519()
            z = 0
            for i in range(32):
                DHEE[i] = XOUT[i]
                z += XOUT[i]
            if z != 0:
                for i in range(32):
                    HCK[i] = DHES[i]
                for i in range(16):
                    HCN[i] = LBL_MASTER[i]
                hchacha20()
                for i in range(16):
                    HCN[i] = HCO[i]
                for i in range(32):
                    HCK[i] = DHEE[i]
                hchacha20()
                for i in range(32):
                    MASTER[i] = HCO[i]
                    HCK[i] = HCO[i]
                for i in range(16):
                    HCN[i] = LBL_C2S[i]
                hchacha20()
                for i in range(32):
                    KC2S[i] = HCO[i]
                    HCK[i] = MASTER[i]
                for i in range(16):
                    HCN[i] = LBL_S2C[i]
                hchacha20()
                for i in range(32):
                    KS2C[i] = HCO[i]
                    AK[i] = HCO[i]
                for i in range(12):
                    AN[i] = 0
                for i in range(8):
                    AAD[i] = SID[i]
                AAD[8] = 2
                for i in range(32):
                    AAD[9 + i] = EP[i]
                    AAD[41 + i] = RP[i]
                AADL = 73
                for i in range(16):
                    BUF[i] = RXF[41 + i]
                    TAGIN[i] = RXF[57 + i]
                BUFL = 16
                aead_open()
                if AOK == 1:
                    same = 1
                    for i in range(16):
                        if BUF[i] != READYB[i]:
                            same = 0
                    SS_READY = same
                    if same == 1:
                        ss_clear_handshake()


def ss_seal():
    """SS_TX を暗号化して TXF にフレームを作る"""
    global SS_SENDCTR, TXL, AADL, BUFL
    n = len(SS_TX)
    BUF[0] = n // 256
    BUF[1] = n % 256
    for i in range(n):
        BUF[2 + i] = SS_TX[i]
    m = 2 + n
    while m % 32 != 0:
        BUF[m] = 0
        m += 1
    BUFL = m
    SS_SENDCTR += 1
    ctr = SS_SENDCTR
    for i in range(8):
        TXF[i] = SID[i]
    TXF[8] = 3
    for i in unroll(6):
        TXF[9 + i] = ctr // 256 ** (5 - i) % 256
    for i in range(15):
        AAD[i] = TXF[i]
    AADL = 15
    for i in range(6):
        AN[i] = 0
    for i in unroll(6):
        AN[6 + i] = ctr // 256 ** (5 - i) % 256
    for i in range(32):
        AK[i] = KC2S[i]
    aead_seal()
    for i in range(BUFL):
        TXF[15 + i] = BUF[i]
    for i in range(16):
        TXF[15 + BUFL + i] = ATAG[i]
    TXL = 31 + BUFL


def ss_open():
    """RXF の DATA フレームを検証・復号して SS_RX に入れる。成功なら SS_RXOK=1"""
    global SS_RXOK, SS_RECVLAST, AADL, BUFL
    SS_RXOK = 0
    if SS_READY == 1 and RXL >= 63 and RXL <= 336 and RXF[8] == 4 and (RXL - 31) % 32 == 0:
        sidok = 1
        for i in range(8):
            if RXF[i] != SID[i]:
                sidok = 0
        ctr = 0
        for i in range(6):
            ctr = ctr * 256 + RXF[9 + i]
        if sidok == 1 and ctr > SS_RECVLAST:
            for i in range(15):
                AAD[i] = RXF[i]
            AADL = 15
            for i in range(6):
                AN[i] = 0
            for i in unroll(6):
                AN[6 + i] = ctr // 256 ** (5 - i) % 256
            for i in range(32):
                AK[i] = KS2C[i]
            BUFL = RXL - 31
            for i in range(BUFL):
                BUF[i] = RXF[15 + i]
            for i in range(16):
                TAGIN[i] = RXF[RXL - 16 + i]
            aead_open()
            if AOK == 1:
                SS_RECVLAST = ctr
                n = BUF[0] * 256 + BUF[1]
                if 2 + n <= BUFL:
                    SS_RX.clear()
                    for i in range(n):
                        SS_RX.append(BUF[2 + i])
                    SS_RXOK = 1


# ====================================================================== テキスト <-> バイト
def ss_text_to_tx(text):
    SS_TX.clear()
    n = length_of(text)
    if n > 286:
        n = 286
    for i in range(n):
        ch = letter_of(i + 1, text)
        idx = list_index_of(TXT_CHARS, ch)
        if idx == 0:
            SS_TX.append(63)
        else:
            SS_TX.append(TXT_CODES[idx - 1])


def ss_rx_to_text():
    global SS_TEXT
    SS_TEXT = ""
    for i in range(len(SS_RX)):
        b = SS_RX[i]
        idx = list_index_of(TXT_CODES, b)
        if idx == 0:
            SS_TEXT = join(SS_TEXT, "?")
        else:
            SS_TEXT = join(SS_TEXT, TXT_CHARS[idx - 1])


# ====================================================================== 利用者向けブロック
@api("🔒 wipe secrets")
def ss_wipe():
    """鍵・乱数・作業領域・受信文をゼロにする(プロジェクトを保存・共有する前に必ず実行)"""
    global SS_READY, SS_STATUS, SS_TEXT
    for i in range(32):
        EK[i] = 0
        EP[i] = 0
        RP[i] = 0
        DHES[i] = 0
        DHEE[i] = 0
        MASTER[i] = 0
        KC2S[i] = 0
        KS2C[i] = 0
        HCK[i] = 0
        HCO[i] = 0
        CCK[i] = 0
        PKEY[i] = 0
        AK[i] = 0
        XK[i] = 0
        XU[i] = 0
        XOUT[i] = 0
        ZK[i] = 0
    for i in range(64):
        CCO[i] = 0
    for i in range(16):
        ST[i] = 0
        INI[i] = 0
        HCN[i] = 0
        PT[i] = 0
        PM[i] = 0
        TAGIN[i] = 0
        ATAG[i] = 0
        PTAG[i] = 0
    for i in range(256):
        GFM[i] = 0
    for i in range(320):
        BUF[i] = 0
    for i in range(344):
        TXF[i] = 0
        RXF[i] = 0
    for i in range(400):
        PMSG[i] = 0
    for i in range(12):
        AN[i] = 0
    for i in range(80):
        AAD[i] = 0
    for i in range(17):
        PR[i] = 0
        PH[i] = 0
        PC[i] = 0
        PX[i] = 0
        PG[i] = 0
    for i in unroll(16):
        MA[i] = 0
        MB[i] = 0
    for i in unroll(31):
        MT[i] = 0
    SS_TX.clear()
    SS_RX.clear()
    SS_READY = 0
    SS_TEXT = ""
    SS_STATUS = "idle"


@api("🔒 disconnect")
def ss_disconnect():
    ss_wipe()


@nowarp
@api("🔒 connect")
def ss_connect():
    """乱数収集 -> 鍵交換 -> サーバー認証。完了すると「🔒 connected」が 1 になる"""
    global SS_STATUS, SS_SEEN, SS_SEQ
    ss_reset_state()
    if SS_SEQ == 0:
        SS_SEQ = rand_int(1, 900000)      # 前回の実行の HDR と偶然一致して「変化なし」と見なされるのを避ける
    ss_gather()
    SS_STATUS = "computing keys (slow, please wait)"
    say(SS_STATUS)
    ss_make_hello()
    SS_SEEN = CLOUD_S2C_HDR
    ss_send_frame()
    SS_STATUS = "waiting for the server"
    say(SS_STATUS)
    t0 = timer()
    while SS_READY == 0 and timer() - t0 < 30 and SS_TRIES < 3:
        wait(0.1)
        if CLOUD_S2C_HDR != SS_SEEN:
            SS_SEEN = CLOUD_S2C_HDR
            ss_read_frame()
            if RXOK == 1 and RXL == 73 and RXF[8] == 2:
                SS_STATUS = "verifying server"
                ss_derive_and_verify()
    if SS_READY == 1:
        SS_STATUS = "connected (server verified)"
    else:
        ss_wipe()                          # 認証できなかった相手向けに作った鍵・乱数を一切残さない
        SS_STATUS = "FAILED: server not verified"
    say(SS_STATUS)


@nowarp
@api("🔒 send TX bytes")
def ss_send():
    if SS_READY == 1:                      # サーバーを認証できていない間は、何も送らない
        ss_seal()
        ss_send_frame()


@nowarp
@api("🔒 send text %s")
def ss_send_text(text):
    ss_text_to_tx(text)
    ss_send()


@nowarp
@api("🔒 wait for message (max %s sec)")
def ss_wait_message(maxsec):
    """メッセージが届くか時間切れまで待つ。届くと「🔒 got message」=1、RX bytes と received text に入る"""
    global SS_GOT, SS_SEEN
    SS_GOT = 0
    t0 = timer()
    while SS_GOT == 0 and timer() - t0 < maxsec:
        wait(0.05)
        if CLOUD_S2C_HDR != SS_SEEN:
            SS_SEEN = CLOUD_S2C_HDR
            ss_read_frame()
            if RXOK == 1:
                ss_open()
                if SS_RXOK == 1:
                    SS_GOT = 1
    if SS_GOT == 1:
        ss_rx_to_text()


@when_flag
def main():
    """デモ: 接続して、入力した文を暗号化して送り、返事を表示する"""
    ss_wipe()
    ss_connect()
    if SS_READY == 1:
        while True:
            ask("message? (lowercase, digits, punctuation)")
            ss_send_text(answer())
            ss_wait_message(60)
            if SS_GOT == 1:
                say(SS_TEXT)
            else:
                say("(no reply)")
    else:
        say("connection failed")
