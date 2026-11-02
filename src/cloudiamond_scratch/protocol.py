"""Frame / cloud-variable encoding (shared with the Scratch client).

Cloud variables only hold digit strings of at most 256 characters, so a binary *frame*
is split into *slots* of 84 bytes. One byte becomes three decimal digits and a leading
``1`` keeps the number from losing leading zeros: ``"1" + "%03d" * n`` (253 digits).
A frame is up to 4 slots (336 bytes). A header variable (``HDR``) is written *after* the
slots; its value changes on every write and tells the reader "the slots are complete":

    HDR = 100_000_000 + (seq % 1_000_000) * 100 + slot_count
"""
from __future__ import annotations

SLOT_BYTES = 84
MAX_SLOTS = 4
MAX_FRAME = SLOT_BYTES * MAX_SLOTS          # 336
TAG_LEN = 16
HEADER_LEN = 15                              # sid(8) | type(1) | ctr(6)
BLOCK = 32                                   # plaintext padding unit
# The padded plaintext is a multiple of 32 bytes and starts with a 2-byte length, so the
# largest padded block is 288 bytes (frame = 15 + 288 + 16 = 319 <= 336) -> 286 data bytes.
MAX_PADDED = ((MAX_FRAME - HEADER_LEN - TAG_LEN) // BLOCK) * BLOCK   # 288
MAX_MESSAGE = MAX_PADDED - 2                                          # 286

SID_LEN = 8
T_HELLO, T_REPLY, T_C2S, T_S2C = 1, 2, 3, 4
HELLO_LEN = SID_LEN + 1 + 32                 # 41
REPLY_LEN = SID_LEN + 1 + 32 + 16 + TAG_LEN  # 73
CTR_MAX = (1 << 48) - 1

VAR_C2S_HDR = "C2S_HDR"
VAR_S2C_HDR = "S2C_HDR"
VAR_C2S = tuple(f"C2S_{i}" for i in range(MAX_SLOTS))
VAR_S2C = tuple(f"S2C_{i}" for i in range(MAX_SLOTS))
CLOUD_VARIABLES = (VAR_C2S_HDR, *VAR_C2S, VAR_S2C_HDR, *VAR_S2C)
CLOUD_PREFIX = "\u2601 "                      # "☁ "

HDR_BASE = 100_000_000


def encode_slot(chunk: bytes) -> str:
    if len(chunk) > SLOT_BYTES:
        raise ValueError("slot too large")
    return "1" + "".join(f"{b:03d}" for b in chunk)


def decode_slot(text: object) -> bytes | None:
    """Digit string -> bytes, or ``None`` if it is not a well-formed slot."""
    s = text if isinstance(text, str) else (str(int(text)) if isinstance(text, (int, float)) and not isinstance(text, bool) else None)
    if s is None or not s.isascii() or not s.isdigit() or s[0] != "1":
        return None
    body = s[1:]
    if len(body) % 3 or len(body) // 3 > SLOT_BYTES:
        return None
    out = bytearray()
    for i in range(0, len(body), 3):
        v = int(body[i:i + 3])
        if v > 255:
            return None
        out.append(v)
    return bytes(out)


def frame_to_slots(frame: bytes) -> list[str]:
    if not 1 <= len(frame) <= MAX_FRAME:
        raise ValueError(f"frame must be 1..{MAX_FRAME} bytes")
    return [encode_slot(frame[i:i + SLOT_BYTES]) for i in range(0, len(frame), SLOT_BYTES)]


def slots_to_frame(slots: list[object]) -> bytes | None:
    if not 1 <= len(slots) <= MAX_SLOTS:
        return None
    out = bytearray()
    for s in slots:
        b = decode_slot(s)
        if b is None:
            return None
        out += b
    return bytes(out) if out else None


def make_hdr(seq: int, n_slots: int) -> int:
    if not 1 <= n_slots <= MAX_SLOTS:
        raise ValueError("bad slot count")
    return HDR_BASE + (seq % 1_000_000) * 100 + n_slots


def parse_hdr(value: object) -> tuple[int, int] | None:
    """``HDR`` value -> ``(seq, slot_count)`` or ``None`` if malformed."""
    try:
        if isinstance(value, bool):
            return None
        v = int(float(value)) if isinstance(value, (int, float)) else int(str(value))
    except (TypeError, ValueError):
        return None
    if not HDR_BASE <= v < 2 * HDR_BASE:
        return None
    n = v % 100
    if not 1 <= n <= MAX_SLOTS:
        return None
    return ((v - HDR_BASE) // 100, n)


def pad_message(data: bytes) -> bytes:
    """``len(2, big endian) | data | zero padding`` up to a multiple of 32 bytes."""
    if len(data) > MAX_MESSAGE:
        raise ValueError(f"message too long ({len(data)} > {MAX_MESSAGE} bytes)")
    raw = len(data).to_bytes(2, "big") + data
    return raw + b"\0" * (-len(raw) % BLOCK)


def unpad_message(padded: bytes) -> bytes | None:
    if len(padded) < BLOCK or len(padded) % BLOCK:
        return None
    n = int.from_bytes(padded[:2], "big")
    if 2 + n > len(padded):
        return None
    return padded[2:2 + n]


def data_nonce(ctr: int) -> bytes:
    """12-byte AEAD nonce for a data frame: 6 zero bytes || counter (6 bytes, big endian)."""
    return b"\0" * 6 + ctr.to_bytes(6, "big")
