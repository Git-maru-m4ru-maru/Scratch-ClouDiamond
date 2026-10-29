"""Text <-> bytes table shared with the Scratch client (``TXT_CHARS`` / ``TXT_CODES`` lists).

The client turns each character into ONE byte with a lookup table, because Scratch has no
character-code function. Two Scratch quirks shape the table:

* Scratch compares strings **case-insensitively**, so ``A`` and ``a`` cannot be told apart:
  uppercase letters are sent as lowercase. (Hiragana / katakana have no case, so they are fine.)
* Anything not in the table is sent as ``?``.

The first 69 entries (ASCII, lowercase only) are identical to v0.1, so ASCII text is unchanged.
v1.0.0 adds hiragana, katakana and Japanese punctuation, using the remaining byte values.
"""
from __future__ import annotations

__all__ = ["TABLE", "CHARS", "CODES", "encode", "decode", "to_scratch_text", "is_sendable"]

_ASCII = (
    [chr(c) for c in range(32, 65)]            # ' ' .. '@'   (digits, punctuation)
    + [chr(c) for c in range(91, 97)]          # [ \ ] ^ _ `
    + [chr(c) for c in range(97, 123)]         # a .. z
    + [chr(c) for c in range(123, 127)]        # { | } ~
)
_HIRAGANA = [chr(c) for c in range(0x3041, 0x3094)]            # ぁ .. ん (83)
_KATAKANA = [chr(c) for c in range(0x30A1, 0x30F7)]            # ァ .. ヶ (86)
_JA_PUNCT = ["ー", "、", "。", "「", "」", "・", "！", "？"]

_EXTRA = _HIRAGANA + _JA_PUNCT + _KATAKANA
# byte values not used by ASCII: 128..255 first, then 65..90 (unused uppercase slots), then 1..31
_FREE = list(range(128, 256)) + list(range(65, 91)) + list(range(1, 32))

TABLE: dict[str, int] = {ch: ord(ch) for ch in _ASCII}
TABLE.update({ch: code for ch, code in zip(_EXTRA, _FREE)})
assert len(_EXTRA) <= len(_FREE) and len(set(TABLE.values())) == len(TABLE)

CHARS: list[str] = list(TABLE)            # order = order of the Scratch list TXT_CHARS
CODES: list[int] = [TABLE[c] for c in CHARS]
_REV: dict[int, str] = {v: k for k, v in TABLE.items()}


def to_scratch_text(s: str) -> str:
    """What Scratch will actually show/send for ``s``: lowercase, unsupported characters -> ``?``."""
    return "".join(c if c in TABLE else ("?" if c.lower() not in TABLE else c.lower()) for c in s)


def is_sendable(s: str) -> bool:
    """True if ``s`` survives a trip through the Scratch table unchanged."""
    return all(c in TABLE for c in s)


def encode(s: str) -> bytes:
    """Text -> bytes using the Scratch table (lowercases; unsupported characters become ``?``)."""
    return bytes(TABLE[c] for c in to_scratch_text(s))


def decode(b: bytes) -> str:
    """Bytes -> text using the Scratch table (unknown byte values become ``?``)."""
    return "".join(_REV.get(x, "?") for x in b)
