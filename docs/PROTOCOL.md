# Protocol specification (`SCRSEC1`)

This document describes exactly what goes over the shared cloud variables, so that the design can be reviewed and
other implementations can be written. The reference implementations are `src/cloudiamond_scratch/` (Python) and the
Scratch client blocks in `src/cloudiamond_scratch/data/client_template.json`; **both reproduce the test vectors at the end
of this file** (`tests/test_vectors.py`).

> The composition below (two-stage key derivation + framing) has **not been reviewed by a third party**.
> The primitives are standard. See `SECURITY.md`.

## 1. Goals and threat model

* The Scratch project (all blocks, constants, the embedded server public key) is public. **No secret may live in it.**
* The cloud variables are public: anyone can read every value and write any value at any time.
* Goals: confidentiality and integrity of messages, server authentication, replay protection, forward secrecy against a
  later compromise of the server's long-term key.
* Non-goals: client authentication, availability, hiding traffic metadata (see README).

## 2. Primitives

| Need | Algorithm |
|---|---|
| Key agreement | X25519 (RFC 7748) |
| AEAD | ChaCha20-Poly1305 (RFC 8439), 12-byte nonce, 16-byte tag |
| KDF step | HChaCha20 (draft-irtf-cfrg-xchacha-03 §2.2): 32-byte key + 16-byte input → 32 bytes |

Scratch has no bit operations and no 64-bit integers; the client implements all three with `+ − × floor mod` and lists
only (every intermediate value stays below 2^53). The Python side uses `cryptography` (X25519, ChaCha20-Poly1305) and a
small pure-Python HChaCha20.

## 3. Cloud-variable layer

Exactly ten cloud variables (Scratch's maximum): `☁ C2S_HDR`, `☁ C2S_0..3`, `☁ S2C_HDR`, `☁ S2C_0..3`.

* **Slot** = at most 84 bytes. Encoding: the character `1` followed by each byte as exactly three decimal digits
  (`0` → `000`, `255` → `255`): at most `1 + 3·84 = 253` digits (a cloud variable holds digits only, ≤ 256 characters).
* **Frame** = binary message of 1..336 bytes, cut into consecutive 84-byte slots (the last may be shorter). At most 4 slots.
* **Header (HDR)**: `100000000 + (seq mod 1000000)·100 + n` where `n` (1..4) is the slot count. **All slots are written first,
  then HDR.** A reader acts only when HDR changes, so **HDR must differ from the previous value on every frame**
  (increment `seq`; a restarted writer must also avoid the value still stored in the cloud).
* Direction `C2S` is written by the Scratch client, `S2C` by the server. Writers pace themselves (the Scratch client waits
  0.12 s after each slot it writes; cloud servers rate-limit sets).
* Values a cloud server replays when a reader connects (current state) must not be processed as new frames.

## 4. Frames

`sid` = the first 8 bytes of the client's ephemeral public key `E`. All integers are big-endian.

```
HELLO  (41 B)  sid(8) | 01 | E(32)                                         client → server
REPLY  (73 B)  sid(8) | 02 | R(32) | AEAD(k_s2c, nonce=0^12, aad, READY)    server → client
               aad = sid | 02 | E | R              READY = "SCRSEC1-READY" + 3×00 (16 B) → 16 B ciphertext + 16 B tag
DATA   (63..336 B)  sid(8) | type(1) | ctr(6) | ciphertext(32·k) | tag(16)
               type 03 = client→server, 04 = server→client
               aad   = the 15 header bytes (sid | type | ctr)
               nonce = 00 00 00 00 00 00 | ctr(6)             (12 bytes)
               plaintext = len(2) | message | 00-padding, padded to a multiple of 32 bytes (k ≥ 1, 32·k ≤ 288)
```

* Maximum message: 286 bytes (frame 15 + 288 + 16 = 319 bytes ≤ 336).
* `ctr` starts at 1 and increases by 1 for each frame in a direction; a receiver accepts only `ctr` **greater than** the
  last authenticated `ctr` of that direction and advances its record **only after** the tag verified.
* The READY ciphertext uses nonce `0` with `k_s2c`; data frames use `ctr ≥ 1`, so a (key, nonce) pair is never reused.

## 5. Handshake and keys

```
client: e ← 32 random bytes (one per connection), E = X25519(e, 9)                 sid = E[0:8]
        send HELLO
server: dh_es = X25519(s, E)                      (s = long-term secret, S = X25519(s, 9) is embedded in the client)
        r ← 32 random bytes (one per HELLO), R = X25519(r, 9)    dh_ee = X25519(r, E)
        reject if a shared secret is all zero (low-order point); discard r
        reply with REPLY; keep the session keys
client: dh_es = X25519(e, S)      dh_ee = X25519(e, R)       (reject all-zero)
        verify the AEAD tag of REPLY → only the holder of s can produce it
        connected; wipe e, dh_es, dh_ee, master
```

Key schedule (HChaCha20 is used as a PRF; labels are 16 bytes, zero padded):

```
t       = HChaCha20(key = dh_es, input = "SCRSEC1-master" + 00 00)
master  = HChaCha20(key = dh_ee, input = t[0:16])
k_c2s   = HChaCha20(key = master, input = "SCRSEC1-c2s" + 00×5)
k_s2c   = HChaCha20(key = master, input = "SCRSEC1-s2c" + 00×5)
```

(`SCRSEC1` is the protocol identifier; the name is historical and must not change.)

### Retransmission
The client sends HELLO again every 6 s (at most 3 sends in total) while no valid REPLY has arrived. A server that receives
a HELLO with the **same `E`** for an existing session returns the cached REPLY; with a different `E` but the same `sid` it
ignores the frame (a newcomer can never replace a live session).

### Invalid input
Every invalid frame (bad length, unknown session, replayed or old `ctr`, failed tag, malformed payload) is **dropped without
any reply**. The server counts drops (`SecureServer.stats`).

## 6. Properties and reasoning

* **Server authentication:** `dh_es` needs `s`; without it the READY tag cannot be produced for the client's `e`.
  An all-zero or low-order `R` is rejected.
* **Forward secrecy:** `dh_ee` needs `e` or `r`, both destroyed after the handshake. Leaking `s` later lets an attacker
  impersonate the server but not decrypt recorded sessions.
* **Replay / reflection:** strictly increasing per-direction counters; separate keys per direction; the type byte is
  authenticated as part of the AAD.
* **Why a two-stage KDF:** XOR-combining `dh_es` and `dh_ee` collapses when `R = S`. Chaining `dh_es → dh_ee` through
  HChaCha20 keeps `master` unpredictable if either input is secret. A standard HKDF-SHA256 would be preferable; porting
  SHA-256 to Scratch was judged too expensive.
* **Length hiding:** plaintext padded to 32-byte blocks (lengths still leak at that granularity).
* **Session identifiers** are public and not guaranteed unique (64 bits of a public key); a collision is treated as invalid.

## 7. The Scratch text table

The Scratch client turns text into bytes with a lookup (`TXT_CHARS` → `TXT_CODES`), one byte per character:

* 69 ASCII entries: space … `@`, `[ \ ] ^ _ \``, `a`…`z`, `{ | } ~` with their ASCII codes (identical to v0.1).
  **No uppercase:** Scratch compares strings case-insensitively, so `A` and `a` cannot be distinguished; uppercase is sent as lowercase.
* v1.0.0 adds hiragana `ぁ…ん` (83), `ー 、 。 「 」 ・ ！ ？` (8) and katakana `ァ…ヶ` (86), assigned in this order to the
  unused byte values `128…255`, then `65…90`, then `1…31`. The authoritative table is `cloudiamond_scratch.text.TABLE`
  (it is also what `tools/make_template.py` writes into the project).
* Characters outside the table are sent as `?` (byte 63). Servers that treat messages as raw bytes can ignore the table.

## 8. Test vectors

Fixed keys (hex). `s` = long-term secret, `e` = client ephemeral, `r` = server one-time key.

```
s       0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
e       2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40
r       4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60
S       07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c
E       5869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b
R       64b101b1d0be5a8704bd078f9895001fc03e8e9f9522f188dd128d9846d48466
sid     5869aff450549732
dh_es   a84dc7c3c8f058b1b2dc4cd1e9b5dc0a7987f88b6a9564cde3391fc421159e77
dh_ee   b6ddcb217f2edb78fe01f0d967925f1e3fda132789e4566ddc2abcd3e2fd9526
master  cad8478268edb88363b63919faed32a0272d3fa7c381946ac09891adcf0cdac4
k_c2s   7948efaae553e5ac95e3ef01d9e08c7c1fb28cd5a0be9eb3333945538f22983b
k_s2c   7c2324249956b8f2ec329740bd95ba19bc85faee18711e2547f7b1f8796f4982

HELLO   5869aff450549732015869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b
REPLY   5869aff4505497320264b101b1d0be5a8704bd078f9895001fc03e8e9f9522f188dd128d9846d484661ddfe6c479057bdecf1b9abb7913c54961bb7aa6f5cb302ff0dd63d44d84ecbd
DATA c2s, ctr 1, message "hello":
        5869aff450549732030000000000017f94cb573006fc3c6366491e72fb67f610f1ef605215e2d35a6cb7f2f75d1b6fa528d23f2aaca47797d9cbed527ac4cd
DATA s2c, ctr 1, message "world":
        5869aff450549732040000000000015d04f3144d81655aa9ebbd951ff4edf46a6d0e2aeb5b14a51bc156cad199b72646fcda8d0d5e42f2fc07a2095668fbac
```

Slot / header examples: `make_hdr(seq=7, n=1) = 100000701`; the HELLO above is one slot of 124 digits starting `1088105175244…`
(`1`, then `088` `105` `175` `244` … for bytes 0x58 0x69 0xAF 0xF4 …).

Primitive vectors used in the tests: RFC 7748 §5.2 and §6.1 (X25519), RFC 8439 §2.8.2 (AEAD),
draft-irtf-cfrg-xchacha-03 §A.6.1 (HChaCha20).
