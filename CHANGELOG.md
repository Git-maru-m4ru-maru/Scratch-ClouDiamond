# Changelog

## [1.0.0] - 2026-10-17

First stable-API release. The wire protocol is unchanged (`SCRSEC1`): **v0.1 clients and v1.0 servers (and the other
way round) interoperate**; the cryptographic blocks of the Scratch client are the compiled v0.1 blocks, byte for byte.

### Safety
- Server: per-session and global token-bucket rate limits, session capacity with eviction that protects real users
  (sessions that never sent a valid message are evicted first and expire after 120 s), idle expiry (1 h), strict
  monotonic counters that are only advanced by *authenticated* frames, no session replacement on session-id collision,
  low-order point / all-zero shared secret rejection, defensive handling of handler exceptions and unsupported reply types.
- HELLO retransmission is answered from a cache with the *same* (public) reply, so a retry never creates a second session.
- Bridge: the server's `S2C_HDR` is guaranteed to differ from the value already in the cloud (a restarted server could
  otherwise repeat the previous header and the client would never notice the frame); sequence numbers start at random.
  Values replayed by the cloud server right after connecting are not processed as new frames.
- `keygen` writes the key with mode 0600 and never overwrites; loading warns if the file is group/world readable;
  `CLOUDIAMOND_SERVER_KEY` environment variable; the publicly known demo key is detected and warned about.
- New `audit` command: finds session keys, message residue, modified constant tables and pasted secret keys in a saved
  `.sb3` before you publish it. New `verify` command: checks that an `.sb3` is the unmodified client of this version.
- Password helpers (`scrypt`, constant-time check, login throttle).

### Scratch client
- `🔒 connect` re-sends the HELLO every 6 s (up to 3 sends) while no reply has arrived (v0.1 sent it once).
- New block `🔒 request (text) (max N sec)` = send + wait for the answer.
- Text table extended with hiragana, katakana and Japanese punctuation (the 69 ASCII entries are unchanged). Uppercase
  letters are still sent as lowercase: Scratch compares strings case-insensitively.
- `--no-demo` builds a "library" project without the green-flag demo script.
- The project contains a comment with version, public key and fingerprint.

### Usability / generality
- Message router (`@router.command`), `Session` objects (`user`, `data`), `on_connect` / `on_close` callbacks,
  `handler=` in addition to the 0.1-style `on_message=`, server `stats` counters.
- Optional asyncio transport (standard library only): WebSocket client for TurboWarp-style cloud-variable servers,
  `CloudRunner` (paced writes, reconnect, snapshot handling), local `devcloud` server. **Not tested against a live
  TurboWarp/Scratch server.**
- CLI: `keygen`, `pubkey`, `build`, `inspect`, `audit`, `verify`, `selftest`, `serve`, `devcloud`.
- Pure-Python reference client (`ReferenceClient`) for tests and Python-to-Python links.

### Verification
- 228 tests, including the compiled Scratch client run in an independent Python block interpreter against the server
  (handshake, retransmission, impostor server, tampering, replay, reflection, eavesdropping, saved-project audit),
  RFC 7748 / RFC 8439 / draft-irtf-cfrg-xchacha vectors for the blocks inside the client, and mutation testing of the
  security-critical code.
- The new Scratch blocks were **not** run on the real `scratch-vm` or in an editor. See README "検証したこと / 未検証".

### Changed
- `Development Status` classifier is Beta (the composition has no third-party review).

### Compatibility notes
- Documented 0.1 API (`SecureServer(key, on_message=...)`, `CloudBridge(server, write=...)`, `bridge.on_variable`,
  `bridge.push`, `load_or_create_static_key`, CLI `keygen/build/selftest`) is kept.

## [0.1.0]
- Initial release (demo): X25519 + ChaCha20-Poly1305 client generated as `.sb3`, `SecureServer`, `CloudBridge`.
