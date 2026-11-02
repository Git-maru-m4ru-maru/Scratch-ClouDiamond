# Changelog

## [1.0.1] - 2026-11-02

Fixes found by testing the published packages from the sdist and on Windows. **No change to the protocol, the server logic or
the Scratch blocks:** the compiled client blocks, the text table and the test vectors are identical to 1.0.0.

### Fixed
- **sdist was missing test helpers.** `MANIFEST.in` listed file extensions (`recursive-include tests *.py`), so a non-Python
  helper such as a Node.js harness (`tests/vmharness.js`) was left out and tests run from the sdist failed with
  `Cannot find module '.../tests/vmharness.js'`. It now grafts whole directories (`tests`, `docs`, `examples`, `tools`).
  A test checks that the rules cover every file in those directories (and would include a `.js` harness and `.json`
  fixtures); CI and the publish workflow unpack the sdist and run the test suite **from it**.
- **Windows: the key file was not protected.** `os.chmod` / mode `0600` do nothing useful on Windows (only the read-only
  attribute is touched) and the permission check was POSIX-only. New `fsperm` module: on Windows the key file is locked down
  with `icacls` (inheritance removed, current user only) **before** the secret is written, and read back; loading warns when
  the file's access rules cannot be confirmed as private (`strict=True` raises). On POSIX the file is created with mode 600 as
  before. Whether others can read a file on Windows also depends on the ACL inherited from its folder; the messages say
  "could not be confirmed" rather than claiming more than is known. If it cannot be restricted the key is still written and
  a warning with the fix command is printed.
- **Windows: console crash.** Printing the sprite name (a diamond emoji) raised `UnicodeEncodeError` on consoles whose code
  page cannot show it (cp1252 / cp932). Unencodable characters now print as `?`.
- **Tests: locale-dependent file reading.** `read_text()` without `encoding` failed on Windows (cp1252) for UTF-8 files
  containing Japanese text (`pyproject.toml`). All text I/O in tests and tools now names its encoding, and a test scans the
  code base so it cannot come back. A leftover helper that pointed at a path on a developer machine was removed.

### Changed
- `keygen` reports how the key was protected and warns when it could not be; new `keygen --strict`.
  `save_static_key(..., strict=False)` now returns `bool` (private or not); `load_or_create_static_key` accepts `strict`.
- README: links to the changelog, the protocol specification and the upgrade guide are absolute, so they work on the PyPI
  project page. New section on key-file protection per OS.
- The `.sb3` built by this version carries `1.0.1` in its workspace comment. `cloudiamond-scratch verify` still recognises
  a client built by an earlier 1.0.x as unmodified (it compares the blocks; "identical to a fresh build" says no).
- Checked by scanning the source that no Python 3.12-only syntax is used (the code is meant for Python >= 3.11);
  it has still only been run on Python 3.12 / Linux.

### Verification
- 270 tests (6 of them Windows-only and skipped elsewhere) pass on Linux / Python 3.12, also when run from an unpacked sdist
  that contains a stand-in `tests/vmharness.js`. Mutation check of the security-critical code: 29 / 29 patterns caught
  (`tools/mutation_check.py`).
- The Windows protection is tested with a simulated `icacls` / `whoami` (command construction, output parsing, every failure
  path, order of operations). `tests/test_windows_real.py` exercises the real tools and runs only on Windows (CI); it has not
  been run on a real Windows machine by the author of this change.

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
