# Upgrading from 0.1 to 1.0

## Compatibility
* The wire protocol (`SCRSEC1`) is unchanged. A 0.1 `.sb3` talks to a 1.0 server and a 1.0 `.sb3` talks to a 0.1 server.
  (The 1.0 client's HELLO retries rely on the 1.0 server answering a repeated HELLO from its cache; how a 0.1 server reacts to a
  repeated HELLO was not checked, so use a 1.0 server with 1.0 clients.)
* Documented 0.1 API: `SecureServer(key, on_message=...)`, `CloudBridge(server, write=...)`, `bridge.on_variable`,
  `bridge.push`, `load_or_create_static_key`, `cloudiamond-scratch keygen|build|selftest` keep working.
  Methods that were not documented may have changed.
* Your existing `server.key` still loads (raw 32 bytes, hex, and base64 files are accepted). Existing `.sb3` files keep working;
  rebuild only if you want the new blocks. The public key (and therefore the fingerprint) does not change when you rebuild.
* Stricter by default: a 5 msg/s per-session limit (burst 10), 1000 sessions, 1 h idle timeout. Raise them with
  `SecureServer(..., message_rate=..., max_sessions=..., session_ttl=...)` if your project needs more.

## If you maintain the SPy sources (`scratch/program.py`, `scratch/spy.py`)

The 1.0.0 `.sb3` was **not** produced by the SPy compiler: the compiled v0.1 blocks are the template and
`tools/make_template.py` applies three changes (it also asserts that the cryptographic blocks stay untouched, and a test
checks that only blocks of `🔒 connect` differ from v0.1). To make SPy the source of truth again, port these to
`program.py`:

1. **`🔒 connect`: HELLO retransmission.** After `ss_connect.t0 = timer`, add `ss_connect.tl = timer` and
   `ss_connect.sends = 1`. In the wait loop, after `wait(0.1)`:
   `if SS_TRIES < 1 and ss_connect.sends < 3 and (timer - ss_connect.tl) > 6: ss_send_frame(); sends += 1; tl = timer`.
   (`ss_send_frame` re-sends the HELLO still held in `TXF`.)
2. **New procedure `🔒 request %s (max %s sec)`**: `🔒 send text (text)` then `🔒 wait for message (max)`.
3. **Text table**: replace the lists `TXT_CHARS` / `TXT_CODES` with `cloudiamond_scratch.text.CHARS` / `.CODES`
   (the first 69 entries equal 0.1).

Also the builder adds a workspace comment (version, public key, fingerprint) and offers `--no-demo`.
`sb3.verify_project` compares a client with the shipped template block for block, so after porting, regenerate
`data/client_template.json` from your compiler output (and `tests/test_release_consistency.py` accordingly).

## Real `scratch-vm`
The 0.1 tests that execute the client on the real `scratch-vm` (Node.js) exercise the SPy output, not this template. Please
run an equivalent check against the 1.0.0 `.sb3` before releasing (checklist in README, section "公開前の確認").
