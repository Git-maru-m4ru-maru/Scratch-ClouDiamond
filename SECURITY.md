# Security policy

## Reporting a vulnerability

Please report security problems **privately** (do not open a public issue):

* GitHub: *Security* tab → *Report a vulnerability* (private vulnerability reporting), or
* the maintainer contact listed on the PyPI project page.

Include the version (`cloudiamond-scratch --version`), what you observed, and a minimal reproduction if you have one.
Acknowledgement is best-effort (this is a volunteer project).

## Supported versions

Only the latest release receives fixes. The wire protocol identifier is `SCRSEC1`; a protocol change would be a major version.

## Scope and honest limits

* The cryptographic primitives are standard (X25519, ChaCha20-Poly1305, HChaCha20). The *composition* (the two-stage key
  derivation and the framing in `docs/PROTOCOL.md`) has **not been reviewed by a third party**. Do not use it to protect
  information whose disclosure would cause serious harm until it has been reviewed.
* Out of scope by design: client authentication (the client code is public), denial of service on shared cloud variables,
  traffic metadata, compromised endpoints. See the README section "防げないもの / What it does not protect against".
* Python cannot reliably erase secrets from memory; the server relies on the OS and process boundaries.

## Things users must do

* Keep `server.key` private, never commit it, never put it in a Scratch project, and do not store it in a synced or shared folder.
  On Linux/macOS it is created with mode 600. On Windows mode bits do nothing, so the key helpers restrict the file's ACL with
  `icacls` (inheritance removed, current user only) and read it back; if they cannot confirm that, they warn (and `keygen --strict` fails).
  An administrator, another process of the same user, or a backup/sync tool can still read it.
* Run `cloudiamond-scratch audit your.sb3` before publishing a project; run `🔒 wipe secrets` before saving one.
* Compare the key fingerprint (`cloudiamond-scratch inspect`) through a trusted channel when you distribute a client.
