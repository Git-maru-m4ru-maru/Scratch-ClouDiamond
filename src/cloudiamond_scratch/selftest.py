"""``cloudiamond-scratch selftest``: known-answer tests + an in-process protocol run."""
from __future__ import annotations

import json
import sys

from . import protocol as P
from . import sb3
from . import text as scratch_text
from .crypto import aead_open, aead_seal, hchacha20, x25519_public, x25519_shared
from .keys import generate_static_key, public_key
from .refclient import ReferenceClient
from .server import SecureServer


def _checks():
    # --- known answers -------------------------------------------------------------
    key = bytes(range(32))
    yield "HChaCha20 (draft-irtf-cfrg-xchacha A.6.1)", hchacha20(key, bytes.fromhex("000000090000004a0000000031415927")).hex() == \
        "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"
    a = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
    u = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
    yield "X25519 (RFC 7748 6.1 vector)", x25519_shared(a, u).hex() == "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
    k2 = bytes(range(0x80, 0xA0))
    n2 = bytes.fromhex("070000004041424344454647")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, "
          b"sunscreen would be it.")
    sealed = aead_seal(k2, n2, aad, pt)
    yield "ChaCha20-Poly1305 (RFC 8439 2.8.2 vector)", sealed[-16:].hex() == "1ae10b594f09e26a7e902ecbd0600691" and aead_open(k2, n2, aad, sealed) == pt
    # --- protocol --------------------------------------------------------------------
    secret = generate_static_key()
    pub = public_key(secret)
    srv = SecureServer(secret, on_message=lambda sid, d: b"re:" + d)
    cli = ReferenceClient(pub)
    reply = srv.handle_frame(cli.hello())
    yield "handshake: client verifies the server", reply is not None and cli.accept_reply(reply)
    # a client that expects a different server key must refuse this server's reply
    impostor_target = ReferenceClient(public_key(generate_static_key()))
    r = srv.handle_frame(impostor_target.hello())
    yield "handshake: a wrong server key is detected by the client", r is not None and not impostor_target.accept_reply(r)
    msg = cli.seal(b"ping")
    out = srv.handle_frame(msg)
    yield "message round trip", out is not None and cli.open(out) == b"re:ping"
    yield "replay is dropped", srv.handle_frame(msg) is None
    bad = bytearray(cli.seal(b"x"))
    bad[20] ^= 1
    yield "tampered frame is dropped", srv.handle_frame(bytes(bad)) is None
    srv2 = SecureServer(generate_static_key())
    cli2 = ReferenceClient(srv2.public_key)
    cli2.accept_reply(srv2.handle_frame(cli2.hello()))
    yield "frame for an unknown session is dropped", srv.handle_frame(cli2.seal(b"x")) is None
    yield "dropped frames are counted, not answered", srv.stats["drop.replay"] == 1 and srv.stats["drop.auth"] == 1 \
        and srv.stats["drop.unknown_session"] == 1
    # --- encoding --------------------------------------------------------------------
    f = bytes(range(256))[:200]
    yield "slot encoding round trip", P.slots_to_frame(P.frame_to_slots(f)) == f
    yield "Japanese text table round trip", scratch_text.decode(scratch_text.encode("こんにちは、セカイ！ abc 123")) == "こんにちは、セカイ！ abc 123"
    # --- client file -------------------------------------------------------------------
    data = sb3.build_sb3(pub)
    project, assets = sb3.read_sb3(data)
    yield "client .sb3: structure", sb3.lint_project(project) == []
    yield "client .sb3: unmodified + audit clean", sb3.verify_project(project, assets, expected_pub=pub).ok and sb3.audit_project(project).ok
    yield "client .sb3: build is reproducible", sb3.build_sb3(pub) == data


def run(verbose: bool = False) -> int:
    failed = 0
    for name, ok in _checks():
        if not ok:
            failed += 1
        if verbose or not ok:
            print(("  ok   " if ok else "  FAIL ") + name)
    if failed:
        print(f"selftest: {failed} check(s) FAILED", file=sys.stderr)
        return 1
    print("selftest: all checks passed")
    return 0
