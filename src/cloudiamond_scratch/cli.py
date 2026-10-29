"""Command line interface: ``cloudiamond-scratch <command>`` (or ``python -m cloudiamond_scratch``)."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib
import logging
import os
import sys
from pathlib import Path

from . import __version__, sb3
from . import text as scratch_text
from .crypto import CryptoError, fingerprint
from .keys import (ENV_VAR, generate_static_key, is_demo_key, key_from_env, load_static_key, parse_public,
                   public_key, save_static_key)

EXIT_OK, EXIT_FINDINGS, EXIT_USAGE = 0, 1, 2


def _err(msg: str) -> int:
    print(f"error: {msg}", file=sys.stderr)
    return EXIT_USAGE


def _pub_from_args(args) -> bytes | None:
    if getattr(args, "pub", None):
        return parse_public(args.pub)
    if getattr(args, "key", None):
        return public_key(load_static_key(args.key))
    env = key_from_env()
    if env is not None and getattr(args, "use_env", False):
        return public_key(env)
    return None


def _secret_from_args(args) -> bytes:
    if getattr(args, "env", False):
        s = key_from_env()
        if s is None:
            raise ValueError(f"environment variable {ENV_VAR} is not set")
        return s
    if not args.key:
        raise ValueError("give --key FILE (or --env)")
    return load_static_key(args.key)


# ---------------------------------------------------------------------------- commands ----
DEMO_WARNING = ("WARNING: this is the publicly known DEMO key (its private half is in the repository). "
                "Anyone can impersonate such a server. Use it only to try things out; create your own with 'keygen'.")


def cmd_keygen(args) -> int:
    path = Path(args.output or args.path or "server.key")
    secret = generate_static_key()
    try:
        save_static_key(path, secret, overwrite=args.force)
    except FileExistsError:
        return _err(f"{path} already exists (use --force to replace it; this invalidates every client built for the old key)")
    pub = public_key(secret)
    print(f"secret key written to {path} (mode 600) - KEEP IT PRIVATE, back it up, never commit it")
    print(f"public key : {pub.hex()}")
    print(f"fingerprint: {fingerprint(pub)}")
    return EXIT_OK


def cmd_pubkey(args) -> int:
    try:
        pub = public_key(_secret_from_args(args))
    except (ValueError, OSError, CryptoError) as e:
        return _err(str(e))
    print(pub.hex())
    print(f"fingerprint: {fingerprint(pub)}", file=sys.stderr)
    return EXIT_OK


def cmd_build(args) -> int:
    try:
        pub = _pub_from_args(args)
        if pub is None:
            return _err("give --key FILE (server secret key) or --pub HEX (public key)")
        if args.key and Path(args.output).resolve() == Path(args.key).resolve():
            return _err("refusing to overwrite the key file")
        data = sb3.build_sb3(pub, name=args.name, demo=not args.no_demo)
    except (ValueError, OSError, CryptoError) as e:
        return _err(str(e))
    Path(args.output).write_bytes(data)
    if is_demo_key(pub):
        print(DEMO_WARNING, file=sys.stderr)
    print(f"wrote {args.output} ({len(data)} bytes)")
    print(f"sha256     : {hashlib.sha256(data).hexdigest()}")
    print(f"public key : {pub.hex()}")
    print(f"fingerprint: {fingerprint(pub)}")
    print("Tell users the fingerprint through a trusted channel so they can compare it (cloudiamond-scratch inspect FILE).")
    return EXIT_OK


def _load(path: str):
    return sb3.read_sb3(Path(path).read_bytes())


def cmd_inspect(args) -> int:
    try:
        project, assets = _load(args.file)
        pub = sb3.embedded_public_key(project)
    except (ValueError, KeyError, OSError) as e:
        return _err(str(e))
    sp = sb3._sprite(project)
    errs = sb3.lint_project(project)
    print(f"sprite     : {sp['name']}")
    print(f"public key : {pub.hex()}")
    print(f"fingerprint: {fingerprint(pub)}")
    print(f"demo script: {'yes' if any(isinstance(b, dict) and b['opcode'] == 'event_whenflagclicked' for b in sp['blocks'].values()) else 'no'}")
    print(f"blocks     : {len(sp['blocks'])}")
    print("structure  : " + ("OK" if not errs else f"{len(errs)} problem(s): {errs[0]}"))
    return EXIT_OK if not errs else EXIT_FINDINGS


def cmd_audit(args) -> int:
    try:
        project, _ = _load(args.file)
    except (ValueError, OSError) as e:
        return _err(str(e))
    rep = sb3.audit_project(project)
    shown = [f for f in rep.findings if args.verbose or f.severity != "info"]
    for f in shown:
        print(f)
    if rep.ok:
        print("audit OK: no session keys or message data left in the project")
        return EXIT_OK
    print("audit FAILED: do not publish this file. Open it, run '\U0001F512 wipe secrets', save, and audit again.", file=sys.stderr)
    return EXIT_FINDINGS


def cmd_verify(args) -> int:
    try:
        project, assets = _load(args.file)
        expected = _pub_from_args(args)
    except (ValueError, OSError, CryptoError) as e:
        return _err(str(e))
    rep = sb3.verify_project(project, assets, expected_pub=expected)
    if rep.public_key:
        print(f"public key : {rep.public_key.hex()}")
        print(f"fingerprint: {fingerprint(rep.public_key)}")
    for n in rep.notes:
        print(f"note: {n}")
    print(f"client blocks unmodified (v{__version__}): {'yes' if rep.client_unmodified else 'NO'}")
    print(f"identical to a fresh build             : {'yes' if rep.identical else 'no'}")
    if expected is not None and rep.public_key != expected:
        print("public key matches the expected key    : NO")
        return EXIT_FINDINGS
    return EXIT_OK if rep.ok else EXIT_FINDINGS


def cmd_selftest(args) -> int:
    from .selftest import run
    return run(verbose=args.verbose)


def _import_handler(spec: str):
    mod, _, attr = spec.partition(":")
    if not mod or not attr:
        raise ValueError("--handler must look like package.module:object")
    obj = getattr(importlib.import_module(mod), attr)
    return obj() if isinstance(obj, type) else obj


def cmd_serve(args) -> int:
    from .server import SecureServer
    from .transport import CloudRunner
    try:
        secret = _secret_from_args(args)
    except (ValueError, OSError, CryptoError) as e:
        return _err(str(e))
    log = logging.getLogger("cloudiamond_scratch")
    if args.handler:
        try:
            handler = _import_handler(args.handler)
        except (ValueError, ImportError, AttributeError) as e:
            return _err(str(e))
    else:
        handler = lambda session, data: scratch_text.encode("echo: " + scratch_text.decode(data))  # noqa: E731
        log.warning("no --handler given: running the echo demo")
    server = SecureServer(
        secret, handler=handler,
        on_connect=lambda s: log.info("session %s connected", s.sid_hex),
        on_close=lambda s, why: log.info("session %s closed (%s)", s.sid_hex, why))
    if is_demo_key(server.public_key):
        print(DEMO_WARNING, file=sys.stderr)
    print(f"server public key fingerprint: {server.fingerprint}")
    print(f"connecting to {args.url} (project {args.project_id}) ... Ctrl+C to stop")
    runner = CloudRunner(server, args.url, args.project_id, username=args.username, min_interval=args.min_interval)
    try:
        asyncio.run(runner.run())
    except KeyboardInterrupt:
        print("\nstopped")
    return EXIT_OK


def cmd_devcloud(args) -> int:
    from .transport import CloudDevServer
    srv = CloudDevServer(args.host, args.port)

    async def go():
        await srv.start()
        print(f"development cloud server on {srv.url} (not for production). Ctrl+C to stop")
        await srv.serve_forever()
    try:
        asyncio.run(go())
    except KeyboardInterrupt:
        print("\nstopped")
    return EXIT_OK


# ------------------------------------------------------------------------------- parser ----
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cloudiamond-scratch",
                                description="Encrypted Scratch <-> Python communication over cloud variables.")
    p.add_argument("--version", action="version", version=f"cloudiamond-scratch {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True, metavar="command")

    s = sub.add_parser("keygen", help="create the server's long-term secret key file")
    s.add_argument("path", nargs="?", help="key file to create (default: server.key)")
    s.add_argument("-o", "--output", help="same as the positional path")
    s.add_argument("--force", action="store_true", help="replace an existing key file")
    s.set_defaults(fn=cmd_keygen)

    s = sub.add_parser("pubkey", help="print the public key (hex) of a secret key file")
    s.add_argument("--key", default="server.key")
    s.add_argument("--env", action="store_true", help=f"read the key from ${ENV_VAR}")
    s.set_defaults(fn=cmd_pubkey)

    s = sub.add_parser("build", help="build the Scratch client (.sb3) for a server key")
    g = s.add_mutually_exclusive_group()
    g.add_argument("--key", help="server secret key file (only its public part is used)")
    g.add_argument("--pub", help="server public key, 64 hex characters")
    s.add_argument("-o", "--output", default="ClouDiamond.sb3")
    s.add_argument("--name", default=sb3.DEFAULT_NAME, help="sprite name (without the diamond)")
    s.add_argument("--no-demo", action="store_true", help="library mode: omit the green-flag demo script")
    s.set_defaults(fn=cmd_build)

    s = sub.add_parser("inspect", help="show the public key / fingerprint of an .sb3")
    s.add_argument("file")
    s.set_defaults(fn=cmd_inspect)

    s = sub.add_parser("audit", help="check an .sb3 for leftover session keys / messages before publishing")
    s.add_argument("file")
    s.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(fn=cmd_audit)

    s = sub.add_parser("verify", help="check that an .sb3 is the unmodified client of this version")
    s.add_argument("file")
    g = s.add_mutually_exclusive_group()
    g.add_argument("--pub", help="expected server public key (hex)")
    g.add_argument("--key", help="expected server key file")
    s.set_defaults(fn=cmd_verify)

    s = sub.add_parser("selftest", help="run built-in known-answer and protocol checks")
    s.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(fn=cmd_selftest)

    s = sub.add_parser("serve", help="run a server against a cloud-variable server (experimental transport)")
    s.add_argument("--key", default="server.key")
    s.add_argument("--env", action="store_true", help=f"read the secret key from ${ENV_VAR}")
    s.add_argument("--url", required=True, help="ws://host:port or wss://host")
    s.add_argument("--project-id", required=True)
    s.add_argument("--username", default="cloudiamond-server")
    s.add_argument("--handler", help="package.module:object (a Router or f(session, data) -> reply); default: echo demo")
    s.add_argument("--min-interval", type=float, default=0.25, help="seconds between frames (default 0.25)")
    s.set_defaults(fn=cmd_serve)

    s = sub.add_parser("devcloud", help="run a local cloud-variable server for development")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=9080)
    s.set_defaults(fn=cmd_devcloud)
    return p


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO if os.environ.get("CLOUDIAMOND_LOG") is None else os.environ["CLOUDIAMOND_LOG"],
                        format="%(asctime)s %(levelname)s %(message)s")
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except BrokenPipeError:
        return EXIT_OK
