"""A small scoreboard server: login + score submission, built with the router and the password helpers.

Try it without Scratch first:   python examples/router_server.py --selftest
Run it for real (see README):   cloudiamond-scratch serve --key server.key --url ws://127.0.0.1:9080 \
                                    --project-id 1 --handler router_server:router     (run from examples/)

Scratch side:  🔒 request [login alice hello-scratch-1234] (max 10 sec)
               🔒 request [score 120] (max 10 sec)        🔒 request [top] (max 10 sec)

Everything a Scratch client can type is lowercase ASCII / kana (see cloudiamond_scratch.text), so the
demo password is lowercase. Real servers should load users from a database; this is a demo.
"""
from __future__ import annotations

from cloudiamond_scratch import Router
from cloudiamond_scratch.auth import LoginThrottle, hash_password, verify_password

USERS = {"alice": hash_password("hello-scratch-1234"), "bob": hash_password("another-demo-pass-99")}
_DUMMY = hash_password("not-a-real-user")        # checked for unknown names too, so timing does not reveal who exists
SCORES: dict[str, int] = {}
throttle = LoginThrottle(max_failures=5, window=300, lockout=300)

router = Router()


@router.command("login", min_args=2, max_args=2)
def login(ctx):
    name, password = ctx.args
    if not throttle.allowed(name):
        return "error locked"
    stored = USERS.get(name)
    ok = verify_password(password, stored or _DUMMY)
    if stored is not None and ok:
        throttle.success(name)
        ctx.session.user = name                  # remembered for this session only
        return "ok " + name
    throttle.failure(name)
    return "error login"                         # same answer for "no such user" and "wrong password"


@router.command("score", login=True, min_args=1, max_args=1)
def score(ctx):
    try:
        value = int(ctx.args[0])
    except ValueError:
        return "error number"
    if not 0 <= value <= 1_000_000:
        return "error range"
    SCORES[ctx.user] = max(SCORES.get(ctx.user, 0), value)
    return f"ok best {SCORES[ctx.user]}"


@router.command("top", login=True)
def top(ctx):
    best = sorted(SCORES.items(), key=lambda kv: -kv[1])[:3]
    return " ".join(f"{n}:{s}" for n, s in best) or "empty"


@router.command("bye", login=True)
def bye(ctx):
    ctx.session.user = None
    return "bye"


def _selftest() -> None:
    from cloudiamond_scratch import SecureServer, generate_static_key, text
    from cloudiamond_scratch.refclient import ReferenceClient

    server = SecureServer(generate_static_key(), handler=router)
    client = ReferenceClient(server.public_key)
    assert client.accept_reply(server.handle_frame(client.hello()))

    def ask(line: str) -> str | None:
        out = server.handle_frame(client.seal(text.encode(line)))
        return None if out is None else text.decode(client.open(out))

    for line in ["top", "login alice wrong", "login alice hello-scratch-1234", "score 120", "score 80", "top", "bye", "top"]:
        print(f"> {line:34} -> {ask(line)}")


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        _selftest()
    else:
        print(__doc__)
