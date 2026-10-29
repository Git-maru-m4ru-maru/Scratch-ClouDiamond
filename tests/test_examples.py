"""The examples are documentation; make sure they keep working."""
import _setup  # noqa: F401
import contextlib
import importlib.util
import io
import unittest
from pathlib import Path

from cloudiamond_scratch import SecureServer, generate_static_key, text
from cloudiamond_scratch.refclient import ReferenceClient

EX = Path(__file__).resolve().parent.parent / "examples"


def load(name):
    spec = importlib.util.spec_from_file_location(name, EX / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@unittest.skipUnless(EX.exists(), "examples/ not available")
class Examples(unittest.TestCase):
    def test_in_process_demo_runs(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            load("in_process_demo").main()
        self.assertIn("handshake ok", out.getvalue())
        self.assertIn("echo: hello from the client", out.getvalue())
        self.assertIn("recorded frame is silently dropped: True", out.getvalue())

    def session(self):
        mod = load("router_server")
        server = SecureServer(generate_static_key(), handler=mod.router, message_rate=1000, message_burst=1000)
        client = ReferenceClient(server.public_key)
        client.accept_reply(server.handle_frame(client.hello()))

        def ask(line):
            out = server.handle_frame(client.seal(text.encode(line)))
            return None if out is None else text.decode(client.open(out))
        return mod, ask

    def test_router_server_login_flow(self):
        mod, ask = self.session()
        self.assertEqual(ask("top"), "error login")                      # not logged in
        self.assertEqual(ask("login alice nope"), "error login")
        self.assertEqual(ask("login nobody nope"), "error login")        # same answer: no user enumeration
        self.assertEqual(ask("login alice hello-scratch-1234"), "ok alice")
        self.assertEqual(ask("score 120"), "ok best 120")
        self.assertEqual(ask("score 80"), "ok best 120")
        self.assertEqual(ask("score abc"), "error number")
        self.assertEqual(ask("score 99999999"), "error range")
        self.assertEqual(ask("top"), "alice:120")
        self.assertEqual(ask("bye"), "bye")
        self.assertEqual(ask("top"), "error login")

    def test_router_server_locks_out_guessing(self):
        mod, ask = self.session()
        for _ in range(5):
            ask("login bob guess")
        self.assertEqual(ask("login bob another-demo-pass-99"), "error locked")

    def test_other_examples_import(self):
        load("ws_server")


if __name__ == "__main__":
    unittest.main()
