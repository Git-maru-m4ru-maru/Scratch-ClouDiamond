"""Run a server against a cloud-variable server from Python code (the CLI `serve` command does the same).

Terminal 1:   cloudiamond-scratch devcloud                         # local development cloud server on :9080
Terminal 2:   python examples/ws_server.py                         # this file
Then connect a client (the demo .sb3 embeds the public demo key; TurboWarp can use another cloud host - see README).

The transport is experimental: it has only been tested against the bundled development server.
"""
import asyncio
import logging
from pathlib import Path

from cloudiamond_scratch import SecureServer, text
from cloudiamond_scratch.keys import is_demo_key, load_static_key
from cloudiamond_scratch.transport import CloudRunner

KEY_FILE = Path(__file__).with_name("demo_server.key")      # PUBLIC demo key: replace with your own for anything real


async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    server = SecureServer(
        load_static_key(KEY_FILE),
        handler=lambda session, data: text.encode("echo: " + text.decode(data)),
        on_connect=lambda s: logging.info("client %s connected", s.sid_hex),
        on_close=lambda s, why: logging.info("client %s left (%s)", s.sid_hex, why),
    )
    if is_demo_key(server.public_key):
        logging.warning("using the publicly known DEMO key: anyone can impersonate this server")
    print("fingerprint:", server.fingerprint)
    runner = CloudRunner(server, "ws://127.0.0.1:9080", project_id=1, min_interval=0.25)
    await runner.run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
