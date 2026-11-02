import _setup  # noqa: F401
import asyncio
import json
import time
import unittest

from cloudiamond_scratch import SecureServer, generate_static_key, public_key
from cloudiamond_scratch import protocol as P
from cloudiamond_scratch.refclient import ReferenceClient
from cloudiamond_scratch.transport import CloudClient, CloudDevServer, CloudRunner
from cloudiamond_scratch.transport.wsproto import WSConnection, WSError, client_handshake, server_handshake

PFX = P.CLOUD_PREFIX


class Player:
    """A stand-in for the Scratch client on its own websocket."""

    def __init__(self, url, project, server_pub, name="player"):
        self.c = CloudClient(url, project, name)
        self.ref = ReferenceClient(server_pub)
        self.vals = {}
        self.seq = 0
        self.it = None

    async def start(self):
        await self.c.connect()
        self.it = self.c.messages().__aiter__()

    async def send(self, frame):
        slots = P.frame_to_slots(frame)
        for i, s in enumerate(slots):
            await self.c.set(PFX + P.VAR_C2S[i], s)
        self.seq += 1
        await self.c.set(PFX + P.VAR_C2S_HDR, str(P.make_hdr(self.seq, len(slots))))

    async def recv(self, timeout=3.0):
        """Next server frame addressed to *this* session (frames for other sessions are skipped, as the Scratch client does)."""
        end = time.monotonic() + timeout
        while True:
            name, value = await asyncio.wait_for(self.it.__anext__(), max(0.01, end - time.monotonic()))
            short = name.replace("\u2601", "").strip()
            self.vals[short] = value
            if short == P.VAR_S2C_HDR:
                n = P.parse_hdr(value)[1]
                frame = P.slots_to_frame([self.vals[v] for v in P.VAR_S2C[:n]])
                if frame and frame[:8] == self.ref.sid:
                    return frame

    async def handshake(self):
        await self.send(self.ref.hello())
        return self.ref.accept_reply(await self.recv())

    async def request(self, data: bytes):
        await self.send(self.ref.seal(data))
        return self.ref.open(await self.recv())


class Stack:
    async def __aenter__(self):
        self.dev = CloudDevServer(port=0)
        await self.dev.start()
        self.secret = generate_static_key()
        self.server = SecureServer(self.secret, on_message=lambda sid, d: b"echo:" + d)
        self.runner = CloudRunner(self.server, self.dev.url, 7, min_interval=0.02, snapshot_window=0.15)
        self.task = asyncio.create_task(self.runner.run())
        await asyncio.wait_for(self.runner.connected.wait(), 3)
        return self

    async def __aexit__(self, *exc):
        self.runner.stop()
        await asyncio.wait_for(self.task, 5)
        await self.dev.stop()


class EndToEnd(unittest.IsolatedAsyncioTestCase):
    async def test_handshake_message_and_push(self):
        async with Stack() as s:
            p = Player(s.dev.url, 7, public_key(s.secret))
            await p.start()
            self.assertTrue(await p.handshake())
            self.assertEqual(await p.request(b"hello"), b"echo:hello")
            s.runner.push(p.ref.sid, b"pushed")
            self.assertEqual(p.ref.open(await p.recv()), b"pushed")
            await p.c.close()
            self.assertEqual(s.dev.rejected, 0, "every value we wrote must look like a legal cloud value")

    async def test_two_players_do_not_see_each_others_traffic_in_plaintext(self):
        async with Stack() as s:
            a = Player(s.dev.url, 7, public_key(s.secret), "a")
            b = Player(s.dev.url, 7, public_key(s.secret), "b")
            await a.start(); await b.start()
            self.assertTrue(await a.handshake())
            # b is a passive observer of the same project: it receives a's REPLY too, but cannot use it
            await asyncio.sleep(0.1)
            self.assertTrue(await b.handshake())
            self.assertEqual(await a.request(b"alice secret"), b"echo:alice secret")
            self.assertEqual(await b.request(b"bob secret"), b"echo:bob secret")
            self.assertEqual(len(s.server.sessions), 2)
            await a.c.close(); await b.c.close()

    async def test_other_projects_are_separate(self):
        async with Stack() as s:
            other = Player(s.dev.url, 999, public_key(s.secret))
            await other.start()
            await other.send(other.ref.hello())
            with self.assertRaises(asyncio.TimeoutError):
                await other.recv(0.5)
            self.assertEqual(s.server.stats["session_new"], 0)
            await other.c.close()

    async def test_late_joiner_snapshot_is_not_processed_twice(self):
        async with Stack() as s:
            p = Player(s.dev.url, 7, public_key(s.secret))
            await p.start()
            await p.handshake()
            await p.request(b"x")
            before = dict(s.server.stats)
            late = CloudClient(s.dev.url, 7, "late")
            await late.connect()
            await asyncio.sleep(0.3)
            self.assertEqual(dict(s.server.stats), before)
            await late.close(); await p.c.close()

    async def test_runner_reconnects_after_the_cloud_server_restarts(self):
        dev = CloudDevServer(port=0)
        await dev.start()
        port = dev.port
        server = SecureServer(generate_static_key(), on_message=lambda sid, d: b"ok")
        runner = CloudRunner(server, dev.url, 1, min_interval=0.02, snapshot_window=0.1)
        task = asyncio.create_task(runner.run())
        await asyncio.wait_for(runner.connected.wait(), 3)
        await dev.stop()
        for _ in range(50):                      # connection drop noticed
            if not runner.connected.is_set():
                break
            await asyncio.sleep(0.05)
        self.assertFalse(runner.connected.is_set())
        dev2 = CloudDevServer(port=port)
        await dev2.start()
        await asyncio.wait_for(runner.connected.wait(), 8)
        runner.stop()
        await asyncio.wait_for(task, 5)
        await dev2.stop()


class DevServer(unittest.IsolatedAsyncioTestCase):
    async def test_values_that_real_cloud_servers_would_refuse_are_rejected(self):
        dev = CloudDevServer(port=0)
        await dev.start()
        c = CloudClient(dev.url, 1, "u")
        await c.connect()
        for name, value in [(PFX + "C2S_0", "abc"), (PFX + "C2S_0", "1" * 300), ("no-cloud-mark", "123"),
                            (PFX + "C2S_0", ""), (PFX + "C2S_0", "12 34")]:
            await c.set(name, value)
        await c.set(PFX + "C2S_0", "1" * 253)
        await asyncio.sleep(0.2)
        self.assertEqual(dev.rejected, 5)
        self.assertEqual(dev.projects["1"], {PFX + "C2S_0": "1" * 253})
        await c.close(); await dev.stop()

    async def test_sends_current_values_on_handshake(self):
        dev = CloudDevServer(port=0)
        await dev.start()
        a = CloudClient(dev.url, 1, "a"); await a.connect()
        await a.set(PFX + "S2C_HDR", "100000101")
        await asyncio.sleep(0.1)
        b = CloudClient(dev.url, 1, "b"); await b.connect()
        it = b.messages().__aiter__()
        name, value = await asyncio.wait_for(it.__anext__(), 2)
        self.assertEqual((name, value), (PFX + "S2C_HDR", "100000101"))
        await a.close(); await b.close(); await dev.stop()


class WebSocketProtocol(unittest.IsolatedAsyncioTestCase):
    async def _pair(self):
        got = asyncio.Queue()

        async def handle(r, w):
            try:
                await server_handshake(r, w)
                ws = WSConnection(r, w, is_client=False)
                while True:
                    m = await ws.recv()
                    if m is None:
                        break
                    await got.put(m)
                    await ws.send_text("echo:" + m)
            except (WSError, ConnectionError):
                pass
            finally:
                w.close()
        srv = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        r, w = await asyncio.open_connection("127.0.0.1", port)
        await client_handshake(r, w, f"127.0.0.1:{port}")
        return srv, WSConnection(r, w, is_client=True), got

    async def test_messages_of_all_size_classes(self):
        srv, ws, got = await self._pair()
        for n in (0, 1, 125, 126, 127, 65535, 65536, 200_000):
            msg = "é" * (n // 2) + "x" * (n % 2) if n else ""
            await ws.send_text(msg)
            self.assertEqual(await asyncio.wait_for(got.get(), 3), msg)
            self.assertEqual(await asyncio.wait_for(ws.recv(), 3), "echo:" + msg)
        await ws.close(); srv.close(); await srv.wait_closed()

    async def test_server_closing_ends_recv(self):
        srv, ws, got = await self._pair()
        await ws.close()
        srv.close(); await srv.wait_closed()
        self.assertIsNone(await ws.recv())

    async def test_non_websocket_peer_is_refused(self):
        async def http(r, w):
            await r.readline()
            w.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            await w.drain()
            w.close()
        srv = await asyncio.start_server(http, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        c = CloudClient(f"ws://127.0.0.1:{port}", 1)
        with self.assertRaises(WSError):
            await c.connect()
        srv.close(); await srv.wait_closed()

    async def test_bad_urls(self):
        for url in ("http://x", "ws://", "nonsense", "ftp://h:1"):
            with self.assertRaises(ValueError):
                await CloudClient(url, 1).connect()


if __name__ == "__main__":
    unittest.main()
