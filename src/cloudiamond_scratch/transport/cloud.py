"""Cloud-variable transport: client, local development server, and the bridge runner.

Speaks the cloud-variable WebSocket protocol used by TurboWarp-compatible servers: newline-delimited
JSON, ``{"method":"handshake","user":..,"project_id":..}`` first, then ``{"method":"set","name":..,"value":..}``.

Status: written to that documented protocol and tested against the bundled ``CloudDevServer`` only.
It has NOT been tested against a live TurboWarp or Scratch server. The official Scratch server needs a
logged-in session (use a library such as scratchattach and feed ``CloudBridge.on_variable`` instead).
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import ssl as _ssl
from typing import AsyncIterator
from urllib.parse import urlsplit

from .. import protocol as P
from ..bridge import BridgeCore
from ..server import SecureServer
from .wsproto import WSConnection, WSError, client_handshake, server_handshake

__all__ = ["CloudClient", "CloudDevServer", "CloudRunner"]

log = logging.getLogger("cloudiamond_scratch")
_VALUE_OK = re.compile(r"^-?\d{1,256}(\.\d{1,254})?$")


class CloudClient:
    def __init__(self, url: str, project_id: str | int, username: str = "cloudiamond-server", *,
                 ssl: _ssl.SSLContext | None = None):
        self.url, self.project_id, self.username = url, str(project_id), username
        self._ssl = ssl
        self.ws: WSConnection | None = None

    async def connect(self) -> None:
        u = urlsplit(self.url)
        if u.scheme not in ("ws", "wss") or not u.hostname:
            raise ValueError("url must look like ws://host:port or wss://host")
        secure = u.scheme == "wss"
        port = u.port or (443 if secure else 80)
        ctx = (self._ssl or _ssl.create_default_context()) if secure else None
        reader, writer = await asyncio.open_connection(u.hostname, port, ssl=ctx)
        try:
            await client_handshake(reader, writer, f"{u.hostname}:{port}", (u.path or "/") + (f"?{u.query}" if u.query else ""))
        except BaseException:
            writer.close()
            raise
        self.ws = WSConnection(reader, writer, is_client=True)
        await self._send({"method": "handshake", "user": self.username, "project_id": self.project_id})

    async def _send(self, obj: dict) -> None:
        assert self.ws is not None
        await self.ws.send_text(json.dumps(obj, ensure_ascii=False) + "\n")

    async def set(self, name: str, value: str) -> None:
        await self._send({"method": "set", "name": name, "value": value,
                          "user": self.username, "project_id": self.project_id})

    async def messages(self) -> AsyncIterator[tuple[str, str]]:
        """Yields ``(name, value)`` for every ``set`` message until the connection closes."""
        assert self.ws is not None
        while True:
            raw = await self.ws.recv()
            if raw is None:
                return
            for line in raw.split("\n"):
                if not line.strip():
                    continue
                try:
                    msg = json.loads(line)
                except ValueError:
                    continue
                if isinstance(msg, dict) and msg.get("method") == "set" and "name" in msg:
                    yield str(msg["name"]), msg.get("value", "")

    async def close(self) -> None:
        if self.ws is not None:
            await self.ws.close()


class CloudDevServer:
    """A small cloud-variable server for local development and tests (``ws://127.0.0.1:9080``).

    Keeps variables per ``project_id``, sends the current values to a client right after its
    handshake, and relays every ``set`` to the *other* clients of the same project. Values must look
    like real cloud values (digits only, at most 256 characters); anything else is refused, which
    catches protocol bugs early.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 9080):
        self.host, self.port = host, port
        self.projects: dict[str, dict[str, str]] = {}
        self._clients: dict[str, set[WSConnection]] = {}
        self._server: asyncio.AbstractServer | None = None
        self.rejected = 0

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, self.host, self.port)
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()                       # stop accepting
        for conns in list(self._clients.values()):     # close clients FIRST: since Python 3.12
            for c in list(conns):                      # wait_closed() waits for every connection
                await c.close()
        if self._server is not None:
            try:
                await asyncio.wait_for(self._server.wait_closed(), 3)
            except asyncio.TimeoutError:
                log.warning("some development-server connections did not close in time")

    @property
    def url(self) -> str:
        return f"ws://{self.host}:{self.port}"

    async def serve_forever(self) -> None:
        if self._server is None:
            await self.start()
        assert self._server is not None
        await self._server.serve_forever()

    async def _handle(self, reader, writer) -> None:
        try:
            await server_handshake(reader, writer)
        except (WSError, ConnectionError, OSError, asyncio.IncompleteReadError):
            writer.close()
            return
        ws = WSConnection(reader, writer, is_client=False)
        pid: str | None = None
        try:
            while True:
                raw = await ws.recv()
                if raw is None:
                    break
                for line in raw.split("\n"):
                    if not line.strip():
                        continue
                    try:
                        msg = json.loads(line)
                    except ValueError:
                        continue
                    if not isinstance(msg, dict):
                        continue
                    if msg.get("method") == "handshake" and pid is None:
                        pid = str(msg.get("project_id", ""))
                        self._clients.setdefault(pid, set()).add(ws)
                        for n, v in self.projects.get(pid, {}).items():
                            await ws.send_text(json.dumps({"method": "set", "name": n, "value": v}) + "\n")
                    elif msg.get("method") == "set" and pid is not None:
                        name, value = str(msg.get("name", "")), str(msg.get("value", ""))
                        if not name.startswith(P.CLOUD_PREFIX) or not _VALUE_OK.match(value):
                            self.rejected += 1
                            continue
                        self.projects.setdefault(pid, {})[name] = value
                        out = json.dumps({"method": "set", "name": name, "value": value}) + "\n"
                        for other in list(self._clients.get(pid, ())):
                            if other is not ws:
                                try:
                                    await other.send_text(out)
                                except (ConnectionError, OSError):
                                    pass
        except (WSError, ConnectionError, OSError):
            pass
        finally:
            if pid is not None:
                self._clients.get(pid, set()).discard(ws)
            await ws.close()


class CloudRunner:
    """Run a :class:`SecureServer` against a cloud-variable server until :meth:`stop` is called.

    * ``min_interval``: pause between consecutive frames (a slow Scratch client could otherwise miss one).
    * ``reconnect``: reconnect with exponential back-off (1 s ... 30 s) when the connection drops.
    * Values the cloud server replays right after connecting are remembered but not processed
      (``snapshot_window`` seconds of quiet ends the snapshot), so stale frames are not handled twice.
    """

    def __init__(self, server: SecureServer, url: str, project_id: str | int, *,
                 username: str = "cloudiamond-server", min_interval: float = 0.25, reconnect: bool = True,
                 snapshot_window: float = 0.5, ssl: _ssl.SSLContext | None = None):
        self.server, self.url, self.project_id, self.username = server, url, str(project_id), username
        self.min_interval, self.reconnect, self.snapshot_window, self._ssl = min_interval, reconnect, snapshot_window, ssl
        self.core = BridgeCore(server)
        self._out: asyncio.Queue | None = None
        self._stop = asyncio.Event()
        self.connected = asyncio.Event()

    def stop(self) -> None:
        self._stop.set()

    def push(self, sid: bytes | str, data: bytes | str) -> None:
        """Send a server-initiated message. Call from the event-loop thread."""
        if self._out is None:
            raise RuntimeError("runner is not running")
        for frame in self.core.push(sid, data):
            self._out.put_nowait(frame)

    async def run(self) -> None:
        delay = 1.0
        while not self._stop.is_set():
            try:
                await self._session()
                delay = 1.0
            except (WSError, ConnectionError, OSError, asyncio.IncompleteReadError) as exc:
                log.warning("cloud connection lost: %s", exc)
            self.connected.clear()
            if not self.reconnect or self._stop.is_set():
                return
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=delay)
            except asyncio.TimeoutError:
                pass
            delay = min(delay * 2, 30.0)

    async def _session(self) -> None:
        client = CloudClient(self.url, self.project_id, self.username, ssl=self._ssl)
        await client.connect()
        self._out = asyncio.Queue()
        writer = asyncio.create_task(self._writer(client))
        stopper = asyncio.create_task(self._stop.wait())
        try:
            it = client.messages().__aiter__()
            snapshot = True
            while True:
                nxt = asyncio.ensure_future(it.__anext__())
                done, _ = await asyncio.wait({nxt, stopper}, timeout=self.snapshot_window if snapshot else None,
                                             return_when=asyncio.FIRST_COMPLETED)
                if stopper in done:
                    nxt.cancel()
                    return
                if not done:                       # quiet for snapshot_window -> live from now on
                    snapshot = False
                    self.connected.set()
                    done, _ = await asyncio.wait({nxt, stopper}, return_when=asyncio.FIRST_COMPLETED)
                    if stopper in done:
                        nxt.cancel()
                        return
                try:
                    name, value = nxt.result()
                except StopAsyncIteration:
                    return
                for frame in self.core.feed(name, value, initial=snapshot):
                    self._out.put_nowait(frame)
        finally:
            stopper.cancel()
            writer.cancel()
            await asyncio.gather(writer, stopper, return_exceptions=True)
            await client.close()
            self._out = None

    async def _writer(self, client: CloudClient) -> None:
        assert self._out is not None
        while True:
            frame = await self._out.get()
            for name, value in frame:
                await client.set(name, value)
            await asyncio.sleep(self.min_interval)
