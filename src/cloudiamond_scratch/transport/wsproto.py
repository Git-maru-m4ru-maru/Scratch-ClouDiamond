"""Minimal RFC 6455 WebSocket (text messages only) on asyncio streams. Standard library only."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import struct

__all__ = ["WSConnection", "WSError", "client_handshake", "server_handshake"]

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MAX_MESSAGE = 1 << 20


class WSError(Exception):
    pass


def _accept_key(key: bytes) -> bytes:
    return base64.b64encode(hashlib.sha1(key + GUID).digest())


async def _read_head(reader: asyncio.StreamReader) -> list[bytes]:
    lines = []
    total = 0
    while True:
        line = await reader.readline()
        total += len(line)
        if not line or total > 16384:
            raise WSError("bad or oversized HTTP header")
        if line in (b"\r\n", b"\n"):
            return lines
        lines.append(line.rstrip(b"\r\n"))


def _headers(lines: list[bytes]) -> dict[str, str]:
    out = {}
    for ln in lines[1:]:
        k, _, v = ln.partition(b":")
        out[k.strip().lower().decode("latin-1")] = v.strip().decode("latin-1")
    return out


async def client_handshake(reader, writer, host: str, path: str = "/") -> None:
    key = base64.b64encode(os.urandom(16))
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
           f"Sec-WebSocket-Key: {key.decode()}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode()
    writer.write(req)
    await writer.drain()
    lines = await _read_head(reader)
    if not lines or b" 101" not in lines[0]:
        raise WSError(f"server refused the WebSocket upgrade: {lines[0].decode('latin-1') if lines else 'no response'}")
    if _headers(lines).get("sec-websocket-accept", "").encode() != _accept_key(key):
        raise WSError("bad Sec-WebSocket-Accept")


async def server_handshake(reader, writer) -> str:
    lines = await _read_head(reader)
    h = _headers(lines)
    if "websocket" not in h.get("upgrade", "").lower() or "sec-websocket-key" not in h:
        writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
        await writer.drain()
        raise WSError("not a WebSocket request")
    path = lines[0].split(b" ")[1].decode("latin-1") if lines and len(lines[0].split(b" ")) > 1 else "/"
    writer.write(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                 b"Sec-WebSocket-Accept: " + _accept_key(h["sec-websocket-key"].encode()) + b"\r\n\r\n")
    await writer.drain()
    return path


class WSConnection:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, *, is_client: bool):
        self.reader, self.writer, self.is_client = reader, writer, is_client
        self._wlock = asyncio.Lock()
        self.closed = False

    async def _send_frame(self, opcode: int, payload: bytes) -> None:
        n = len(payload)
        head = bytes([0x80 | opcode])
        mbit = 0x80 if self.is_client else 0
        if n < 126:
            head += bytes([mbit | n])
        elif n < 65536:
            head += bytes([mbit | 126]) + struct.pack(">H", n)
        else:
            head += bytes([mbit | 127]) + struct.pack(">Q", n)
        if self.is_client:
            mask = os.urandom(4)
            payload = bytes(b ^ mask[i & 3] for i, b in enumerate(payload))
            head += mask
        async with self._wlock:
            self.writer.write(head + payload)
            await self.writer.drain()

    async def send_text(self, text: str) -> None:
        await self._send_frame(0x1, text.encode("utf-8"))

    async def _read_frame(self) -> tuple[bool, int, bytes]:
        b1, b2 = await self.reader.readexactly(2)
        fin, opcode = bool(b1 & 0x80), b1 & 0x0F
        masked, n = bool(b2 & 0x80), b2 & 0x7F
        if n == 126:
            n = struct.unpack(">H", await self.reader.readexactly(2))[0]
        elif n == 127:
            n = struct.unpack(">Q", await self.reader.readexactly(8))[0]
        if n > MAX_MESSAGE:
            raise WSError("frame too large")
        if masked != (not self.is_client):
            raise WSError("masking rule violated")
        mask = await self.reader.readexactly(4) if masked else b""
        payload = await self.reader.readexactly(n)
        if masked:
            payload = bytes(b ^ mask[i & 3] for i, b in enumerate(payload))
        return fin, opcode, payload

    async def recv(self) -> str | None:
        """Next text message, or ``None`` when the peer closed the connection."""
        buf = b""
        try:
            while True:
                fin, op, payload = await self._read_frame()
                if op == 0x8:                       # close
                    if not self.closed:
                        self.closed = True
                        try:
                            await self._send_frame(0x8, payload[:2])
                        except (ConnectionError, OSError):
                            pass
                    return None
                if op == 0x9:                       # ping -> pong
                    await self._send_frame(0xA, payload)
                    continue
                if op == 0xA:
                    continue
                if op in (0x1, 0x2, 0x0):
                    buf += payload
                    if len(buf) > MAX_MESSAGE:
                        raise WSError("message too large")
                    if fin:
                        return buf.decode("utf-8", "replace")
                else:
                    raise WSError(f"unsupported opcode {op}")
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            return None

    async def close(self) -> None:
        if not self.closed:
            self.closed = True
            try:
                await self._send_frame(0x8, struct.pack(">H", 1000))
            except (ConnectionError, OSError):
                pass
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except (ConnectionError, OSError):
            pass
