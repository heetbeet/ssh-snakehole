"""Asyncio streams for wsproto, with verified TLS on secure relay URLs."""

import asyncio
import contextlib
import os
import ssl
from collections import deque
from urllib.parse import urlsplit

import certifi
from wsproto import ConnectionType, WSConnection
from wsproto.events import (
    AcceptConnection,
    BytesMessage,
    CloseConnection,
    Event,
    Ping,
    Pong,
    Request,
    TextMessage,
)

from .aio import close_stream
from .errors import ProtocolViolation, RelayUnavailable


class WebSocket:
    def __init__(self, reader, writer, protocol, limit=65536):
        self.reader, self.writer, self.protocol = reader, writer, protocol
        self.limit = limit
        self.events: deque[Event] = deque()
        self.parts = []
        self.size = 0
        self.lock = asyncio.Lock()
        self.closed = False
        self.binary_only = False

    @classmethod
    async def connect(cls, url, *, limit=65536):
        parsed = urlsplit(url)
        if (
            parsed.scheme not in ("ws", "wss")
            or not parsed.hostname
            or parsed.username is not None
            or parsed.fragment
        ):
            raise ValueError("Expected a ws:// or wss:// relay URL")
        tls = None
        if parsed.scheme == "wss":
            # Python's Windows CA import can select an expired store certificate.
            # Use Mozilla's roots, or an explicitly configured private CA bundle.
            tls = ssl.create_default_context(
                cafile=os.environ.get("SSL_CERT_FILE") or certifi.where(),
                capath=os.environ.get("SSL_CERT_DIR") or None,
            )
        reader, writer = await asyncio.open_connection(
            parsed.hostname, parsed.port or (443 if tls else 80), ssl=tls, limit=65536
        )
        ws = cls(reader, writer, WSConnection(ConnectionType.CLIENT), limit)
        try:
            target = parsed.path or "/"
            if parsed.query:
                target += "?" + parsed.query
            await ws.send_event(Request(host=parsed.netloc, target=target))
            event = await ws.next_event()
            if not isinstance(event, AcceptConnection):
                raise RelayUnavailable("WebSocket upgrade rejected")
            return ws
        except BaseException:
            await ws.aclose()
            raise

    async def send_event(self, event):
        async with self.lock:
            self.writer.write(self.protocol.send(event))
            async with asyncio.timeout(30):
                await self.writer.drain()

    async def next_event(self):
        while not self.events:
            data = await self.reader.read(16384)
            if not data:
                raise EOFError("WebSocket closed")
            self.protocol.receive_data(data)
            self.events.extend(self.protocol.events())
        return self.events.popleft()

    async def send(self, data):
        if len(data) > self.limit:
            raise ProtocolViolation("WebSocket message exceeds limit")
        await self.send_event(
            TextMessage(data=data) if isinstance(data, str) else BytesMessage(data=data)
        )

    async def receive(self):
        while True:
            event = await self.next_event()
            if isinstance(event, Ping):
                await self.send_event(event.response())
            elif isinstance(event, Pong):
                continue
            elif isinstance(event, CloseConnection):
                raise EOFError("WebSocket peer closed")
            elif isinstance(event, (TextMessage, BytesMessage)):
                if self.binary_only and isinstance(event, TextMessage):
                    raise ProtocolViolation(
                        "Transit requires binary WebSocket messages"
                    )
                chunk = (
                    event.data.encode("utf-8")
                    if isinstance(event.data, str)
                    else event.data
                )
                self.size += len(chunk)
                if self.size > self.limit:
                    raise ProtocolViolation("WebSocket message exceeds limit")
                if chunk:
                    self.parts.append(chunk)
                if event.message_finished:
                    result = b"".join(self.parts)
                    self.parts.clear()
                    self.size = 0
                    return result
            else:
                raise ProtocolViolation("Unexpected WebSocket event")

    async def aclose(self):
        if self.closed:
            return
        self.closed = True
        try:
            if self.protocol.state.name == "OPEN":
                with contextlib.suppress(Exception):
                    async with asyncio.timeout(1):
                        await self.send_event(CloseConnection(code=1000, reason=""))
        finally:
            await close_stream(self.writer)


class WebSocketStream:
    """Binary WebSocket messages as a bounded byte stream for Transit and SSH."""

    def __init__(self, ws):
        self.ws = ws
        self.input = bytearray()
        self.output = bytearray()
        self.closed = False
        ws.binary_only = True

    @property
    def transport(self):
        return self.ws.writer.transport

    async def read(self, count=32768):
        if count <= 0:
            return b""
        while not self.input:
            try:
                self.input.extend(await self.ws.receive())
            except EOFError:
                return b""
        result = bytes(self.input[:count])
        del self.input[:count]
        return result

    async def readexactly(self, count):
        if count > 262160:
            raise ProtocolViolation("Transit stream read exceeds limit")
        result = bytearray()
        while len(result) < count:
            data = await self.read(count - len(result))
            if not data:
                raise asyncio.IncompleteReadError(bytes(result), count)
            result.extend(data)
        return bytes(result)

    async def readuntil(self, separator=b"\n"):
        result = bytearray()
        while not result.endswith(separator):
            result.extend(await self.readexactly(1))
            if len(result) > 4096:
                raise ProtocolViolation("Transit line exceeds limit")
        return bytes(result)

    def write(self, data):
        if self.closed:
            raise EOFError("Transit stream closed")
        if len(self.output) + len(data) > 262160:
            raise ProtocolViolation("Transit write buffer exceeds limit")
        self.output.extend(data)

    async def drain(self):
        if self.output:
            data = bytes(self.output)
            self.output.clear()
            await self.ws.send(data)

    def close(self):
        self.closed = True
        self.ws.writer.close()

    async def wait_closed(self):
        await self.ws.aclose()
