"""Authenticated ICE negotiation and a bounded reliable WebRTC byte stream."""

import asyncio
import contextlib
import secrets
import sys

from aiortc import (
    RTCConfiguration,
    RTCIceServer,
    RTCPeerConnection,
    RTCSessionDescription,
)

from .aio import close_stream
from .crypto import hkdf, seal, unseal
from .errors import ProtocolViolation
from .wire import json_bytes, parse_json, uint

WINDOW = 256 * 1024
CHUNK = 16384
SIGNAL_LIMIT = 65536
PREPARE_TIMEOUT = 6
OPEN_TIMEOUT = 4


class DirectStream:
    """SCTP owns reliability; consumption credit bounds application buffers."""

    route = "direct-udp"
    close_timeout = PREPARE_TIMEOUT + 2

    def __init__(self, peer):
        self.peer = peer
        self.channel = peer.createDataChannel(
            "ssh-snakehole",
            negotiated=True,
            id=0,
            ordered=True,
            protocol="ssh-snakehole/3",
        )
        self.channel.bufferedAmountLowThreshold = WINDOW // 2
        self.reader = asyncio.StreamReader(limit=WINDOW)
        self.ready = asyncio.Event()
        self.writable = asyncio.Event()
        self.flush_lock = asyncio.Lock()
        self.credit = WINDOW
        self.unread = 0
        self.pending = bytearray()
        self.remote_eof = False
        self.local_eof = False
        self.closed = False
        self.error = None
        self.close_task = None
        self.eof_task = None
        self.prepare_task = None
        self.relay_writer = None
        self.transport = self
        self.channel.on("open", self.ready.set)
        self.channel.on("bufferedamountlow", self.writable.set)
        self.channel.on("message", self.receive)
        self.channel.on("close", self.close)

        @peer.on("connectionstatechange")
        def changed():
            if peer.connectionState in ("failed", "closed"):
                self.fail(ConnectionError("Direct UDP connection ended"))

    def receive(self, message):
        try:
            if not isinstance(message, bytes) or not message:
                raise ProtocolViolation("Invalid direct stream frame")
            kind, data = message[0], message[1:]
            if kind == 0:
                if (
                    self.remote_eof
                    or not 0 < len(data) <= CHUNK
                    or self.unread + len(data) > WINDOW
                ):
                    raise ProtocolViolation("Direct stream receive window exceeded")
                self.unread += len(data)
                self.reader.feed_data(data)
            elif kind == 1 and len(data) == 4:
                count = int.from_bytes(data, "big")
                if not 0 < count <= WINDOW - self.credit:
                    raise ProtocolViolation("Invalid direct stream credit")
                self.credit += count
                self.writable.set()
            elif kind == 2 and not data and not self.remote_eof:
                self.remote_eof = True
                self.reader.feed_eof()
            else:
                raise ProtocolViolation("Invalid direct stream frame")
        except Exception as exc:
            self.fail(exc)

    async def read(self, count=-1):
        if count < 0:
            parts = []
            while data := await self.read(CHUNK):
                parts.append(data)
            return b"".join(parts)
        data = await self.reader.read(count)
        if data:
            self.unread -= len(data)
            if not self.closed and self.channel.readyState == "open":
                self.channel.send(b"\1" + uint(len(data)))
        return data

    def write(self, data):
        if self.closed or self.local_eof:
            raise ConnectionError("Direct stream is closed")
        if len(self.pending) + len(data) > WINDOW:
            raise BufferError("Drain the direct stream before writing more")
        self.pending.extend(data)

    async def drain(self):
        async with self.flush_lock:
            while self.pending:
                self.writable.clear()
                if self.closed:
                    raise self.error or ConnectionError("Direct stream is closed")
                if not self.credit or self.channel.bufferedAmount >= WINDOW:
                    await self.writable.wait()
                    continue
                count = min(CHUNK, self.credit, len(self.pending))
                self.channel.send(b"\0" + bytes(self.pending[:count]))
                del self.pending[:count]
                self.credit -= count

    def write_eof(self):
        if not self.closed and not self.local_eof:
            self.local_eof = True
            self.eof_task = asyncio.create_task(self.finish_eof())

    async def finish_eof(self):
        try:
            await self.drain()
            if not self.closed:
                self.channel.send(b"\2")
        except Exception as exc:
            self.fail(exc)

    def fail(self, error):
        if not self.closed:
            self.error = error
            self.reader.set_exception(error)
            self.close()

    def close(self):
        if not self.closed:
            self.closed = True
            self.ready.set()
            self.writable.set()
            self.reader.feed_eof()
            self.close_task = asyncio.create_task(self.finish_close())

    abort = close

    async def finish_close(self):
        try:
            if self.eof_task:
                self.eof_task.cancel()
                await asyncio.gather(self.eof_task, return_exceptions=True)
            # aioice registers sockets after its binding loop. Let that loop
            # finish before closing so cancellation cannot orphan a socket.
            if self.prepare_task:
                await asyncio.gather(self.prepare_task, return_exceptions=True)
            closing = asyncio.create_task(self.peer.close())
            if sys.platform == "win32":
                try:
                    async with asyncio.timeout(0.25):
                        await asyncio.shield(closing)
                except TimeoutError:
                    # CPython #156920: Proactor UDP close can hang with queued
                    # writes. Abort the owned sockets, then finish aiortc close.
                    # aiortc exposes no public socket handle; these internals
                    # are bounded to the pinned aioice version and teardown.
                    connection = self.peer.sctp.transport.transport._connection
                    for protocol in tuple(connection._protocols):
                        protocol.transport.abort()
            await closing
        finally:
            self.pending.clear()
            if self.relay_writer:
                await close_stream(self.relay_writer)

    async def wait_closed(self):
        if self.close_task:
            await asyncio.shield(self.close_task)

    async def wait_open(self):
        try:
            async with asyncio.timeout(OPEN_TIMEOUT):
                await self.ready.wait()
            return not self.closed and self.channel.readyState == "open"
        except TimeoutError:
            return False


async def description(stream, kind, remote=None):
    async def prepare():
        if remote is not None:
            await stream.peer.setRemoteDescription(
                RTCSessionDescription(remote, "offer")
            )
        local = await (
            stream.peer.createOffer() if kind == "offer" else stream.peer.createAnswer()
        )
        await stream.peer.setLocalDescription(local)
        return stream.peer.localDescription.sdp

    stream.prepare_task = asyncio.create_task(prepare())
    async with asyncio.timeout(PREPARE_TIMEOUT):
        return await asyncio.shield(stream.prepare_task)


def validate_sdp(sdp):
    if sdp is not None and (
        not isinstance(sdp, str)
        or len(sdp.encode()) > 32768
        or sdp.count("a=candidate:") > 64
        or sdp.count("m=") != 1
        or "m=application " not in sdp
    ):
        raise ProtocolViolation("Invalid ICE description")


async def negotiate(reader, writer, key, *, sender, stun):
    """Choose direct UDP or the existing stream before starting SSH."""
    signal_key = hkdf(key, b"ssh-snakehole/ice-signalling/3")
    stream = None
    selected = False
    handed_off = False

    async def send(kind, attempt, value):
        data = seal(
            signal_key, json_bytes(dict(type=kind, attempt=attempt, value=value))
        )
        if len(data) > SIGNAL_LIMIT:
            raise ProtocolViolation("ICE signal exceeds limit")
        writer.write(uint(len(data)) + data)
        await writer.drain()

    async def receive(kind, attempt=None):
        async with asyncio.timeout(12):
            count = int.from_bytes(await reader.readexactly(4), "big")
            if not 40 <= count <= SIGNAL_LIMIT:
                raise ProtocolViolation("ICE signal exceeds limit")
            data = parse_json(
                unseal(signal_key, await reader.readexactly(count)), SIGNAL_LIMIT
            )
        if (
            not isinstance(data, dict)
            or set(data) != {"type", "attempt", "value"}
            or data["type"] != kind
            or not isinstance(data["attempt"], str)
            or len(data["attempt"]) != 32
            or (attempt is not None and data["attempt"] != attempt)
        ):
            raise ProtocolViolation("Invalid ICE negotiation transcript")
        return data["attempt"], data["value"]

    def create():
        return DirectStream(
            RTCPeerConnection(
                RTCConfiguration(
                    iceServers=[RTCIceServer(stun)] if stun else [],
                )
            )
        )

    try:
        if sender:
            attempt = secrets.token_hex(16)
            offer = None
            try:
                stream = create()
                offer = await description(stream, "offer")
                validate_sdp(offer)
            except (TimeoutError, OSError, ValueError):
                if stream:
                    await close_stream(stream)
                    stream = None
            await send("offer", attempt, offer)
            _, answer = await receive("answer", attempt)
            validate_sdp(answer)
            direct = False
            if stream and answer is not None:
                try:
                    await stream.peer.setRemoteDescription(
                        RTCSessionDescription(answer, "answer")
                    )
                    direct = await stream.wait_open()
                except (OSError, ValueError):
                    pass
            await send("select", attempt, direct)
            _, acknowledged = await receive("selected", attempt)
            if type(acknowledged) is not bool or acknowledged and not direct:
                raise ProtocolViolation("Invalid ICE selection")
            selected = direct and acknowledged
            await send("commit", attempt, selected)
        else:
            attempt, offer = await receive("offer")
            validate_sdp(offer)
            answer = None
            if offer is not None:
                try:
                    stream = create()
                    answer = await description(stream, "answer", offer)
                    validate_sdp(answer)
                except (TimeoutError, OSError, ValueError):
                    if stream:
                        await close_stream(stream)
                        stream = None
            await send("answer", attempt, answer)
            _, direct = await receive("select", attempt)
            if type(direct) is not bool:
                raise ProtocolViolation("Invalid ICE selection")
            acknowledged = bool(direct and stream and await stream.wait_open())
            await send("selected", attempt, acknowledged)
            _, selected = await receive("commit", attempt)
            if type(selected) is not bool or selected and not acknowledged:
                raise ProtocolViolation("Invalid ICE commit")
        if selected:
            assert stream is not None
            stream.relay_writer = writer
            handed_off = True
            return stream, stream
        return reader, writer
    finally:
        if stream and not handed_off:
            with contextlib.suppress(Exception):
                await close_stream(stream)
