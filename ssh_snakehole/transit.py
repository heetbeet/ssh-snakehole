"""Outbound Magic Wormhole Transit rendezvous. SSH authenticates the stream."""

import asyncio
from urllib.parse import urlsplit

from .aio import close_stream
from .crypto import hkdf
from .errors import ProtocolViolation
from .websocket import WebSocket, WebSocketStream

RELAY = "tcp://transit.magic-wormhole.io:4001"
STUN = "stun:stun.l.google.com:19302"


def validate_stun(url):
    if url is None:
        return
    if not isinstance(url, str) or not url.startswith("stun:") or len(url) > 512:
        raise ValueError("Expected a stun:hostname:port URL or None")
    parsed = urlsplit("udp://" + url[5:])
    if (
        not parsed.hostname
        or not parsed.port
        or parsed.username is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Expected a stun:hostname:port URL or None")


def endpoint(url):
    parsed = urlsplit(url)
    if (
        parsed.scheme not in ("tcp", "ws", "wss")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Expected tcp://hostname:port or wss:// Transit relay")
    if parsed.scheme == "tcp" and (not parsed.port or parsed.path not in ("", "/")):
        raise ValueError("Expected tcp://hostname:port Transit relay")
    return parsed.hostname, parsed.port or (443 if parsed.scheme == "wss" else 80)


async def dial(key, side, *, sender=False, relay=RELAY, stun=STUN):
    endpoint(relay)
    validate_stun(stun)
    reader: asyncio.StreamReader | WebSocketStream
    writer: asyncio.StreamWriter | WebSocketStream
    if urlsplit(relay).scheme in ("ws", "wss"):
        reader = writer = WebSocketStream(await WebSocket.connect(relay, limit=262160))
    else:
        reader, writer = await asyncio.open_connection(*endpoint(relay), limit=65536)
    try:
        token = hkdf(key, b"transit_relay_token").hex()
        writer.write(f"please relay {token} for side {side}\n".encode("ascii"))
        await writer.drain()
        if await reader.readexactly(3) != b"ok\n":
            raise ProtocolViolation("Transit relay match rejected")
        role, peer = ("sender", "receiver") if sender else ("receiver", "sender")
        own = hkdf(key, f"transit_{role}".encode()).hex()
        other = hkdf(key, f"transit_{peer}".encode()).hex()
        writer.write(f"transit {role} {own} ready\n\n".encode("ascii"))
        await writer.drain()
        expected = f"transit {peer} {other} ready\n\n".encode("ascii")
        if await reader.readexactly(len(expected)) != expected:
            raise ProtocolViolation("Transit peer greeting did not authenticate")
        if sender:
            writer.write(b"go\n")
            await writer.drain()
        elif await reader.readexactly(3) != b"go\n":
            raise ProtocolViolation("Transit leader did not select stream")
        from .ice import negotiate

        return await negotiate(reader, writer, key, sender=sender, stun=stun)
    except BaseException:
        await close_stream(writer)
        raise
