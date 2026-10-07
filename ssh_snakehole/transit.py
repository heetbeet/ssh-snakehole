"""Outbound Magic Wormhole Transit rendezvous. SSH authenticates the stream."""
import asyncio
import contextlib
from urllib.parse import urlsplit

from ._crypto import hkdf
from .errors import ProtocolViolation
from .websocket import WebSocket, WebSocketStream

RELAY = "tcp://transit.magic-wormhole.io:4001"


def endpoint(url):
    parsed = urlsplit(url)
    if parsed.scheme not in ("tcp","ws","wss") or not parsed.hostname or parsed.username or parsed.query or parsed.fragment:
        raise ValueError("Expected tcp://hostname:port or wss:// Transit relay")
    if parsed.scheme=="tcp" and (not parsed.port or parsed.path not in ("","/")): raise ValueError("Expected tcp://hostname:port Transit relay")
    return parsed.hostname,parsed.port or (443 if parsed.scheme=="wss" else 80)


async def dial(key, side, *, sender=False, relay=RELAY):
    endpoint(relay)
    if urlsplit(relay).scheme in ("ws","wss"):
        reader=writer=WebSocketStream(await WebSocket.connect(relay,limit=262160))
    else: reader, writer = await asyncio.open_connection(*endpoint(relay), limit=65536)
    try:
        token = hkdf(key, b"transit_relay_token").hex()
        writer.write(f"please relay {token} for side {side}\n".encode("ascii"))
        await writer.drain()
        if await reader.readexactly(3) != b"ok\n": raise ProtocolViolation("Transit relay match rejected")
        role, peer = ("sender", "receiver") if sender else ("receiver", "sender")
        own = hkdf(key, f"transit_{role}".encode()).hex()
        other = hkdf(key, f"transit_{peer}".encode()).hex()
        writer.write(f"transit {role} {own} ready\n\n".encode("ascii")); await writer.drain()
        expected = f"transit {peer} {other} ready\n\n".encode("ascii")
        if await reader.readexactly(len(expected)) != expected: raise ProtocolViolation("Transit peer greeting did not authenticate")
        if sender:
            writer.write(b"go\n"); await writer.drain()
        elif await reader.readexactly(3) != b"go\n": raise ProtocolViolation("Transit leader did not select stream")
        return reader, writer
    except BaseException:
        writer.close()
        with contextlib.suppress(Exception): await writer.wait_closed()
        raise
