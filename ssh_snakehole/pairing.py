"""Magic Wormhole mailbox and symmetric SPAKE2, with bounded phase storage."""

import asyncio
import contextlib
import datetime
import hashlib
import importlib.resources
import json
import re
import secrets
import time

from spake2 import SPAKE2_Symmetric as SPAKE
from spake2 import SPAKEError

from .crypto import hkdf, seal, unseal
from .errors import InvalidCode, PairingFailed, ProtocolViolation
from .websocket import WebSocket
from .wire import json_bytes, parse_json

APPID = "io.github.heetbeet.ssh-snakehole/v2"
MAILBOX = "wss://relay.magic-wormhole.io/v1"


def hashcash(challenge):
    bits, resource = challenge.get("bits"), challenge.get("resource")
    if (
        type(bits) is not int
        or not 0 <= bits <= 22
        or not isinstance(resource, str)
        or len(resource) > 1024
        or ":" in resource
    ):
        raise PairingFailed("Unsupported mailbox proof-of-work challenge")
    date = datetime.datetime.now(datetime.UTC).strftime("%y%m%d")
    prefix = f"1:{bits}:{date}:{resource}::{secrets.token_hex(12)}:"
    deadline = time.monotonic() + 30
    for counter in range(2**26):
        stamp = prefix + format(counter, "x")
        if (
            int.from_bytes(hashlib.sha1(stamp.encode("utf-8")).digest(), "big")
            >> (160 - bits)
            == 0
        ):
            return stamp
        if counter % 4096 == 0 and time.monotonic() > deadline:
            break
    raise PairingFailed("Mailbox proof-of-work exceeded its time limit")


def words():
    return json.loads(
        importlib.resources.files("ssh_snakehole")
        .joinpath("words.json")
        .read_text("utf-8")
    )


def validate_code(code):
    if not isinstance(code, str) or len(code) > 256:
        raise InvalidCode("Invalid pairing code")
    parts = code.strip().lower().split("-")
    lists = words()
    if len(parts) != 5 or not re.fullmatch(r"[0-9]{1,40}", parts[0]):
        raise InvalidCode("Expected number and four words")
    if any(word not in lists[i % 2] for i, word in enumerate(parts[1:])):
        raise InvalidCode("Unknown pairing word")
    return "-".join(parts)


class Pairing:
    def __init__(self, ws):
        self.ws = ws
        self.side = secrets.token_hex(8)
        self.peer = None
        self.phases = {}
        self.seen = {}
        self.nameplate = self.mailbox = None
        self.key = None
        self.released = False

    @classmethod
    async def open(cls, url=MAILBOX):
        self = cls(await WebSocket.connect(url))
        try:
            welcome = await self.response("welcome")
            permissions = welcome.get("welcome", {}).get(
                "permission-required", {"none": {}}
            )
            if not isinstance(permissions, dict):
                raise ProtocolViolation("Invalid mailbox permissions")
            if "none" not in permissions:
                if "hashcash" not in permissions or not isinstance(
                    permissions["hashcash"], dict
                ):
                    raise PairingFailed(
                        "Mailbox requires unsupported permission challenge"
                    )
                stamp = await asyncio.to_thread(hashcash, permissions["hashcash"])
                await self.command("submit-permissions", method="hashcash", stamp=stamp)
            await self.command("bind", appid=APPID, side=self.side)
            return self
        except BaseException:
            await self.ws.aclose()
            raise

    async def command(self, kind, **fields):
        await self.ws.send(
            json_bytes(dict(type=kind, id=secrets.token_hex(4), **fields)).decode(
                "ascii"
            )
        )

    async def response(self, kind):
        while True:
            message = parse_json(await self.ws.receive(), 65536)
            if not isinstance(message, dict):
                raise ProtocolViolation("Expected mailbox object")
            if message.get("type") == "error":
                raise PairingFailed("Mailbox rejected the pairing operation")
            if message.get("type") == "message":
                self._store(message)
            if message.get("type") == kind:
                return message

    def _store(self, message):
        side, phase, body = (message.get(x) for x in ("side", "phase", "body"))
        if side == self.side:
            return
        if not isinstance(side, str) or not re.fullmatch(r"[0-9a-f]{2,64}", side):
            raise ProtocolViolation("Invalid mailbox side")
        if self.peer and side != self.peer:
            raise PairingFailed("Pairing code was claimed by more than two peers")
        self.peer = side
        if phase not in ("pake", "version", "0", "1"):
            raise ProtocolViolation("Unexpected pairing phase")
        if not isinstance(body, str) or len(body) > 18000:
            raise ProtocolViolation("Pairing message exceeds limit")
        try:
            raw = bytes.fromhex(body)
        except ValueError as exc:
            raise ProtocolViolation("Invalid mailbox message") from exc
        if phase in self.seen:
            if self.seen[phase] != raw:
                raise PairingFailed("Conflicting pairing message")
            return
        self.seen[phase] = raw
        self.phases[phase] = raw

    async def allocate(self):
        await self.command("allocate")
        nameplate = (await self.response("allocated"))["nameplate"]
        lists = words()
        code = (
            nameplate + "-" + "-".join(secrets.choice(lists[i % 2]) for i in range(4))
        )
        await self.claim(code)
        return code

    async def claim(self, code):
        self.code = validate_code(code)
        self.nameplate = self.code.split("-", 1)[0]
        await self.command("claim", nameplate=self.nameplate)
        self.mailbox = (await self.response("claimed"))["mailbox"]
        if not isinstance(self.mailbox, str) or len(self.mailbox) > 256:
            raise ProtocolViolation("Invalid mailbox ID")
        await self.command("open", mailbox=self.mailbox)

    async def phase(self, phase):
        while phase not in self.phases:
            await self.response("message")
        return self.phases.pop(phase)

    async def establish(self):
        pake = await asyncio.to_thread(
            SPAKE, self.code.encode("ascii"), APPID.encode("ascii")
        )
        await self.command(
            "add", phase="pake", body=json_bytes({"pake_v1": pake.start().hex()}).hex()
        )
        peer = parse_json(await self.phase("pake"))
        try:
            self.key = await asyncio.to_thread(
                pake.finish, bytes.fromhex(peer["pake_v1"])
            )
        except (ValueError, KeyError, TypeError, SPAKEError) as exc:
            raise PairingFailed("Pairing key agreement failed") from exc
        self.code = None
        del pake
        await self.command("release", nameplate=self.nameplate)
        self.released = True
        await self.send("version", {"app_versions": {"ssh-snakehole": 2}})
        version = await self.receive("version")
        if version != {"app_versions": {"ssh-snakehole": 2}}:
            raise PairingFailed("Unsupported pairing peer")

    def phase_key(self, side, phase):
        assert self.key is not None
        return hkdf(
            self.key,
            b"wormhole:phase:"
            + hashlib.sha256(side.encode("ascii")).digest()
            + hashlib.sha256(phase.encode("ascii")).digest(),
        )

    async def send(self, phase, value):
        ciphertext = seal(self.phase_key(self.side, phase), json_bytes(value))
        await self.command("add", phase=phase, body=ciphertext.hex())

    async def receive(self, phase):
        body = await self.phase(phase)
        try:
            return parse_json(unseal(self.phase_key(self.peer, phase), body))
        except ValueError as exc:
            raise PairingFailed("Pairing code did not authenticate") from exc

    async def aclose(self):
        try:
            with contextlib.suppress(Exception):
                async with asyncio.timeout(2):
                    if self.nameplate and not self.released:
                        await self.command("release", nameplate=self.nameplate)
                    if self.mailbox:
                        await self.command(
                            "close",
                            mailbox=self.mailbox,
                            mood="happy" if self.key else "lonely",
                        )
                        await self.response("closed")
        finally:
            self.code = None
            self.key = None
            await self.ws.aclose()
