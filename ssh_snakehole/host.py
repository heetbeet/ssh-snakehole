"""A foreground host owns one invitation, SSH identities, connections and children."""

from __future__ import annotations

import asyncio
import math
import os
import platform
import secrets
import time
from collections.abc import Coroutine
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import asyncssh

from .errors import (
    CodeConsumed,
    PairingExpired,
    ProtocolViolation,
    SessionExpired,
    UnsupportedOperation,
)
from .idle import Idle
from .pairing import MAILBOX, Pairing
from .platform import check_privilege, check_runtime, process_user
from .process import ServerChannel, parse_argv, serve_command, shell_command
from .sftp import SFTPServer
from .ssh import SSHConnection, key_blob, key_public
from .ticket import SCHEMA, HostInfo, digest, strict, timestamp
from .transit import RELAY, dial, endpoint
from .wire import b64, unb64


@dataclass(frozen=True)
class RelayConfig:
    mailbox: str = MAILBOX
    transit: str = RELAY

    def __post_init__(self) -> None:
        endpoint(self.transit)


@dataclass(frozen=True)
class CloseReason:
    reason: str
    timestamp: str


class Host:
    def __init__(
        self,
        *,
        lifetime: float | None = None,
        idle_timeout: float = 1800,
        admin: bool = False,
        relay: RelayConfig | None = None,
    ) -> None:
        if lifetime is not None and (
            isinstance(lifetime, bool)
            or not isinstance(lifetime, (int, float))
            or not math.isfinite(lifetime)
            or lifetime <= 0
        ):
            raise ValueError("Lifetime must be positive")
        self.lifetime, self.admin, self.relay = lifetime, admin, relay or RelayConfig()
        self.idle = Idle(idle_timeout)
        self.pairing: Pairing | None = None
        self.tasks: set[asyncio.Task[None]] = set()
        self.connections: set[SSHConnection] = set()
        self.close_owner: asyncio.Task | None = None
        self.closing_tasks: set[asyncio.Task] = set()
        self.seed: bytes | None = None
        self.authorized: bytes | None = None
        self.ready = asyncio.Event()
        self.closed = asyncio.Event()
        self.closing = False
        self.error: Exception | None = None
        self._code: str | None = None
        self.accepted = False
        self.first_auth = False

    @property
    def code(self) -> str:
        if self.accepted:
            raise CodeConsumed("Pairing code has been consumed")
        if self._code is None:
            raise SessionExpired("Host is not open")
        return self._code

    def task(self, operation: Coroutine[Any, Any, None]) -> asyncio.Task[None]:
        task = asyncio.create_task(operation)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return task

    async def __aenter__(self) -> Host:
        if self.closing or self.seed is not None:
            raise RuntimeError("Host can only be opened once")
        check_runtime(host=True)
        privilege = check_privilege(self.admin)
        home = Path.home()
        self.cwd = str(home if home.is_dir() else Path.cwd())
        self.seed = secrets.token_bytes(32)
        self.expires = (
            time.time() + self.lifetime if self.lifetime is not None else None
        )
        self.deadline = (
            time.monotonic() + self.lifetime if self.lifetime is not None else math.inf
        )
        os_name = (
            "windows"
            if os.name == "nt"
            else "macos"
            if platform.system() == "Darwin"
            else "linux"
        )
        self.offer = dict(
            schema=SCHEMA,
            type="offer",
            role="host",
            session_id=secrets.token_hex(16),
            host_key="ssh-ed25519 " + b64(key_blob(self.seed)),
            transit_key=b64(secrets.token_bytes(32)),
            host_side=secrets.token_hex(8),
            operator_side=secrets.token_hex(8),
            relay=self.relay.transit,
            host_os=os_name,
            host_name=platform.node()[:128],
            process_user=process_user()[:128],
            privilege=privilege,
            expires_at=timestamp(self.expires) if self.expires is not None else None,
            idle_timeout=self.idle.timeout,
        )
        self.info = HostInfo.from_offer(self.offer)
        try:
            async with asyncio.timeout(40):
                self.pairing = await Pairing.open(self.relay.mailbox)
                self._code = await self.pairing.allocate()
            self.task(self._pair())
            if self.lifetime is not None:
                self.task(self._expire())
            return self
        except BaseException:
            await self.aclose()
            raise

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    async def _expire(self) -> None:
        await asyncio.sleep(max(0, self.deadline - time.monotonic()))
        self.error = SessionExpired("Host lifetime expired")
        await self.aclose()

    async def _pair(self) -> None:
        pairing = self.pairing
        assert pairing is not None
        try:
            async with asyncio.timeout(
                min(600, self.lifetime) if self.lifetime is not None else 600
            ):
                await pairing.establish()
                await pairing.send("0", self.offer)
                accept = await pairing.receive("0")
                strict(
                    accept,
                    ("session_id", "offer_hash", "client_key"),
                    kind="accept",
                    role="operator",
                )
                if accept["session_id"] != self.offer["session_id"] or accept[
                    "offer_hash"
                ] != digest(self.offer):
                    raise ProtocolViolation("Pairing transcript mismatch")
                if not isinstance(accept["client_key"], str) or not accept[
                    "client_key"
                ].startswith("ssh-ed25519 "):
                    raise ProtocolViolation("Invalid operator key")
                self.authorized = unb64(accept["client_key"].split(" ")[1])
                key_public(self.authorized)
                await pairing.send(
                    "1",
                    dict(
                        schema=SCHEMA,
                        type="ready",
                        role="host",
                        session_id=self.offer["session_id"],
                        accept_hash=digest(accept),
                    ),
                )
                self.accepted = True
                self._code = None
            await pairing.aclose()
            self.pairing = None
            self.ready.set()
            self.task(self._accept_loop())
            self.task(self._first_auth_deadline())
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.error = (
                PairingExpired("Pairing expired")
                if isinstance(exc, TimeoutError)
                else exc
            )
            await self.aclose()

    async def _first_auth_deadline(self) -> None:
        await asyncio.sleep(120)
        if not self.first_auth:
            self.error = SessionExpired("No SSH authentication followed pairing")
            await self.aclose()

    async def _accept_loop(self) -> None:
        delay = 1
        while not self.closing:
            try:
                if len(self.connections) >= 8:
                    await asyncio.sleep(0.2)
                    continue
                async with asyncio.timeout(
                    min(270, max(0, self.deadline - time.monotonic()))
                ):
                    reader, writer = await dial(
                        unb64(self.offer["transit_key"], 32),
                        self.offer["host_side"],
                        sender=True,
                        relay=self.relay.transit,
                    )
                connection = SSHConnection(
                    reader,
                    writer,
                    server=True,
                    seed=self.seed,
                    authorized=self.authorized,
                    handler=self._command,
                    sftp_factory=lambda channel: SFTPServer(
                        channel, self.cwd, self.idle
                    ),
                )
                self.connections.add(connection)
                self.task(self._connection(connection))
                delay = 1
            except asyncio.CancelledError:
                raise
            except Exception:
                await asyncio.sleep(delay)
                delay = min(10, delay * 2)

    async def _connection(self, connection: SSHConnection) -> None:
        try:
            await connection.start()
            self.idle.touch()
            if not self.first_auth:
                self.first_auth = True
                self.task(self._idle_expire())
            await connection.wait_closed()
        except Exception:
            await connection.aclose()
        finally:
            await connection.aclose()
            self.connections.discard(connection)

    async def _idle_expire(self) -> None:
        await self.idle.wait_expired()
        self.error = SessionExpired("Access expired after inactivity")
        await self.aclose()

    async def _command(self, process: asyncssh.SSHServerProcess[bytes]) -> None:
        with self.idle.operation():
            await self._operation(process)

    async def _operation(self, process: asyncssh.SSHServerProcess[bytes]) -> None:
        command: str | list[str]
        if process.subsystem == "snakehole-keepalive":
            async with asyncio.timeout(10):
                identifier = await process.stdin.read(64)
            if identifier != self.info.session_id.encode() + b"\n":
                process.exit(1)
            else:
                process.stdout.write(b"alive\n")
                process.exit(0)
            return
        if process.subsystem == "snakehole-control":
            async with asyncio.timeout(10):
                identifier = await process.stdin.read(64)
            if (
                identifier == self.info.session_id.encode() + b"\n"
                and self._close_request(self.info.session_id)
            ):
                process.stdout.write(b"closed\n")
                process.exit(0)
            else:
                process.exit(1)
            return
        if process.subsystem == "snakehole-argv":
            async with asyncio.timeout(10):
                count = int.from_bytes(await process.stdin.readexactly(4), "big")
                if not 1 <= count <= 65536:
                    raise ProtocolViolation("Argument vector exceeds limit")
                payload = await process.stdin.readexactly(count)
            command, shell = parse_argv(payload), False
        elif process.command is not None:
            command, shell = shell_command(process.command)
        else:
            raise UnsupportedOperation("Use command execution")
        await serve_command(ServerChannel(process), command, shell, cwd=self.cwd)

    def _close_request(self, session_id: str) -> bool:
        if session_id != self.info.session_id or self.closing:
            return False
        asyncio.get_running_loop().call_later(0.1, lambda: self.task(self.aclose()))
        return True

    async def wait_ready(self) -> None:
        await self.ready.wait()
        if not self.accepted:
            raise self.error or SessionExpired("Host closed")

    async def wait_closed(self) -> CloseReason:
        await self.closed.wait()
        return self.close_reason

    async def aclose(self) -> None:
        if self.closing:
            if (
                asyncio.current_task() is not self.close_owner
                and asyncio.current_task() not in self.closing_tasks
            ):
                await self.closed.wait()
            return
        self.close_owner = asyncio.current_task()
        self.closing = True
        self._code = None
        tasks = [task for task in self.tasks if task is not asyncio.current_task()]
        self.closing_tasks = set(tasks)
        for task in tasks:
            task.cancel()
        cleanup = asyncio.create_task(self._finish_close(tasks))
        cancelled = False
        try:
            while True:
                try:
                    await asyncio.shield(cleanup)
                    break
                except asyncio.CancelledError:
                    cancelled = True
                    if cleanup.cancelled():
                        raise
        finally:
            if cancelled:
                raise asyncio.CancelledError

    async def _finish_close(self, tasks: list[asyncio.Task[None]]) -> None:
        try:
            operations = [connection.aclose() for connection in tuple(self.connections)]
            if self.pairing:
                operations.append(self.pairing.aclose())
                self.pairing = None
            await asyncio.gather(*operations, return_exceptions=True)
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            self.seed = None
            self.authorized = None
            self.ready.set()
            self.close_reason = CloseReason(
                type(self.error).__name__ if self.error else "closed",
                timestamp(time.time()),
            )
            self.closed.set()


def open_host(
    *,
    lifetime: float | None = None,
    idle_timeout: float = 1800,
    admin: bool = False,
    relay: RelayConfig | None = None,
) -> Host:
    return Host(lifetime=lifetime, idle_timeout=idle_timeout, admin=admin, relay=relay)
