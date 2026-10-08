"""Importable AsyncSSH operator API. Unknown operations are never replayed."""

from __future__ import annotations

import asyncio
import contextlib
import math
import os
import secrets
import time
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass

import asyncssh

from .errors import (
    CloseUnconfirmed,
    CommandTimedOut,
    ConnectTimeout,
    OutcomeUnknown,
    OutputLimitExceeded,
    PairingExpired,
    RelayUnavailable,
    RemoteCommandFailed,
)
from .host import RelayConfig
from .pairing import Pairing
from .platform import check_runtime
from .sftp import Files, TransferResult
from .ssh import SSHConnection, key_blob
from .ticket import SCHEMA, Ticket, digest, expiry, strict, timestamp, validate_offer
from .transit import dial
from .wire import b64, json_bytes, uint, unb64


async def pair(code: str, *, relay: RelayConfig | None = None) -> Ticket:
    check_runtime()
    config = relay or RelayConfig()
    pairing = None
    try:
        async with asyncio.timeout(120):
            pairing = await Pairing.open(config.mailbox)
            await pairing.claim(code)
            await pairing.establish()
            offer = validate_offer(await pairing.receive("0"))
            if offer["relay"] != config.transit:
                raise ValueError(
                    "Pairing relay contradicts the operator's selected relay"
                )
            seed = secrets.token_bytes(32)
            accept = dict(
                schema=SCHEMA,
                type="accept",
                role="operator",
                session_id=offer["session_id"],
                offer_hash=digest(offer),
                client_key="ssh-ed25519 " + b64(key_blob(seed)),
            )
            await pairing.send("0", accept)
            ready = await pairing.receive("1")
            strict(ready, ("session_id", "accept_hash"), kind="ready", role="host")
            if ready["session_id"] != offer["session_id"] or ready[
                "accept_hash"
            ] != digest(accept):
                raise ValueError("Pairing acceptance did not authenticate")
            ticket = Ticket(offer, seed)
            ticket.check_live()
            return ticket
    except TimeoutError as exc:
        raise PairingExpired("Pairing expired") from exc
    except (OSError, EOFError) as exc:
        raise RelayUnavailable("Pairing relay disconnected") from exc
    finally:
        if pairing:
            await pairing.aclose()


@dataclass(frozen=True)
class CommandExit:
    exit_code: int | None
    exit_signal: str | None
    elapsed: float


@dataclass(frozen=True)
class CommandResult(CommandExit):
    stdout: bytes
    stderr: bytes

    def check_returncode(self) -> CommandResult:
        if self.exit_code != 0 or self.exit_signal:
            raise RemoteCommandFailed(self)
        return self


@dataclass(frozen=True)
class CloseReceipt:
    accepted: bool
    transport_closed: bool
    timestamp: str


class RemoteProcess:
    def __init__(self, process: asyncssh.SSHClientProcess[bytes]) -> None:
        self.process = process
        self.stdout = process.stdout
        self.stderr = process.stderr
        self.started = time.monotonic()

    async def send(self, data: bytes) -> None:
        try:
            self.process.stdin.write(data)
            await self.process.stdin.drain()
        except (OSError, asyncssh.Error) as exc:
            raise OutcomeUnknown("Remote command input was interrupted") from exc

    async def close_stdin(self) -> None:
        self.process.stdin.write_eof()

    async def wait(self) -> CommandExit:
        await self.process.wait_closed()
        signal = self.process.exit_signal
        status = self.process.exit_status
        if status is None and signal is None:
            raise OutcomeUnknown("No confirmed remote exit status")
        return CommandExit(
            status if status is not None and status >= 0 else None,
            signal[0] if signal else None,
            time.monotonic() - self.started,
        )


class Session:
    def __init__(self, ticket: Ticket, connection: SSHConnection) -> None:
        assert isinstance(connection.native, asyncssh.SSHClientConnection)
        self._native = connection.native
        self.ticket = ticket
        self.info = ticket.info
        self.connection = connection
        self._files: Files | None = None
        self._files_lock = asyncio.Lock()
        self.close_receipt: CloseReceipt | None = None

    def _deadline(self, timeout: float | None) -> asyncio.Timeout:
        if timeout is not None and (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("Timeout must be a finite positive number or None")
        remaining = (
            max(0, expiry(self.info.expires_at) - time.time())
            if self.info.expires_at is not None
            else None
        )
        return asyncio.timeout(
            min(timeout, remaining)
            if timeout is not None and remaining is not None
            else timeout
            if timeout is not None
            else remaining
        )

    @contextlib.asynccontextmanager
    async def _process(
        self, command: str | list[str], argv: bool = False
    ) -> AsyncIterator[RemoteProcess]:
        self.ticket.check_live()
        process = None
        try:
            if argv:
                if (
                    not command
                    or len(command) > 128
                    or any(not isinstance(x, str) or "\0" in x for x in command)
                ):
                    raise ValueError("Expected a nonempty argument vector")
                payload = json_bytes(command)
                if len(payload) > 65536:
                    raise ValueError("Argument vector exceeds limit")
                process = await self._native.create_process(
                    subsystem="snakehole-argv", encoding=None
                )
                process.stdin.write(uint(len(payload)) + payload)
                await process.stdin.drain()
            else:
                if (
                    not isinstance(command, str)
                    or "\0" in command
                    or len(command.encode()) > 65536
                ):
                    raise ValueError("Invalid command text")
                process = await self._native.create_process(
                    command, encoding=None, request_pty=False
                )
            yield RemoteProcess(process)
        except asyncssh.Error as exc:
            raise OutcomeUnknown("SSH command outcome could not be confirmed") from exc
        finally:
            if process:
                process.close()
                try:
                    async with asyncio.timeout(2):
                        await process.wait_closed()
                except TimeoutError:
                    await self.connection.aclose()

    @contextlib.asynccontextmanager
    async def exec(
        self, command: str, *, timeout: float | None = None
    ) -> AsyncIterator[RemoteProcess]:
        try:
            async with self._deadline(timeout):
                async with self._process(command) as process:
                    yield process
        except TimeoutError as exc:
            raise CommandTimedOut() from exc

    async def _run(
        self,
        command: str | list[str],
        argv: bool,
        stdin: bytes,
        timeout: float | None,
        max_output: int,
    ) -> CommandResult:
        if type(max_output) is not int or max_output < 0:
            raise ValueError("Output limit must be a nonnegative integer")
        deadline = self._deadline(timeout)
        output = [bytearray(), bytearray()]
        total = 0
        tasks = []
        try:
            async with deadline:
                async with self._process(command, argv) as process:

                    async def capture(
                        stream: asyncssh.SSHReader[bytes], index: int
                    ) -> None:
                        nonlocal total
                        while data := await stream.read(32768):
                            room = max_output - total
                            output[index].extend(data[: max(0, room)])
                            total += len(data)
                            if total > max_output:
                                raise OutputLimitExceeded()

                    async def feed() -> None:
                        try:
                            await process.send(stdin)
                            await process.close_stdin()
                        except OutcomeUnknown:
                            if (
                                process.process.exit_status is None
                                and process.process.exit_signal is None
                            ):
                                raise

                    tasks = [
                        asyncio.create_task(capture(process.stdout, 0)),
                        asyncio.create_task(capture(process.stderr, 1)),
                        asyncio.create_task(feed()),
                    ]
                    try:
                        await asyncio.gather(*tasks)
                        result = await process.wait()
                    finally:
                        for task in tasks:
                            task.cancel()
                        await asyncio.gather(*tasks, return_exceptions=True)
                    return CommandResult(
                        result.exit_code,
                        result.exit_signal,
                        result.elapsed,
                        bytes(output[0]),
                        bytes(output[1]),
                    )
        except (TimeoutError, OutputLimitExceeded) as exc:
            error = (
                OutputLimitExceeded
                if isinstance(exc, OutputLimitExceeded)
                else CommandTimedOut
            )
            raise error(stdout=bytes(output[0]), stderr=bytes(output[1])) from exc

    async def run(
        self,
        command: str,
        *,
        stdin: bytes = b"",
        timeout: float | None = None,
        max_output: int = 8 * 1024 * 1024,
    ) -> CommandResult:
        return await self._run(command, False, stdin, timeout, max_output)

    async def run_argv(
        self,
        argv: Sequence[str],
        *,
        stdin: bytes = b"",
        timeout: float | None = None,
        max_output: int = 8 * 1024 * 1024,
    ) -> CommandResult:
        if isinstance(argv, (str, bytes)):
            raise ValueError("Expected a sequence of arguments, not command text")
        return await self._run(list(argv), True, stdin, timeout, max_output)

    async def files(self) -> Files:
        async with self._files_lock:
            if self._files is None or self._files.closed:
                self._files = await Files.start(self._native)
            return self._files

    async def put(
        self,
        source: str | os.PathLike[str],
        destination: str,
        *,
        overwrite: bool = False,
    ) -> TransferResult:
        return await (await self.files()).put(source, destination, overwrite=overwrite)

    async def get(
        self,
        source: str,
        destination: str | os.PathLike[str],
        *,
        overwrite: bool = False,
    ) -> TransferResult:
        return await (await self.files()).get(source, destination, overwrite=overwrite)

    async def keepalive(self) -> None:
        """Renew host inactivity without executing a shell command."""
        self.ticket.check_live()
        async with asyncio.timeout(10):
            async with self._native.create_process(
                subsystem="snakehole-keepalive", encoding=None
            ) as process:
                process.stdin.write(self.info.session_id.encode() + b"\n")
                process.stdin.write_eof()
                reply = await process.stdout.read(64)
                await process.wait_closed()
                if reply != b"alive\n" or process.exit_status != 0:
                    raise OutcomeUnknown("Host did not acknowledge keepalive")

    async def close_host(self) -> CloseReceipt:
        if self.close_receipt:
            return self.close_receipt
        try:
            async with asyncio.timeout(10):
                async with self._native.create_process(
                    subsystem="snakehole-control", encoding=None
                ) as process:
                    process.stdin.write(self.info.session_id.encode() + b"\n")
                    process.stdin.write_eof()
                    if await process.stdout.read(64) != b"closed\n":
                        raise CloseUnconfirmed("Host did not acknowledge revocation")
                    await process.wait_closed()
                    if process.exit_status != 0:
                        raise CloseUnconfirmed("Host rejected revocation")
                await self.connection.wait_closed()
            self.close_receipt = CloseReceipt(True, True, timestamp(time.time()))
            return self.close_receipt
        except Exception as exc:
            if isinstance(exc, CloseUnconfirmed):
                raise
            raise CloseUnconfirmed("Remote close could not be confirmed") from exc

    async def aclose(self) -> None:
        await self.connection.aclose()


@contextlib.asynccontextmanager
async def connect(
    code_or_ticket: str | Ticket,
    *,
    relay: RelayConfig | None = None,
    timeout: float = 40,
) -> AsyncIterator[Session]:
    check_runtime()
    if isinstance(timeout, bool) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("Connection timeout must be a finite positive number")
    ticket = (
        code_or_ticket
        if isinstance(code_or_ticket, Ticket)
        else await pair(code_or_ticket, relay=relay)
    )
    ticket.check_live()
    if relay is not None and relay.transit != ticket.offer["relay"]:
        raise ValueError("Ticket relay contradicts explicit configuration")
    connection = None
    try:
        async with asyncio.timeout(timeout):
            reader, writer = await dial(
                unb64(ticket.offer["transit_key"], 32),
                ticket.offer["operator_side"],
                relay=ticket.offer["relay"],
            )
            connection = SSHConnection(
                reader,
                writer,
                seed=ticket.client_seed,
                pin=unb64(ticket.offer["host_key"].split(" ")[1]),
            )
            await connection.start()
    except BaseException as exc:
        if connection:
            await connection.aclose()
        error: BaseException
        if isinstance(exc, TimeoutError):
            error = ConnectTimeout(
                "SSH connection timed out; the accepted ticket can be retried"
            )
        elif isinstance(exc, (OSError, EOFError, asyncssh.Error)):
            error = RelayUnavailable(
                "SSH relay disconnected; the accepted ticket can be retried"
            )
        else:
            error = exc
        if isinstance(error, (ConnectTimeout, RelayUnavailable)):
            error.ticket = ticket
        if error is exc:
            raise
        raise error from exc
    try:
        yield Session(ticket, connection)
    finally:
        await connection.aclose()
