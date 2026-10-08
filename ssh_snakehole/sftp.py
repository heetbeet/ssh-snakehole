"""AsyncSSH SFTP with regular-file handles and atomic sibling-file publication."""

import asyncio
import contextlib
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path

import asyncssh

from .aio import file_call, open_regular
from .errors import TransferFailed

DATA = 32768


def local_path(value):
    if "\0" in value:
        raise ValueError("NUL in path")
    if os.name != "nt":
        return value
    value = value.replace("\\", "/")
    if value.startswith("//") or value.startswith("/dev/"):
        raise ValueError("UNC and device paths are not supported")
    if len(value) > 3 and value[0] == "/" and value[1].isalpha() and value[2:4] == ":/":
        value = value[1:]
    drive, tail = os.path.splitdrive(value)
    if ":" in tail or drive and not tail.startswith("/"):
        raise ValueError("Alternate streams and drive-relative paths are not supported")
    for part in tail.split("/"):
        if part in (".", ".."):
            continue
        if part.endswith((".", " ")) or part.split(".", 1)[0].upper() in {
            "CON",
            "PRN",
            "AUX",
            "NUL",
            *(f"COM{i}" for i in range(1, 10)),
            *(f"LPT{i}" for i in range(1, 10)),
        }:
            raise ValueError("Ambiguous Windows path")
    return value


def commit(source, destination, overwrite):
    if overwrite:
        os.replace(source, destination)
    else:
        os.link(source, destination)
        os.unlink(source)


class SFTPServer(asyncssh.SFTPServer):
    def __init__(self, channel, cwd, activity=None):
        super().__init__(channel)
        self.cwd = cwd
        self.files = set()
        self.activity = activity
        self.operations = {}

    def map_path(self, path):
        if self.activity is not None:
            self.activity.touch()
        path = local_path(os.fsdecode(path))
        return os.fsencode(
            path if os.path.isabs(path) else os.path.join(self.cwd, path)
        )

    def open(self, path, flags, attrs):
        if (
            flags & ~63
            or not flags & 3
            or flags & (4 | 16)
            and not flags & 2
            or flags & 32
            and not flags & 8
        ):
            raise asyncssh.SFTPInvalidParameter("Invalid SFTP open flags")
        if len(self.files) >= 64:
            raise asyncssh.SFTPFailure("File handle limit reached")
        mode = (
            os.O_RDWR if flags & 3 == 3 else os.O_WRONLY if flags & 2 else os.O_RDONLY
        )
        for bit, option in (
            (4, os.O_APPEND),
            (8, os.O_CREAT),
            (16, os.O_TRUNC),
            (32, os.O_EXCL),
        ):
            if flags & bit:
                mode |= option
        fd = os.open(
            self.map_path(path),
            mode | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0),
            0o600 if attrs.permissions is None else attrs.permissions & 0o777,
        )
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise asyncssh.SFTPOpUnsupported("Regular files required")
            file = os.fdopen(
                fd,
                "r+b" if flags & 3 == 3 else "wb" if flags & 2 else "rb",
                buffering=0,
            )
        except BaseException:
            os.close(fd)
            raise
        self.files.add(file)
        if self.activity is not None:
            operation = self.activity.operation()
            operation.__enter__()
            self.operations[file] = operation
        return file

    async def read(self, file, offset, size):
        if size > 4 * 1024 * 1024:
            raise asyncssh.SFTPInvalidParameter("Read exceeds the advertised limit")
        return await file_call(super().read, file, offset, size)

    async def write(self, file, offset, data):
        def write():
            file.seek(offset)
            view = memoryview(data)
            while view:
                count = file.write(view)
                if not count:
                    raise OSError("Short file write")
                view = view[count:]
            return len(data)

        return await file_call(write)

    async def close(self, file):
        try:
            await file_call(file.close)
        finally:
            self.files.discard(file)
            operation = self.operations.pop(file, None)
            if operation is not None:
                operation.__exit__(None, None, None)

    async def fsync(self, file):
        await file_call(os.fsync, file.fileno())

    async def exit(self):
        for file in tuple(self.files):
            await self.close(file)


@dataclass(frozen=True)
class TransferResult:
    bytes_copied: int
    destination: str
    durable: bool


def attrs(value: asyncssh.SFTPAttrs) -> dict[str, int | float]:
    return {
        key: getattr(value, key)
        for key in ("size", "permissions", "uid", "gid", "atime", "mtime")
        if getattr(value, key) is not None
    }


class Files:
    def __init__(
        self, connection: asyncssh.SSHClientConnection, client: asyncssh.SFTPClient
    ) -> None:
        self.connection = connection
        self.client = client
        self.closed = False

    @classmethod
    async def start(cls, connection: asyncssh.SSHClientConnection) -> "Files":
        async with asyncio.timeout(30):
            client = await connection.start_sftp_client(sftp_version=3)
        return cls(connection, client)

    async def call(self, method, *args, **kwargs):
        try:
            async with asyncio.timeout(30):
                return await method(*args, **kwargs)
        except (asyncio.CancelledError, TimeoutError):
            # AsyncSSH matches replies by request ID and discards cancelled
            # waiters. End this subsystem without waiting on the blocked reply.
            self.closed = True
            self.client.exit()
            raise

    async def stat(
        self, path: str, *, follow_symlinks: bool = True
    ) -> dict[str, int | float]:
        return attrs(
            await self.call(
                self.client.stat if follow_symlinks else self.client.lstat, str(path)
            )
        )

    async def listdir(
        self, path: str = "."
    ) -> list[tuple[str, dict[str, int | float]]]:
        result: list[tuple[str, dict[str, int | float]]]
        result = []
        async with asyncio.timeout(30):
            async for entry in self.client.scandir(str(path)):
                if isinstance(entry.filename, str) and entry.filename not in (
                    ".",
                    "..",
                ):
                    result.append((entry.filename, attrs(entry.attrs)))
                if len(result) > 100000:
                    raise ValueError("Directory listing exceeds limit")
        return result

    async def mkdir(self, path: str) -> None:
        await self.call(
            self.client.mkdir, str(path), asyncssh.SFTPAttrs(permissions=0o700)
        )

    async def remove(self, path: str) -> None:
        await self.call(self.client.remove, str(path))

    async def rmdir(self, path: str) -> None:
        await self.call(self.client.rmdir, str(path))

    async def put(
        self,
        source: str | os.PathLike[str],
        destination: str,
        *,
        overwrite: bool = False,
    ) -> TransferResult:
        temporary = str(destination) + ".snakehole-" + secrets.token_hex(8)
        total = 0
        committed = False
        commit_started = False
        handle = None
        try:
            with open_regular(source) as file:
                handle = await self.call(
                    self.client.open,
                    temporary,
                    "xb",
                    encoding=None,
                    block_size=DATA,
                    max_requests=1,
                )
                while data := await file_call(file.read, DATA):
                    await self.call(handle.write, data, total)
                    total += len(data)
            durable = True
            try:
                await self.call(handle.fsync)
            except asyncssh.SFTPOpUnsupported:
                durable = False
            await self.call(handle.close)
            handle = None
            commit_started = True
            if overwrite:
                await self.call(self.client.posix_rename, temporary, str(destination))
                committed = True
            else:
                await self.call(self.client.link, temporary, str(destination))
                committed = True
                await self.remove(temporary)
            return TransferResult(total, str(destination), durable)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            known_failure = isinstance(
                exc, (asyncssh.SFTPFileAlreadyExists, asyncssh.SFTPOpUnsupported)
            )
            raise TransferFailed(
                str(exc),
                committed=committed
                if committed or not commit_started or known_failure
                else None,
                temporary=temporary,
            ) from exc
        finally:
            if handle:
                with contextlib.suppress(Exception):
                    await self.call(handle.close)
            if not committed:
                with contextlib.suppress(Exception):
                    await self.remove(temporary)

    async def get(
        self,
        source: str,
        destination: str | os.PathLike[str],
        *,
        overwrite: bool = False,
    ) -> TransferResult:
        destination_path = Path(destination)
        temporary = destination_path.with_name(
            destination_path.name + ".snakehole-" + secrets.token_hex(8)
        )
        total = 0
        committed = False
        commit_started = False
        handle = None
        try:
            handle = await self.call(
                self.client.open,
                str(source),
                "rb",
                encoding=None,
                block_size=DATA,
                max_requests=1,
            )
            fd = os.open(
                temporary,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0),
                0o600,
            )
            with os.fdopen(fd, "wb") as file:
                while data := await self.call(handle.read, DATA, total):
                    await file_call(file.write, data)
                    total += len(data)
                await file_call(file.flush)
                await file_call(os.fsync, file.fileno())
            await self.call(handle.close)
            handle = None
            commit_started = True
            await file_call(commit, temporary, destination, overwrite)
            committed = True
            return TransferResult(total, str(destination), True)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            raise TransferFailed(
                str(exc),
                committed=None
                if commit_started and not isinstance(exc, FileExistsError)
                else committed,
                temporary=str(temporary),
            ) from exc
        finally:
            if handle:
                with contextlib.suppress(Exception):
                    await self.call(handle.close)
            if not committed:
                with contextlib.suppress(OSError):
                    temporary.unlink()

    async def aclose(self) -> None:
        if self.closed:
            return
        self.closed = True
        if self.client:
            self.client.exit()
            try:
                async with asyncio.timeout(2):
                    await self.client.wait_closed()
            except TimeoutError:
                self.connection.abort()
