"""Optional native SSH adapter. The core library never launches an SSH program."""

import asyncio
import contextlib
import os
import shlex
import sys
from pathlib import Path

from .aio import close_stream
from .platform import private_file
from .ssh import private_key
from .ticket import validate_offer
from .transit import dial
from .wire import json_bytes, parse_json, unb64


def export(ticket, directory, token):
    """Export is explicit; the native private key stays encrypted with the token."""
    ticket.check_live()
    root = Path(directory).resolve()
    from .vault import secret

    secret(token)
    route_path = root / "route.json"
    for value in (str(root), str(route_path), sys.executable):
        if any(ord(c) < 32 or c in '%!"${}' for c in value):
            raise ValueError(
                "Path cannot be represented safely in an OpenSSH configuration"
            )
    identifier = "snakehole-" + ticket.info.session_id
    # OpenSSH tokenization, followed by its local shell. Use double quotes on Windows.
    quote = (
        (lambda value: '"' + str(value).replace("\\", "/").replace('"', '\\"') + '"')
        if sys.platform == "win32"
        else lambda value: shlex.quote(str(value))
    )
    proxy = f"{quote(sys.executable)} -m ssh_snakehole proxy {quote(route_path)}"
    text = f'Host {identifier}\n    HostName {identifier}\n    User help\n    IdentityFile "{(root / "key").as_posix()}"\n    UserKnownHostsFile "{(root / "known_hosts").as_posix()}"\n    StrictHostKeyChecking yes\n    IdentitiesOnly yes\n    ProxyCommand {proxy}\n    RequestTTY no\n'
    root.mkdir(parents=True, exist_ok=False, mode=0o700)
    created = []
    try:
        if sys.platform == "win32":
            private_file(root)
        for name, data in (
            (
                "key",
                private_key(ticket.client_seed)
                .export_private_key(passphrase=token)
                .decode("ascii"),
            ),
            ("route.json", json_bytes(ticket.offer).decode("ascii")),
            ("known_hosts", identifier + " " + ticket.offer["host_key"] + "\n"),
            ("config", text),
        ):
            path = root / name
            fd: int | None = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            created.append(path)
            try:
                private_file(path)
                assert fd is not None
                with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as file:
                    fd = None
                    file.write(data)
            finally:
                if fd is not None:
                    os.close(fd)
    except BaseException:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        root.rmdir()
        raise
    return f'ssh -F "{path}" {identifier} "COMMAND"; delete {root} after use'


async def proxy(route):
    import time

    from .aio import open_regular
    from .ticket import expiry

    with open_regular(route) as file:
        offer = validate_offer(parse_json(file.read(8193)))
    if offer["expires_at"] is not None and time.time() >= expiry(offer["expires_at"]):
        raise ValueError("Native route expired")
    if sys.platform == "win32":
        import msvcrt

        msvcrt.setmode(0, os.O_BINARY)
        msvcrt.setmode(1, os.O_BINARY)
    async with asyncio.timeout(40):
        reader, writer = await dial(
            unb64(offer["transit_key"], 32),
            offer["operator_side"],
            relay=offer["relay"],
            stun=offer["stun"],
        )

    async def upstream():
        if sys.platform == "win32":
            import ctypes as c
            import msvcrt
            from ctypes import wintypes as w

            kernel = c.WinDLL("kernel32", use_last_error=True)
            kernel.PeekNamedPipe.argtypes = [
                w.HANDLE,
                c.c_void_p,
                w.DWORD,
                c.c_void_p,
                c.POINTER(w.DWORD),
                c.c_void_p,
            ]
            handle = msvcrt.get_osfhandle(0)
            while True:
                available = w.DWORD()
                if not kernel.PeekNamedPipe(
                    handle, None, 0, None, c.byref(available), None
                ):
                    if c.get_last_error() == 109:
                        break
                    raise c.WinError(c.get_last_error())
                if not available.value:
                    await asyncio.sleep(0.01)
                    continue
                data = os.read(0, min(available.value, 32768))
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        else:
            pipe = asyncio.StreamReader(limit=65536)
            transport, _ = await asyncio.get_running_loop().connect_read_pipe(
                lambda: asyncio.StreamReaderProtocol(pipe), sys.stdin.buffer
            )
            try:
                while data := await pipe.read(32768):
                    writer.write(data)
                    await writer.drain()
            finally:
                transport.close()
        with contextlib.suppress(Exception):
            writer.write_eof()

    async def downstream():
        while data := await reader.read(32768):
            view = memoryview(data)
            while view:
                count = await asyncio.to_thread(os.write, 1, view)
                view = view[count:]

    tasks = [asyncio.create_task(upstream()), asyncio.create_task(downstream())]
    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            await task
        if tasks[0] in done and tasks[1] not in done:
            import time

            from .ticket import expiry

            async with asyncio.timeout(
                max(0, expiry(offer["expires_at"]) - time.time())
                if offer["expires_at"] is not None
                else None
            ):
                await tasks[1]
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await close_stream(writer)
