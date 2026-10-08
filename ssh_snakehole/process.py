"""Run one owned child tree per SSH channel, with pipe backpressure."""

import asyncio
import contextlib
import os
import signal
import sys
from pathlib import Path

import asyncssh

from .errors import UnsupportedOperation
from .platform import create_job
from .wire import json_bytes, parse_json, uint


class ServerChannel:
    def __init__(self, process: asyncssh.SSHServerProcess[bytes]) -> None:
        self.process = process
        self.stdin = process.stdin

    async def send(self, data: bytes, *, stderr: bool = False) -> None:
        writer = self.process.stderr if stderr else self.process.stdout
        writer.write(data)
        await writer.drain()

    async def exit(self, status: int) -> None:
        if status >= 0:
            self.process.exit(status)
        else:
            self.process.exit_with_signal(
                signal.Signals(-status).name.removeprefix("SIG")
            )


def login_shell() -> list[str]:
    if sys.platform == "win32":
        return [
            os.path.join(
                os.environ["SystemRoot"],
                "System32",
                "WindowsPowerShell",
                "v1.0",
                "powershell.exe",
            ),
            "-NoLogo",
        ]
    import pwd

    shell = os.environ.get("SHELL") or pwd.getpwuid(os.geteuid()).pw_shell
    if not shell or shell.endswith(("/nologin", "/false")):
        shell = "/bin/sh"
    return [shell]


def shell_command(
    command: str, *, terminal: bool = False
) -> tuple[str | list[str], bool]:
    if "\0" in command or len(command.encode("utf-8")) > 65536:
        raise UnsupportedOperation("Invalid command text")
    if sys.platform == "win32":
        return [
            os.path.join(
                os.environ["SystemRoot"],
                "System32",
                "WindowsPowerShell",
                "v1.0",
                "powershell.exe",
            ),
            "-NoLogo",
            "-NoProfile",
            *([] if terminal else ["-NonInteractive"]),
            "-Command",
            command,
        ], False
    return command, True


def parse_argv(payload: bytes) -> list[str]:
    command = parse_json(payload, 65536)
    if (
        not isinstance(command, list)
        or not command
        or len(command) > 128
        or any(not isinstance(x, str) or "\0" in x for x in command)
    ):
        raise UnsupportedOperation("Expected a nonempty argument vector")
    return command


async def serve_command(
    channel: ServerChannel,
    command: str | list[str],
    shell: bool,
    *,
    cwd: str,
    terminal: dict | None = None,
) -> None:
    request = json_bytes({"command": command, "shell": shell, "terminal": terminal})
    if len(request) > 65536:
        raise UnsupportedOperation("Command request exceeds limit")
    job = create_job() if sys.platform == "win32" else None
    process = None
    tasks = []
    read_fd: int | None = None
    write_fd: int | None = None
    try:
        if sys.platform != "win32":
            read_fd, write_fd = os.pipe()
        root = str(Path(__file__).resolve().parent.parent)
        worker = "import sys;sys.path.insert(0,sys.argv.pop(1));from ssh_snakehole.worker import main;main()"
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            *(["-I"] if sys.flags.isolated else []),
            "-c",
            worker,
            root,
            job.name if job else "",
            str(os.getpid()),
            str(read_fd or 0),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=sys.platform != "win32",
            limit=65536,
            cwd=cwd,
            pass_fds=(read_fd,) if read_fd is not None else (),
            env={
                key: value
                for key, value in os.environ.items()
                if not key.startswith("SSH_SNAKEHOLE_")
            },
        )
        stdin, stdout, stderr = process.stdin, process.stdout, process.stderr
        assert stdin is not None and stdout is not None and stderr is not None
        if read_fd is not None:
            os.close(read_fd)
            read_fd = None
        async with asyncio.timeout(10):
            if await stdout.readexactly(6) != b"READY\n":
                raise UnsupportedOperation("Command containment failed")
        stdin.write(uint(len(request)) + request)
        await stdin.drain()

        async def input_pipe():
            try:
                while True:
                    try:
                        data = await channel.stdin.read(32768)
                        if not data:
                            break
                        frame = b"D" + data if terminal else data
                    except asyncssh.TerminalSizeChanged as event:
                        if not terminal or not all(
                            1 <= n <= 1000 for n in event.term_size[:2]
                        ):
                            continue
                        frame = b"R" + uint(event.width) + uint(event.height)
                    except asyncssh.SignalReceived as event:
                        if not terminal or event.signal not in (
                            "INT",
                            "QUIT",
                            "TERM",
                            "HUP",
                            "KILL",
                            "WINCH",
                        ):
                            continue
                        frame = b"S" + event.signal.encode("ascii")
                    stdin.write(uint(len(frame)) + frame if terminal else frame)
                    await stdin.drain()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                stdin.close()

        async def output_pipe(pipe, stderr=False):
            while data := await pipe.read(32768):
                await channel.send(data, stderr=stderr)

        tasks = [
            asyncio.create_task(input_pipe()),
            asyncio.create_task(output_pipe(stdout)),
            asyncio.create_task(output_pipe(stderr, True)),
        ]
        # Pipe EOF can be held open by surviving children. Observe the worker's
        # exit first, then close its owned command tree before draining the pipes.
        while process.returncode is None:
            for task in tasks:
                if task.done() and not task.cancelled():
                    task.result()
            await asyncio.sleep(0.01)
        status = process.returncode
        if job:
            job.close()
        if write_fd is not None:
            os.close(write_fd)
            write_fd = None
        await asyncio.gather(*tasks[1:])
        tasks[0].cancel()
        await channel.exit(status)
    finally:
        for descriptor in (read_fd, write_fd):
            if descriptor is not None:
                os.close(descriptor)
        if job:
            job.close()
        elif process and sys.platform != "win32":
            # The acknowledged pipe watcher owns group termination. After it
            # exits, the numeric group ID may be retired or reused. Never signal
            # that group from the parent; kill only our still-running worker.
            with contextlib.suppress(ProcessLookupError):
                if process.returncode is None:
                    process.kill()
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if process:
            with contextlib.suppress(TimeoutError):

                async def drain(pipe):
                    while await pipe.read(32768):
                        pass

                async with asyncio.timeout(5):
                    await asyncio.gather(
                        process.wait(), drain(process.stdout), drain(process.stderr)
                    )
