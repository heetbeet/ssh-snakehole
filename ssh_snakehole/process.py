"""Run one owned child tree per SSH channel, with pipe backpressure."""
import asyncio
import contextlib
import os
import signal
import sys
from pathlib import Path
from dataclasses import dataclass

from .errors import UnsupportedOperation
from .platform import create_job
from .wire import Reader, json_bytes, parse_json, uint


def command_request(name, payload):
    r = Reader(payload)
    if name == b"exec":
        command = r.text(65536); r.done()
        if "\0" in command: raise UnsupportedOperation("NUL in command")
        if os.name == "nt":
            command = [os.path.join(os.environ["SystemRoot"], "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command]
            return command, False
        return command, True
    if name == b"exec-argv@ssh-snakehole":
        command = parse_json(r.string(65536),65536); r.done()
        if not isinstance(command, list) or not command or len(command)>128 or any(not isinstance(x,str) or "\0" in x for x in command):
            raise UnsupportedOperation("Expected a nonempty argument vector")
        return command, False
    raise UnsupportedOperation("Use exec; interactive shells and PTYs are not supported")


@dataclass(frozen=True)
class ExecRequest:
    command: str | list[str]
    shell: bool
    session_id: str
    cwd: str


async def serve_command(channel, command, shell, *, executor=None, session_id="",cwd=None):
    job = create_job() if os.name == "nt" and executor is None else None
    process = None
    tasks = []
    read_fd=write_fd=None
    try:
        if executor is not None:
            process = await executor(ExecRequest(command,shell,session_id,cwd or os.getcwd()))
        else:
            if os.name != "nt": read_fd,write_fd=os.pipe()
            root = str(Path(__file__).resolve().parent.parent)
            worker = "import sys;sys.path.insert(0,sys.argv.pop(1));from ssh_snakehole.worker import main;main()"
            process = await asyncio.create_subprocess_exec(sys.executable, *(["-I"] if sys.flags.isolated else []), "-c", worker, root,
                job.name if job else "", str(os.getpid()),str(read_fd or 0),stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                start_new_session=os.name != "nt", limit=65536,cwd=cwd,
                **({"pass_fds":(read_fd,)} if read_fd is not None else {}),
                env={key:value for key,value in os.environ.items() if not key.startswith("SSH_SNAKEHOLE_")})
            if read_fd is not None: os.close(read_fd); read_fd=None
            async with asyncio.timeout(10):
                if await process.stdout.readexactly(6) != b"READY\n": raise UnsupportedOperation("Command containment failed")
            request = json_bytes({"command":command,"shell":shell})
            process.stdin.write(uint(len(request))+request); await process.stdin.drain()

        async def input_pipe():
            try:
                async for data in channel.stdout:
                    process.stdin.write(data); await process.stdin.drain()
            except (BrokenPipeError, ConnectionResetError): pass
            finally:
                process.stdin.close()

        async def output_pipe(pipe, stderr=False):
            while data := await pipe.read(32768): await channel.send(data, stderr=stderr)

        tasks = [asyncio.create_task(input_pipe()), asyncio.create_task(output_pipe(process.stdout)), asyncio.create_task(output_pipe(process.stderr,True))]
        if executor is not None: status=await process.wait()
        else:
            # asyncio.wait() can wait for pipe EOF held open by surviving children.
            # Observe the worker's exit first, then close its owned command tree.
            while process.returncode is None: await asyncio.sleep(0.01)
            status=process.returncode
        if job: job.close()
        if write_fd is not None: os.close(write_fd); write_fd=None
        await asyncio.gather(*tasks[1:])
        tasks[0].cancel()
        await channel.exit(status)
    finally:
        for descriptor in (read_fd,write_fd):
            if descriptor is not None: os.close(descriptor)
        if executor is not None and process: await process.cancel()
        elif job: job.close()
        elif process:
            with contextlib.suppress(ProcessLookupError): os.killpg(process.pid, signal.SIGTERM)
            await asyncio.sleep(0.1)
            with contextlib.suppress(ProcessLookupError): os.killpg(process.pid, signal.SIGKILL)
        for task in tasks: task.cancel()
        if tasks: await asyncio.gather(*tasks, return_exceptions=True)
        if process:
            with contextlib.suppress(TimeoutError):
                async def drain(pipe):
                    while await pipe.read(32768): pass
                async with asyncio.timeout(5):
                    await asyncio.gather(process.wait(),drain(process.stdout),drain(process.stderr))
