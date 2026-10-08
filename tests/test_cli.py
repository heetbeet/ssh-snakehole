"""Exercise the installed module's host, encrypted ticket and operator commands."""

import asyncio
import os
import sys
import tempfile
import unittest
from pathlib import Path

from ssh_snakehole.platform import elevated
from ssh_snakehole.relay import Relay


class CLI(unittest.IsolatedAsyncioTestCase):
    @unittest.skipIf(elevated(), "Host workflow requires a non-admin account")
    async def test_installed_cli_workflow(self):
        relay = await Relay().start()
        host = None
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                environment = dict(os.environ)
                environment["LOCALAPPDATA" if os.name == "nt" else "XDG_STATE_HOME"] = (
                    directory
                )
                if sys.platform == "darwin":
                    environment["HOME"] = directory
                state = (
                    root / "Library/Application Support"
                    if sys.platform == "darwin"
                    else root
                )
                command = [
                    sys.executable,
                    "-I",
                    "-m",
                    "ssh_snakehole",
                    "--mailbox",
                    f"ws://127.0.0.1:{relay.mailbox_port}/v1",
                    "--relay",
                    f"tcp://127.0.0.1:{relay.transit_port}",
                ]

                async def invoke(*args, secret, expected_status=0):
                    process = await asyncio.create_subprocess_exec(
                        *command,
                        *args,
                        cwd=directory,
                        env=environment,
                        stdin=asyncio.subprocess.PIPE,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    try:
                        async with asyncio.timeout(40):
                            stdout, stderr = await process.communicate(
                                (secret + "\n").encode()
                            )
                        self.assertEqual(
                            process.returncode,
                            expected_status,
                            stderr.decode(errors="replace"),
                        )
                        return stdout
                    finally:
                        if process.returncode is None:
                            process.kill()
                            await process.wait()

                host = await asyncio.create_subprocess_exec(
                    *command,
                    "open",
                    "--lifetime",
                    "120",
                    cwd=directory,
                    env=environment,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                assert host.stdout is not None
                async with asyncio.timeout(10):
                    code = (await host.stdout.readline()).strip().decode("ascii")
                token = (
                    (await invoke("connect", "--code-stdin", "--detach", secret=code))
                    .strip()
                    .decode("ascii")
                )
                self.assertRegex(token, r"^snake1_[A-Za-z0-9_-]{43}$")
                stored = list((state / "ssh-snakehole" / "tickets").glob("*.json"))
                self.assertEqual(len(stored), 1)
                self.assertNotIn(code.encode(), stored[0].read_bytes())
                self.assertNotIn(token.encode(), stored[0].read_bytes())
                await invoke("keepalive", "--token-stdin", secret=token)
                shell = (
                    "Write-Output cli-ok" if os.name == "nt" else "printf 'cli-ok\\n'"
                )
                self.assertEqual(
                    (
                        await invoke("exec", "--token-stdin", shell, secret=token)
                    ).strip(),
                    b"cli-ok",
                )
                source, target, downloaded = (
                    root / "source",
                    root / "target",
                    root / "downloaded",
                )
                data = bytes(range(256)) * 200
                source.write_bytes(data)
                await invoke(
                    "put", "--token-stdin", str(source), str(target), secret=token
                )
                await invoke(
                    "put",
                    "--token-stdin",
                    str(source),
                    str(target),
                    secret=token,
                    expected_status=1,
                )
                await invoke(
                    "get", "--token-stdin", str(target), str(downloaded), secret=token
                )
                self.assertEqual(downloaded.read_bytes(), data)
                await invoke("close", "--token-stdin", secret=token)
                self.assertEqual(
                    list((state / "ssh-snakehole" / "tickets").glob("*.json")), []
                )
                async with asyncio.timeout(10):
                    self.assertEqual(await host.wait(), 0)
        finally:
            if host is not None and host.returncode is None:
                host.kill()
                await host.wait()
            await relay.aclose()
