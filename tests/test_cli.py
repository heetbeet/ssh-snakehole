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
                environment["SSH_SNAKEHOLE_PASSPHRASE"] = (
                    "a CLI workflow test passphrase"
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

                async def invoke(*args, expected_status=0):
                    process = await asyncio.create_subprocess_exec(
                        *command,
                        *args,
                        cwd=directory,
                        env=environment,
                        stdin=asyncio.subprocess.DEVNULL,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    try:
                        async with asyncio.timeout(40):
                            stdout, stderr = await process.communicate()
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
                identifier = (await invoke("connect", code)).strip().decode("ascii")
                self.assertRegex(identifier, r"^[0-9a-f]{32}$")
                shell = (
                    "Write-Output cli-ok" if os.name == "nt" else "printf 'cli-ok\\n'"
                )
                self.assertEqual(
                    (await invoke("exec", identifier, shell)).strip(), b"cli-ok"
                )
                source, target, downloaded = (
                    root / "source",
                    root / "target",
                    root / "downloaded",
                )
                data = bytes(range(256)) * 200
                source.write_bytes(data)
                await invoke("put", identifier, str(source), str(target))
                await invoke(
                    "put", identifier, str(source), str(target), expected_status=1
                )
                await invoke("get", identifier, str(target), str(downloaded))
                self.assertEqual(downloaded.read_bytes(), data)
                await invoke("close", identifier)
                self.assertEqual(
                    list((root / "ssh-snakehole" / "tickets").glob("*.json")), []
                )
                async with asyncio.timeout(10):
                    self.assertEqual(await host.wait(), 0)
        finally:
            if host is not None and host.returncode is None:
                host.kill()
                await host.wait()
            await relay.aclose()
