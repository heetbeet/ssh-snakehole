"""Exercise the installed module's host, encrypted ticket and operator commands."""

import asyncio
import os
import sys
import tempfile
import unittest
from pathlib import Path

from ssh_snakehole import RelayConfig, open_host
from ssh_snakehole.platform import elevated
from ssh_snakehole.relay import Relay


class CLI(unittest.IsolatedAsyncioTestCase):
    @unittest.skipIf(elevated(), "Host workflow requires a non-admin account")
    async def test_installed_cli_workflow(self):
        relay = await Relay().start()
        host = None
        renewal = None
        temporary = tempfile.TemporaryDirectory()
        try:
            directory = temporary.name
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
                "--stun",
                "none",
                "--relay",
                f"tcp://127.0.0.1:{relay.transit_port}",
            ]

            async def invoke(*args, secret="", stdin=None, expected_status=0):
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
                            stdin if stdin is not None else (secret + "\n").encode()
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
                (await invoke("pair", "--code-stdin", secret=code))
                .strip()
                .decode("ascii")
            )
            self.assertRegex(token, r"^snake1_[A-Za-z0-9_-]{43}$")
            stored = list((state / "ssh-snakehole" / "tickets").glob("*.json"))
            self.assertEqual(len(stored), 1)
            self.assertNotIn(code.encode(), stored[0].read_bytes())
            self.assertNotIn(token.encode(), stored[0].read_bytes())
            await invoke("keepalive", "--token-stdin", secret=token)
            renewal = await asyncio.create_subprocess_exec(
                *command,
                "keepalive",
                "--interval",
                "1200",
                "--token-stdin",
                cwd=directory,
                env=environment,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            renewal.stdin.write((token + "\n").encode())
            await renewal.stdin.drain()
            renewal.stdin.close()
            async with asyncio.timeout(15):
                self.assertEqual(
                    (await renewal.stdout.readline()).strip(), b"Access renewed."
                )
            shell = "Write-Output cli-ok" if os.name == "nt" else "printf 'cli-ok\\n'"
            self.assertEqual(
                (await invoke("exec", "--token-stdin", shell, secret=token)).strip(),
                b"cli-ok",
            )
            code_script = "import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())"
            import shlex

            binary_command = (
                f"& '{sys.executable}' -c '{code_script}'"
                if os.name == "nt"
                else shlex.join([sys.executable, "-c", code_script])
            )
            payload = bytes(range(256)) * 256
            self.assertEqual(
                await invoke("exec", "--token", token, binary_command, stdin=payload),
                payload,
            )
            self.assertEqual(
                await invoke(
                    "exec",
                    "--token-stdin",
                    binary_command,
                    stdin=(token + "\n").encode() + payload,
                ),
                payload,
            )
            source, target, downloaded = (
                root / "source",
                root / "target",
                root / "downloaded",
            )
            data = bytes(range(256)) * 200
            source.write_bytes(data)
            await invoke("put", "--token-stdin", str(source), str(target), secret=token)
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
            async with asyncio.timeout(10):
                self.assertEqual(await renewal.wait(), 1)
            self.assertIn(b"access renewal stopped", await renewal.stderr.read())
            self.assertEqual(
                list((state / "ssh-snakehole" / "tickets").glob("*.json")), []
            )
            async with asyncio.timeout(10):
                self.assertEqual(await host.wait(), 0)
            config = RelayConfig(
                f"ws://127.0.0.1:{relay.mailbox_port}/v1",
                f"tcp://127.0.0.1:{relay.transit_port}",
                stun=None,
            )
            async with open_host(relay=config) as positional_host:
                token = (
                    (await invoke("pair", positional_host.code, secret=""))
                    .strip()
                    .decode("ascii")
                )
                await invoke("close", "--token", token, secret="")
        finally:
            if renewal is not None and renewal.returncode is None:
                renewal.kill()
                await renewal.wait()
            if host is not None and host.returncode is None:
                host.kill()
                await host.wait()
            await relay.aclose()
            temporary.cleanup()
