"""A real host-process crash must stop ordinary owned descendants."""

import asyncio
import os
import shlex
import sys
import tempfile
import unittest
from pathlib import Path

from ssh_snakehole import RelayConfig, connect, open_host
from ssh_snakehole.errors import OutcomeUnknown
from ssh_snakehole.platform import elevated
from ssh_snakehole.relay import Relay


@unittest.skipIf(elevated(), "Lifecycle test requires a non-admin account")
class Lifetime(unittest.IsolatedAsyncioTestCase):
    async def test_command_exit_stops_remaining_descendants(self):
        relay = await Relay().start()
        try:
            config = RelayConfig(
                f"ws://127.0.0.1:{relay.mailbox_port}/v1",
                f"tcp://127.0.0.1:{relay.transit_port}",
                stun=None,
            )
            with tempfile.TemporaryDirectory() as directory:
                marker = Path(directory) / "escaped"
                grandchild = f"import time,pathlib;time.sleep(2);pathlib.Path({str(marker)!r}).write_text('escaped')"
                command = f"import subprocess,sys;subprocess.Popen([sys.executable,'-c',{grandchild!r}]);print('finished',flush=True)"
                async with open_host(relay=config, lifetime=120) as host:
                    async with connect(host.code, relay=config) as session:
                        result = await session.run_argv(
                            [sys.executable, "-c", command], timeout=10
                        )
                        self.assertEqual(
                            (result.stdout.strip(), result.exit_code), (b"finished", 0)
                        )
                        await asyncio.sleep(2.3)
                        self.assertFalse(marker.exists())
                        await session.close_host()
        finally:
            await relay.aclose()

    async def test_forced_host_exit_stops_grandchild(self):
        relay = await Relay().start()
        host = None
        try:
            config = RelayConfig(
                f"ws://127.0.0.1:{relay.mailbox_port}/v1",
                f"tcp://127.0.0.1:{relay.transit_port}",
                stun=None,
            )
            host = await asyncio.create_subprocess_exec(
                sys.executable,
                "-m",
                "ssh_snakehole",
                "--mailbox",
                config.mailbox,
                "--stun",
                "none",
                "--relay",
                config.transit,
                "open",
                "--lifetime",
                "120",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path)),
            )
            async with asyncio.timeout(20):
                code = (await host.stdout.readline()).decode().strip()
            with tempfile.TemporaryDirectory() as directory:
                marker = Path(directory) / "escaped"
                grandchild = f"import pathlib,time;time.sleep(2);pathlib.Path({str(marker)!r}).write_text('escaped')"
                program = f"import subprocess,sys,time;subprocess.Popen([sys.executable,'-c',{grandchild!r}]);print('READY',flush=True);time.sleep(60)"
                script = Path(directory) / "command.py"
                script.write_text(program, encoding="utf-8")
                quote = (
                    (lambda s: "'" + s.replace("'", "''") + "'")
                    if os.name == "nt"
                    else shlex.quote
                )
                command = (
                    ("& " if os.name == "nt" else "")
                    + quote(sys.executable)
                    + " "
                    + quote(str(script))
                )
                async with connect(code, relay=config) as session:
                    try:
                        async with session.exec(command) as process:
                            async with asyncio.timeout(10):
                                output = await process.stdout.read(32768)
                                self.assertIn(b"READY", output)
                            host.kill()
                            await host.wait()
                            with self.assertRaises(OutcomeUnknown):
                                await process.wait()
                    except OutcomeUnknown:
                        pass
                await asyncio.sleep(2.3)
                self.assertFalse(marker.exists())
        finally:
            if host:
                if host.returncode is None:
                    host.kill()
                await host.communicate()
            await relay.aclose()


if __name__ == "__main__":
    unittest.main()
