"""Observable code -> relay -> SSH -> process/files -> close behavior."""

import asyncio
import sys
import tempfile
import unittest
from pathlib import Path

from ssh_snakehole import RelayConfig, Ticket, connect, open_host, vault
from ssh_snakehole.errors import (
    CommandTimedOut,
    OutputLimitExceeded,
    PairingFailed,
    TransferFailed,
    VaultUnlockFailed,
)
from ssh_snakehole.platform import elevated
from ssh_snakehole.relay import Relay


class Pipeline(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.relay = await Relay().start()
        self.config = RelayConfig(
            f"ws://127.0.0.1:{self.relay.mailbox_port}/v1",
            f"tcp://127.0.0.1:{self.relay.transit_port}",
        )

    async def asyncTearDown(self):
        await self.relay.aclose()

    async def workflow(self, config):
        async with open_host(lifetime=120, relay=config) as host:
            code = host.code
            async with connect(code, relay=config) as session:
                result = await session.run_argv(
                    [
                        sys.executable,
                        "-c",
                        "import sys;sys.stdout.buffer.write(sys.stdin.buffer.read());sys.stderr.buffer.write(b'err\\0');sys.exit(7)",
                    ],
                    stdin=b"input\0\xff",
                )
                self.assertEqual(
                    (result.stdout, result.stderr, result.exit_code),
                    (b"input\0\xff", b"err\0", 7),
                )
                ticket = Ticket.from_bytes(session.ticket.to_bytes())
                view = ticket.offer
                view["host_key"] = "changed"
                self.assertEqual(ticket.to_bytes(), session.ticket.to_bytes())
                self.assertNotIn(ticket.offer["transit_key"], repr(ticket))
                with tempfile.TemporaryDirectory() as directory:
                    d = Path(directory)
                    data = bytes(range(256)) * 600
                    (d / "source").write_bytes(data)
                    uploaded = await session.put(d / "source", str(d / "remote"))
                    self.assertEqual(uploaded.bytes_copied, len(data))
                    self.assertTrue(uploaded.durable)
                    with self.assertRaises(TransferFailed):
                        await session.put(d / "source", str(d / "remote"))
                    self.assertEqual((d / "remote").read_bytes(), data)
                    await session.get(str(d / "remote"), d / "download")
                    self.assertEqual((d / "download").read_bytes(), data)
                    files = await session.files()
                    self.assertIn("remote", dict(await files.listdir(str(d))))
                    self.assertEqual(
                        (await files.stat(str(d / "remote")))["size"], len(data)
                    )
                    path = await vault.save(
                        ticket, "a sufficiently long test passphrase", d / "ticket"
                    )
                    self.assertNotIn(ticket.client_seed, path.read_bytes())
                    restored = await vault.load(
                        path, "a sufficiently long test passphrase"
                    )
                    self.assertEqual(restored.to_bytes(), ticket.to_bytes())
                    with self.assertRaises(VaultUnlockFailed):
                        await vault.load(path, "wrong passphrase")
            async with connect(ticket, relay=config) as second:
                self.assertEqual(
                    (
                        await second.run_argv(
                            [sys.executable, "-c", "print('reconnect')"]
                        )
                    ).stdout.strip(),
                    b"reconnect",
                )
                receipt = await second.close_host()
                self.assertTrue(receipt.accepted)
            await host.wait_closed()
            self.assertFalse(host.connections)

    @unittest.skipIf(elevated(), "Full host workflow requires a non-admin test account")
    async def test_tcp_workflow(self):
        await self.workflow(self.config)

    @unittest.skipIf(elevated(), "Full host workflow requires a non-admin test account")
    async def test_websocket_workflow(self):
        await self.workflow(
            RelayConfig(
                self.config.mailbox, f"ws://127.0.0.1:{self.relay.mailbox_port}/transit"
            )
        )

    @unittest.skipIf(elevated(), "Full host workflow requires a non-admin test account")
    async def test_limits_cancel_owned_processes(self):
        async with open_host(lifetime=120, relay=self.config) as host:
            async with connect(host.code, relay=self.config) as session:
                with self.assertRaises(OutputLimitExceeded) as capture:
                    await session.run_argv(
                        [
                            sys.executable,
                            "-c",
                            "import sys;sys.stdout.buffer.write(b'x'*2000000)",
                        ],
                        max_output=1000,
                    )
                self.assertEqual(len(capture.exception.stdout), 1000)
                self.assertIn("output", str(capture.exception))
                self.assertNotIn("timed out", str(capture.exception))
                with tempfile.TemporaryDirectory() as directory:
                    marker = Path(directory) / "should-not-exist"
                    program = f"import time,pathlib;time.sleep(1);pathlib.Path({str(marker)!r}).write_text('escaped')"
                    with self.assertRaises(CommandTimedOut):
                        await session.run_argv(
                            [sys.executable, "-c", program], timeout=0.1
                        )
                    await asyncio.sleep(1.2)
                    self.assertFalse(marker.exists())
                self.assertEqual(
                    (
                        await session.run_argv(
                            [sys.executable, "-c", "print('still alive')"]
                        )
                    ).exit_code,
                    0,
                )
                await session.close_host()

    @unittest.skipIf(elevated(), "Full host workflow requires a non-admin test account")
    async def test_wrong_code_closes_host(self):
        async with open_host(lifetime=120, relay=self.config) as host:
            from ssh_snakehole.pairing import words

            parts = host.code.split("-")
            parts[1] = next(word for word in words()[0] if word != parts[1])
            with self.assertRaises(PairingFailed):
                async with connect("-".join(parts), relay=self.config):
                    pass
            await asyncio.wait_for(host.wait_closed(), 5)
            self.assertFalse(host.accepted)


if __name__ == "__main__":
    unittest.main()
