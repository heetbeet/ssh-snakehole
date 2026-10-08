"""Secrets, idle expiry, active work and shared authorization through real SSH."""

import asyncio
import contextlib
import io
import secrets
import sys
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest.mock import patch

from ssh_snakehole import RelayConfig, connect, open_host, vault
from ssh_snakehole.cli import interactive, parser
from ssh_snakehole.console import read_secret
from ssh_snakehole.errors import VaultUnlockFailed
from ssh_snakehole.idle import Idle
from ssh_snakehole.platform import elevated
from ssh_snakehole.relay import Relay


class Input(unittest.TestCase):
    def test_hidden_input_never_falls_back_to_echo(self):
        import getpass

        def fallback(*args):
            warnings.warn("Cannot disable echo", getpass.GetPassWarning, stacklevel=2)
            return "should not be accepted"

        with patch("ssh_snakehole.console.getpass.getpass", fallback):
            with self.assertRaisesRegex(ValueError, "Hidden input unavailable"):
                read_secret("Code: ")

    def test_invalid_positional_secret_is_not_reflected(self):
        secret = "a-private-code"
        stream = io.StringIO()
        with contextlib.redirect_stderr(stream), self.assertRaises(SystemExit):
            parser().parse_args(["connect", secret])
        self.assertNotIn(secret, stream.getvalue())

    def test_piped_secret_is_bounded_and_not_reflected(self):
        stream = io.TextIOWrapper(io.BytesIO(b"private" * 100 + b"\n"))
        with patch("sys.stdin", stream):
            with self.assertRaisesRegex(ValueError, "bounded") as error:
                read_secret("Code: ", True)
        self.assertNotIn("private", str(error.exception))


class Clock(unittest.IsolatedAsyncioTestCase):
    async def test_overlapping_work_starts_a_fresh_interval_only_after_last_finish(
        self,
    ):
        clock = Idle(0.1)
        expiry = asyncio.create_task(clock.wait_expired())
        with clock.operation():
            with clock.operation():
                await asyncio.sleep(0.15)
                self.assertFalse(expiry.done())
            await asyncio.sleep(0.15)
            self.assertFalse(expiry.done())
        await asyncio.sleep(0.04)
        self.assertFalse(expiry.done())
        await asyncio.wait_for(expiry, 0.3)


@unittest.skipIf(elevated(), "Host requires a non-admin account")
class ReconnectIdle(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.relay = await Relay().start()
        self.config = RelayConfig(
            f"ws://127.0.0.1:{self.relay.mailbox_port}/v1",
            f"tcp://127.0.0.1:{self.relay.transit_port}",
        )

    async def asyncTearDown(self):
        await self.relay.aclose()

    async def test_long_silent_command_and_nonzero_exit_get_full_idle_interval(self):
        async with open_host(relay=self.config, idle_timeout=0.8) as host:
            async with connect(host.code, relay=self.config) as session:
                result = await session.run_argv(
                    [
                        sys.executable,
                        "-c",
                        "import time;time.sleep(1.2);print('finished');raise SystemExit(7)",
                    ]
                )
                self.assertEqual(result.exit_code, 7)
                self.assertIn(b"finished", result.stdout)
                self.assertFalse(host.closed.is_set())
                await asyncio.sleep(0.2)
                self.assertFalse(host.closed.is_set())
                await asyncio.wait_for(host.wait_closed(), 3)

    async def test_idle_authenticated_transport_and_cached_sftp_do_not_renew(self):
        async with open_host(relay=self.config, idle_timeout=0.4) as host:
            async with connect(host.code, relay=self.config) as session:
                await session.files()
                await asyncio.wait_for(host.wait_closed(), 2)

    async def test_live_sftp_file_pauses_clock_until_close(self):
        async with open_host(relay=self.config, idle_timeout=0.5) as host:
            async with connect(host.code, relay=self.config) as session:
                client = (await session.files()).client
                async with client.open(str(Path(sys.executable)), "rb") as file:
                    await asyncio.sleep(0.8)
                    self.assertFalse(host.closed.is_set())
                    self.assertTrue(await file.read(16))
                await asyncio.sleep(0.1)
                self.assertFalse(host.closed.is_set())
                await asyncio.wait_for(host.wait_closed(), 2)

    async def test_keepalive_renews_but_cannot_override_explicit_lifetime(self):
        async with open_host(relay=self.config, idle_timeout=0.6, lifetime=2.5) as host:
            async with connect(host.code, relay=self.config) as session:

                async def renew():
                    while True:
                        await session.keepalive()
                        await asyncio.sleep(0.2)

                renewal = asyncio.create_task(renew())
                try:
                    await asyncio.sleep(1.3)
                    self.assertFalse(host.closed.is_set())
                    await asyncio.wait_for(host.wait_closed(), 3)
                    self.assertEqual(str(host.error), "Host lifetime expired")
                finally:
                    renewal.cancel()
                    await asyncio.gather(renewal, return_exceptions=True)

    async def test_shared_ticket_concurrency_close_and_independent_host(self):
        async with (
            open_host(relay=self.config) as first,
            open_host(relay=self.config) as other,
        ):
            async with (
                connect(first.code, relay=self.config) as a,
                connect(other.code, relay=self.config) as independent,
            ):
                async with connect(a.ticket) as b:
                    tasks = [
                        a.run_argv([sys.executable, "-c", "print('a')"]),
                        b.run_argv([sys.executable, "-c", "print('b')"]),
                    ]
                    results = await asyncio.gather(*tasks)
                    self.assertEqual([r.stdout.strip() for r in results], [b"a", b"b"])
                    await b.close_host()
                    await asyncio.wait_for(a.connection.wait_closed(), 2)
                self.assertFalse(other.closed.is_set())
                self.assertEqual(
                    (
                        await independent.run_argv(
                            [sys.executable, "-c", "print('independent')"]
                        )
                    ).stdout.strip(),
                    b"independent",
                )
                await independent.close_host()

    async def test_encrypted_file_cannot_be_used_with_another_token_or_modified(self):
        async with open_host(relay=self.config) as host:
            code = host.code
            async with connect(code, relay=self.config) as session:
                with tempfile.TemporaryDirectory() as directory:
                    token = await vault.save(session.ticket, root=directory)
                    path = vault.resolve(token, directory)
                    stored = path.read_bytes()
                    for value in (
                        code.encode(),
                        token.encode(),
                        session.ticket.client_seed,
                    ):
                        self.assertNotIn(value, stored)
                    wrong = "snake1_" + secrets.token_urlsafe(32)
                    vault.resolve(wrong, directory).write_bytes(stored)
                    with self.assertRaises(VaultUnlockFailed):
                        await vault.load(wrong, root=directory)
                    path.write_bytes(stored.replace(b'"box":"', b'"box":"A', 1))
                    with self.assertRaises(VaultUnlockFailed):
                        await vault.load(token, root=directory)
                await session.close_host()

    async def test_foreground_prompt_exits_on_remote_close_without_input(self):
        async def waiting():
            await asyncio.Event().wait()
            yield "never"

        async with open_host(relay=self.config, idle_timeout=0.4) as host:
            async with connect(host.code, relay=self.config) as session:
                with (
                    patch("ssh_snakehole.cli.lines", waiting),
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    self.assertFalse(await asyncio.wait_for(interactive(session), 2))
                self.assertTrue(host.closed.is_set())

    async def test_foreground_exit_preserves_reconnection_and_close_revokes(self):
        async def exit_input():
            yield "exit"

        async def close_input():
            yield "close"

        async with open_host(relay=self.config) as host:
            async with connect(host.code, relay=self.config) as session:
                ticket = session.ticket
                with (
                    patch("ssh_snakehole.cli.lines", exit_input),
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    self.assertFalse(await interactive(session))
            async with connect(ticket) as session:
                with (
                    patch("ssh_snakehole.cli.lines", close_input),
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    self.assertTrue(await interactive(session))
            self.assertTrue(host.closed.is_set())
