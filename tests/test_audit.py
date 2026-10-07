"""Failures found during review, exercised through actual session boundaries."""

import asyncio
import contextlib
import os
import secrets
import subprocess
import sys
import tempfile
import threading
import tracemalloc
import unittest
from pathlib import Path
from unittest.mock import patch

import asyncssh
from wsproto.events import BytesMessage

from ssh_snakehole import RelayConfig, connect, open_host
from ssh_snakehole.aio import file_call
from ssh_snakehole.errors import (
    AuthenticationFailed,
    HostKeyMismatch,
    OutcomeUnknown,
    ProtocolViolation,
    TransferFailed,
)
from ssh_snakehole.native import export
from ssh_snakehole.platform import elevated
from ssh_snakehole.relay import Relay
from ssh_snakehole.sftp import SFTPServer
from ssh_snakehole.ssh import SSHConnection, key_blob
from ssh_snakehole.websocket import WebSocket, WebSocketStream
from ssh_snakehole.wire import parse_json


class InputBoundaries(unittest.IsolatedAsyncioTestCase):
    @unittest.skipUnless(os.name == "nt", "Windows job ownership")
    def test_job_name_collision_preserves_existing_job(self):
        from ssh_snakehole import win32

        with patch(
            "ssh_snakehole.win32.secrets.token_hex", return_value=secrets.token_hex(16)
        ):
            first = win32.Job()
            try:
                from ssh_snakehole.errors import PlatformContainmentUnavailable

                with self.assertRaises(PlatformContainmentUnavailable):
                    win32.Job()
                self.assertIsNotNone(first.handle)
            finally:
                first.close()

    @unittest.skipUnless(os.name == "posix", "POSIX FIFO boundary")
    def test_vault_rejects_a_fifo_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fifo"
            os.mkfifo(path)
            code = "import asyncio,sys;from ssh_snakehole import vault;asyncio.run(vault.load(sys.argv[1],'passphrase'))"
            result = subprocess.run(
                [sys.executable, "-I", "-c", code, str(path)],
                capture_output=True,
                timeout=3,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"VaultUnlockFailed", result.stderr)

    def test_invalid_read_only_open_cannot_truncate_a_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "data"
            path.write_bytes(b"keep this")
            server = SFTPServer(None, directory)
            with self.assertRaises(asyncssh.SFTPInvalidParameter):
                server.open(os.fsencode(path), 1 | 16, asyncssh.SFTPAttrs())
            self.assertEqual(path.read_bytes(), b"keep this")

    async def test_relay_failed_start_closes_its_first_listener(self):
        relay = Relay()
        original = asyncio.start_server
        opened = []

        async def start(*args, **kwargs):
            if opened:
                raise OSError("Second port occupied")
            server = await original(*args, **kwargs)
            opened.append(server)
            return server

        try:
            with patch("ssh_snakehole.relay.asyncio.start_server", start):
                with self.assertRaises(OSError):
                    await relay.start()
            self.assertFalse(opened[0].is_serving())
        finally:
            for server in opened:
                server.close()
                await server.wait_closed()
            await relay.aclose()

    async def test_full_transit_capacity_does_not_accumulate_rejected_tokens(self):
        relay = Relay()
        relay.pending[b"held"] = [None] * 256

        class Reader:
            async def readuntil(self, separator):
                return b"please relay " + b"0" * 64 + b" for side " + b"1" * 16 + b"\n"

        class Writer:
            def close(self):
                pass

        try:
            with self.assertRaises(ValueError):
                await relay._transit(Reader(), Writer())
            self.assertEqual(set(relay.pending), {b"held"})
        finally:
            relay.pending.clear()
            await relay.aclose()

    async def test_cancelled_transport_close_does_not_strand_waiters(self):
        class Writer:
            def __init__(self):
                self.transport = self
                self.aborted = False

            def close(self):
                pass

            def abort(self):
                self.aborted = True

            async def wait_closed(self):
                await asyncio.Event().wait()

        writer = Writer()
        connection = SSHConnection(None, writer, seed=b"x" * 32)
        task = asyncio.create_task(connection.aclose())
        await asyncio.sleep(0)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        self.assertTrue(writer.aborted)
        async with asyncio.timeout(0.1):
            await connection.wait_closed()

    def test_json_overflow_is_not_a_finite_number(self):
        with self.assertRaises(ProtocolViolation):
            parse_json(b'{"value":1e9999}')

    async def test_empty_websocket_messages_are_not_stream_eof(self):
        ws = WebSocket(None, None, None)
        messages = iter((b"", b"", b"abc"))

        async def receive():
            return next(messages)

        ws.receive = receive
        self.assertEqual(await WebSocketStream(ws).readexactly(3), b"abc")

    async def test_empty_fragment_flood_has_bounded_memory(self):
        ws = WebSocket(None, None, None)
        remaining = 50000

        async def event():
            nonlocal remaining
            remaining -= 1
            return BytesMessage(
                data=b"" if remaining else b"ok", message_finished=remaining == 0
            )

        ws.next_event = event
        tracemalloc.start()
        try:
            self.assertEqual(await ws.receive(), b"ok")
            _, peak = tracemalloc.get_traced_memory()
            self.assertLess(peak, 256 * 1024)
        finally:
            tracemalloc.stop()

    async def test_repeated_cancellation_finishes_file_operation(self):
        started, release, finished = (
            threading.Event(),
            threading.Event(),
            threading.Event(),
        )
        with tempfile.TemporaryFile() as file:
            descriptor = file.fileno()

            def write():
                started.set()
                try:
                    if not release.wait(5):
                        raise TimeoutError("Test writer was not released")
                    os.write(descriptor, b"completed")
                finally:
                    finished.set()

            task = asyncio.create_task(file_call(write))
            try:
                await asyncio.to_thread(started.wait, 2)
                task.cancel()
                await asyncio.sleep(0)
                task.cancel()
                await asyncio.sleep(0.02)
                self.assertFalse(
                    task.done(),
                    "Cancellation returned while the descriptor was still in use",
                )
            finally:
                release.set()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
                await asyncio.to_thread(finished.wait, 2)
            file.seek(0)
            self.assertEqual(file.read(), b"completed")


@unittest.skipIf(elevated(), "Session tests require a non-admin account")
class SessionBoundaries(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.relay = await Relay().start()
        self.config = RelayConfig(
            f"ws://127.0.0.1:{self.relay.mailbox_port}/v1",
            f"tcp://127.0.0.1:{self.relay.transit_port}",
        )

    async def asyncTearDown(self):
        await self.relay.aclose()

    async def test_large_independent_sftp_reads_preserve_every_byte(self):
        async with open_host(relay=self.config, lifetime=120) as host:
            async with connect(host.code, relay=self.config) as session:
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "data"
                    data = bytes(range(256)) * 700
                    path.write_bytes(data)
                    client = await session.connection.native.start_sftp_client(
                        sftp_version=3
                    )
                    try:
                        async with client.open(
                            str(path),
                            "rb",
                            encoding=None,
                            block_size=128 * 1024,
                            max_requests=1,
                        ) as file:
                            self.assertEqual(await file.read(), data)
                    finally:
                        client.exit()
                        await client.wait_closed()
                await session.close_host()

    async def test_cancelled_host_shutdown_wakes_waiters(self):
        host = await open_host(relay=self.config, lifetime=120).__aenter__()
        try:
            async with connect(host.code, relay=self.config):
                task = asyncio.create_task(host.aclose())
                await asyncio.sleep(0)
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
                self.assertTrue(host.closed.is_set())
                async with asyncio.timeout(0.1):
                    await host.wait_closed()
        finally:
            if not host.closed.is_set():
                host.closing = False
            await host.aclose()

    async def test_invalid_run_options_do_not_execute_anything(self):
        async with open_host(relay=self.config, lifetime=120) as host:
            async with connect(host.code, relay=self.config) as session:
                with tempfile.TemporaryDirectory() as directory:
                    target = Path(directory) / "side-effect"
                    command = [
                        sys.executable,
                        "-c",
                        "import pathlib,sys;pathlib.Path(sys.argv[1]).write_text('ran')",
                        str(target),
                    ]
                    for options in (
                        {"max_output": 0.5},
                        {"max_output": True},
                        {"timeout": float("nan")},
                        {"timeout": -1},
                    ):
                        with self.assertRaises(ValueError):
                            await session.run_argv(command, **options)
                        self.assertFalse(target.exists())
                    with self.assertRaises(ValueError):
                        await session.run_argv("echo this is not an argument vector")
                await session.close_host()

    async def test_invalid_connect_options_do_not_consume_a_code(self):
        async with open_host(relay=self.config, lifetime=120) as host:
            code = host.code
            for timeout in (0, -1, True, float("nan")):
                with self.assertRaises(ValueError):
                    async with connect(code, relay=self.config, timeout=timeout):
                        pass
                self.assertFalse(host.accepted)
            with self.assertRaises(RuntimeError):
                await host.__aenter__()
            async with connect(code, relay=self.config) as session:
                await session.close_host()

    async def test_failed_write_cannot_publish_a_transfer(self):
        async def fail(server, file, offset, data):
            raise PermissionError("Simulated failed write")

        with patch.object(SFTPServer, "write", fail):
            async with open_host(relay=self.config, lifetime=120) as host:
                async with connect(host.code, relay=self.config) as session:
                    with tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        (root / "source").write_bytes(b"content")
                        with self.assertRaises(TransferFailed) as failure:
                            await session.put(
                                root / "source", str(root / "destination")
                            )
                        self.assertFalse(failure.exception.committed)
                        self.assertFalse((root / "destination").exists())
                        self.assertEqual({p.name for p in root.iterdir()}, {"source"})
                        await session.close_host()

    async def test_consumed_mailboxes_leave_no_subscriber_or_ip_entries(self):
        async with open_host(relay=self.config, lifetime=120) as host:
            async with connect(host.code, relay=self.config) as session:
                await host.wait_ready()
                for _ in range(100):
                    if not self.relay.subscribers:
                        break
                    await asyncio.sleep(0.01)
                self.assertFalse(self.relay.subscribers)
                await session.close_host()
        for _ in range(100):
            if not self.relay.tasks:
                break
            await asyncio.sleep(0.01)
        self.assertFalse(self.relay.ips)

    async def test_early_exit_with_unread_stdin_keeps_exit_status(self):
        async with open_host(relay=self.config, lifetime=120) as host:
            async with connect(host.code, relay=self.config) as session:
                result = await session.run_argv(
                    [sys.executable, "-c", "import sys;print('done');sys.exit(7)"],
                    stdin=b"x" * 1000000,
                )
                self.assertEqual(
                    (result.stdout, result.stderr, result.exit_code),
                    (b"done\r\n" if os.name == "nt" else b"done\n", b"", 7),
                )
                await session.close_host()

    async def test_lost_exit_status_does_not_replay_the_command(self):
        executed = 0

        async def request(host, process):
            nonlocal executed
            executed += 1
            process.stdout.write(b"took effect")
            process.close()

        with patch("ssh_snakehole.host.Host._command", request):
            async with open_host(relay=self.config, lifetime=120) as host:
                async with connect(host.code, relay=self.config) as session:
                    with self.assertRaises(OutcomeUnknown):
                        await session.run("a command which took effect")
                    self.assertEqual(executed, 1)

    async def test_paired_host_pin_is_enforced(self):
        from ssh_snakehole import Ticket, pair
        from ssh_snakehole.wire import b64

        async with open_host(relay=self.config, lifetime=120) as host:
            ticket = await pair(host.code, relay=self.config)
            changed = ticket.offer
            changed["host_key"] = "ssh-ed25519 " + b64(
                key_blob(secrets.token_bytes(32))
            )
            with self.assertRaises(HostKeyMismatch):
                async with connect(Ticket(changed, ticket.client_seed)):
                    pass

    async def test_other_operator_key_is_rejected(self):
        from ssh_snakehole import Ticket, pair

        async with open_host(relay=self.config, lifetime=120) as host:
            ticket = await pair(host.code, relay=self.config)
            with self.assertRaises(AuthenticationFailed):
                async with connect(Ticket(ticket.offer, secrets.token_bytes(32))):
                    pass

    async def test_failed_native_export_leaves_existing_directory_unchanged(self):
        async with open_host(relay=self.config, lifetime=120) as host:
            async with connect(host.code, relay=self.config) as session:
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / "config").write_bytes(b"existing config")
                    with self.assertRaises(FileExistsError):
                        export(session.ticket, root, root / "ticket")
                    self.assertEqual({p.name for p in root.iterdir()}, {"config"})
                    self.assertEqual((root / "config").read_bytes(), b"existing config")
                await session.close_host()

    async def test_parallel_file_operations_do_not_exhaust_channels(self):
        async with open_host(relay=self.config, lifetime=120) as host:
            async with connect(host.code, relay=self.config) as session:

                async def inspect():
                    return await (await session.files()).stat(str(Path(sys.executable)))

                results = await asyncio.gather(*(inspect() for _ in range(30)))
                self.assertTrue(all(result["size"] > 0 for result in results))
                await session.close_host()

    async def test_cancelled_sftp_reply_cannot_poison_the_next_request(self):
        started, release = threading.Event(), threading.Event()
        original = SFTPServer.stat

        async def delayed(server, path):
            if not started.is_set():
                started.set()
                if not await asyncio.to_thread(release.wait, 5):
                    raise TimeoutError("Test metadata was not released")
            return original(server, path)

        with patch.object(SFTPServer, "stat", delayed):
            async with open_host(relay=self.config, lifetime=120) as host:
                async with connect(host.code, relay=self.config) as session:
                    files = await session.files()
                    task = asyncio.create_task(files.stat(str(Path(sys.executable))))
                    try:
                        await asyncio.to_thread(started.wait, 2)
                        task.cancel()
                        with self.assertRaises(asyncio.CancelledError):
                            await task
                    finally:
                        release.set()
                    result = await (await session.files()).stat(
                        str(Path(sys.executable))
                    )
                    self.assertGreater(result["size"], 0)
                    await session.close_host()

    async def test_post_commit_cleanup_error_is_not_reported_as_no_commit(self):
        async with open_host(relay=self.config, lifetime=120) as host:
            async with connect(host.code, relay=self.config) as session:
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / "source").write_bytes(b"published")
                    original = os.unlink

                    def unlink(path, *args, **kwargs):
                        if Path(path).name.startswith("remote.snakehole-"):
                            raise PermissionError("Simulated cleanup failure")
                        return original(path, *args, **kwargs)

                    with patch("ssh_snakehole.sftp.os.remove", unlink):
                        with self.assertRaises(TransferFailed) as failure:
                            await session.put(root / "source", str(root / "remote"))
                    self.assertEqual((root / "remote").read_bytes(), b"published")
                    self.assertTrue(failure.exception.committed)
                await session.close_host()


if __name__ == "__main__":
    unittest.main()
