"""Real ICE/SCTP streams, packet loss, recovery and resource ownership."""

import asyncio
import contextlib
import hashlib
import io
import os
import secrets
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aioice import stun
from aioice.ice import StunProtocol

from ssh_snakehole import RelayConfig, connect, open_host, vault
from ssh_snakehole.aio import close_stream
from ssh_snakehole.errors import OutcomeUnknown, ProtocolViolation, RelayUnavailable
from ssh_snakehole.ice import CHUNK, WINDOW
from ssh_snakehole.platform import elevated
from ssh_snakehole.relay import Relay
from ssh_snakehole.transit import dial


class StunServer(asyncio.DatagramProtocol):
    def __init__(self):
        self.requests = 0

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, address):
        with contextlib.suppress(ValueError):
            message = stun.parse_message(data)
            if (
                message.message_class == stun.Class.REQUEST
                and message.message_method == stun.Method.BINDING
            ):
                self.requests += 1
                response = stun.Message(
                    stun.Method.BINDING, stun.Class.RESPONSE, message.transaction_id
                )
                response.attributes["XOR-MAPPED-ADDRESS"] = address
                self.transport.sendto(bytes(response), address)


class ICE(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.addresses = patch(
            "aioice.ice.get_host_addresses", return_value=["127.0.0.1"]
        )
        self.addresses.start()
        self.relay = await Relay().start()
        self.url = f"tcp://127.0.0.1:{self.relay.transit_port}"
        self.config = RelayConfig(
            f"ws://127.0.0.1:{self.relay.mailbox_port}/v1", self.url, stun=None
        )
        self.streams = []

    async def asyncTearDown(self):
        await asyncio.gather(
            *(close_stream(stream) for stream in self.streams), return_exceptions=True
        )
        await self.relay.aclose()
        self.addresses.stop()

    def tasks(self, stun_url=None):
        key = secrets.token_bytes(32)
        return [
            asyncio.create_task(
                dial(
                    key,
                    secrets.token_hex(8),
                    sender=sender,
                    relay=self.url,
                    stun=stun_url,
                )
            )
            for sender in (True, False)
        ]

    async def pair(self, stun_url=None):
        tasks = self.tasks(stun_url)
        try:
            async with asyncio.timeout(20):
                peers = await asyncio.gather(*tasks)
            self.streams.extend(writer for _, writer in peers)
            return peers[0][0], peers[1][0]
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def test_stun_candidates_and_duplex_binary_stream(self):
        protocol = StunServer()
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: protocol, local_addr=("127.0.0.1", 0)
        )
        try:
            a, b = await self.pair(
                f"stun:127.0.0.1:{transport.get_extra_info('sockname')[1]}"
            )
            self.assertEqual((a.route, b.route), ("direct-udp", "direct-udp"))
            self.assertGreaterEqual(protocol.requests, 2)
            for stream in (a, b):
                candidates = stream.peer.sctp.transport.transport.iceGatherer.getLocalCandidates()
                self.assertIn("srflx", {candidate.type for candidate in candidates})
                self.assertTrue(stream.channel.ordered)
                self.assertIsNone(stream.channel.maxRetransmits)
                self.assertIsNone(stream.channel.maxPacketLifeTime)
            left, right = os.urandom(80000), os.urandom(70000)

            async def send(stream, data):
                for start in range(0, len(data), CHUNK):
                    stream.write(data[start : start + CHUNK])
                    await stream.drain()
                stream.write_eof()

            sent = [
                asyncio.create_task(send(a, left)),
                asyncio.create_task(send(b, right)),
            ]
            received = await asyncio.gather(a.read(), b.read())
            await asyncio.gather(*sent)
            self.assertEqual(received, [right, left])
        finally:
            transport.close()

    async def test_reliable_stream_survives_loss_reordering_and_duplicates(self):
        original = StunProtocol.send_data
        delayed = []
        count = 0

        async def impaired(protocol, data, address):
            nonlocal count
            count += 1
            if count % 13 == 0:
                return
            if count % 17 == 0:

                async def later():
                    await asyncio.sleep(0.03)
                    await original(protocol, data, address)

                delayed.append(asyncio.create_task(later()))
            else:
                await original(protocol, data, address)
                if count % 23 == 0:
                    await original(protocol, data, address)

        with patch.object(StunProtocol, "send_data", impaired):
            try:
                a, b = await self.pair()
                data = os.urandom(1024 * 1024)

                async def produce():
                    for start in range(0, len(data), CHUNK):
                        a.write(data[start : start + CHUNK])
                        await a.drain()
                    a.write_eof()

                task = asyncio.create_task(produce())
                async with asyncio.timeout(30):
                    received = await b.read()
                    await task
                self.assertEqual(
                    hashlib.sha256(received).digest(), hashlib.sha256(data).digest()
                )
                self.assertGreater(count, 100)
            finally:
                await asyncio.gather(*delayed, return_exceptions=True)

    async def test_reliable_stream_fits_low_mtu_paths(self):
        a, b = await self.pair()
        original = StunProtocol.send_data
        dropped = 0

        async def small_path(protocol, data, address):
            nonlocal dropped
            if len(data) > 1200:
                dropped += 1
                return
            await original(protocol, data, address)

        payload = os.urandom(512 * 1024)

        async def produce():
            for start in range(0, len(payload), CHUNK):
                a.write(payload[start : start + CHUNK])
                await a.drain()
            a.write_eof()

        with patch.object(StunProtocol, "send_data", small_path):
            task = asyncio.create_task(produce())
            try:
                async with asyncio.timeout(20):
                    self.assertEqual(await b.read(), payload)
                    await task
                self.assertEqual(dropped, 0)
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    async def test_slow_reader_applies_backpressure_and_close_wakes_writer(self):
        a, b = await self.pair()
        data = os.urandom(WINDOW * 3)

        async def produce():
            for start in range(0, len(data), CHUNK):
                a.write(data[start : start + CHUNK])
                await a.drain()

        task = asyncio.create_task(produce())
        try:
            await asyncio.sleep(0.1)
            self.assertFalse(task.done())
            self.assertLessEqual(b.unread, WINDOW)
            received = bytearray()
            async with asyncio.timeout(15):
                while len(received) < len(data):
                    received.extend(await b.read(CHUNK))
                await task
            self.assertEqual(received, data)
            a.write(b"x" * WINDOW)
            await a.drain()
            a.write(b"blocked")
            blocked = asyncio.create_task(a.drain())
            await asyncio.sleep(0.02)
            self.assertFalse(blocked.done())
            a.close()
            with self.assertRaises(ConnectionError):
                await blocked
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def test_cancelled_candidate_binding_closes_every_udp_socket(self):
        loop = asyncio.get_running_loop()
        original = loop.create_datagram_endpoint
        opened = asyncio.Event()
        release = asyncio.Event()
        transports = []

        async def endpoint(*args, **kwargs):
            result = await original(*args, **kwargs)
            transports.append(result[0])
            opened.set()
            await release.wait()
            return result

        with patch.object(loop, "create_datagram_endpoint", endpoint):
            tasks = self.tasks()
            try:
                async with asyncio.timeout(5):
                    await opened.wait()
                for task in tasks:
                    task.cancel()
                await asyncio.sleep(0.02)
                release.set()
                results = await asyncio.gather(*tasks, return_exceptions=True)
                self.assertTrue(
                    all(
                        isinstance(result, asyncio.CancelledError) for result in results
                    )
                )
                self.assertTrue(transports)
                self.assertTrue(all(transport.is_closing() for transport in transports))
            finally:
                release.set()
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)

    async def test_queued_datagrams_close_without_leaking_sockets(self):
        loop = asyncio.get_running_loop()
        endpoint = loop.create_datagram_endpoint
        sockets = []

        async def capture(*args, **kwargs):
            result = await endpoint(*args, **kwargs)
            sockets.append(result[0].get_extra_info("socket"))
            return result

        with patch.object(loop, "create_datagram_endpoint", capture):
            a, b = await self.pair()
            a.write(b"x" * WINDOW)
            await a.drain()
            async with asyncio.timeout(3):
                await asyncio.gather(close_stream(a), close_stream(b))
            self.assertTrue(sockets)
            self.assertTrue(all(sock.fileno() == -1 for sock in sockets))

    async def test_tampered_signalling_fails_without_relay_downgrade(self):
        from ssh_snakehole import ice

        original = ice.seal

        def corrupt(key, message):
            encrypted = original(key, message)
            return encrypted[:-1] + bytes([encrypted[-1] ^ 1])

        with patch.object(ice, "seal", corrupt):
            tasks = self.tasks()
            async with asyncio.timeout(10):
                results = await asyncio.gather(*tasks, return_exceptions=True)
            self.assertTrue(all(isinstance(result, Exception) for result in results))
            self.assertTrue(any(isinstance(result, ValueError) for result in results))

    async def test_receive_window_and_credit_violations_close_stream(self):
        a, b = await self.pair()
        a.channel.send(b"\1" + (WINDOW + 1).to_bytes(4, "big"))
        async with asyncio.timeout(2):
            await b.ready.wait()
            while not b.closed:
                await asyncio.sleep(0.01)
        with self.assertRaises(ProtocolViolation):
            await b.read(1)

    @unittest.skipIf(elevated(), "Host should run without admin privileges")
    async def test_blocked_udp_falls_back_and_reconnection_can_use_direct(self):
        async with open_host(relay=self.config) as host:
            with (
                patch.object(StunProtocol, "send_stun", lambda *args: None),
                patch("ssh_snakehole.ice.OPEN_TIMEOUT", 0.15),
            ):
                async with connect(host.code, relay=self.config) as session:
                    self.assertEqual(session.transport, "relay")
                    self.assertEqual(
                        (
                            await session.run_argv(
                                [sys.executable, "-c", "print('fallback')"]
                            )
                        ).stdout.strip(),
                        b"fallback",
                    )
                    ticket = session.ticket
            async with connect(ticket, relay=self.config) as recovered:
                self.assertEqual(recovered.transport, "direct-udp")
                await recovered.close_host()

    @unittest.skipIf(elevated(), "Host should run without admin privileges")
    async def test_initial_connection_failure_preserves_cli_reconnection_token(self):
        from ssh_snakehole.cli import parser, run

        async with open_host(relay=self.config) as host:
            args = parser().parse_args(
                [
                    "--mailbox",
                    self.config.mailbox,
                    "--relay",
                    self.config.transit,
                    "--stun",
                    "none",
                    "connect",
                    host.code,
                    "--detach",
                ]
            )
            output = io.StringIO()
            with tempfile.TemporaryDirectory() as directory:
                with (
                    patch(
                        "ssh_snakehole.vault.directory", return_value=Path(directory)
                    ),
                    patch(
                        "ssh_snakehole.client.dial",
                        side_effect=OSError("Blocked relay"),
                    ),
                    contextlib.redirect_stdout(output),
                ):
                    with self.assertRaises(RelayUnavailable):
                        await run(args)
                token = output.getvalue().strip()
                ticket = await vault.load(token, root=directory)
                self.assertTrue(host.accepted)
                self.assertIsNone(args.code)
                self.assertNotIn(
                    token.encode(), vault.resolve(token, directory).read_bytes()
                )
                async with connect(ticket, relay=self.config) as recovered:
                    self.assertEqual(recovered.transport, "direct-udp")
                    await recovered.close_host()

    @unittest.skipIf(elevated(), "Host should run without admin privileges")
    async def test_connection_loss_never_replays_work_and_ticket_can_reconnect(self):
        async with open_host(relay=self.config) as host:
            async with connect(host.code, relay=self.config) as session:
                ticket = session.ticket
                with tempfile.TemporaryDirectory() as directory:
                    marker = Path(directory) / "once"
                    task = asyncio.create_task(
                        session.run_argv(
                            [
                                sys.executable,
                                "-c",
                                "import pathlib,sys,time;pathlib.Path(sys.argv[1]).write_text('one');time.sleep(30)",
                                str(marker),
                            ]
                        )
                    )
                    try:
                        async with asyncio.timeout(5):
                            while not marker.exists():
                                await asyncio.sleep(0.01)
                        await session.connection.writer.peer.close()
                        with self.assertRaises(OutcomeUnknown):
                            async with asyncio.timeout(5):
                                await task
                        self.assertEqual(marker.read_text(), "one")
                        async with connect(ticket, relay=self.config) as recovered:
                            self.assertEqual(
                                (
                                    await recovered.run_argv(
                                        [sys.executable, "-c", "print('reconnected')"]
                                    )
                                ).stdout.strip(),
                                b"reconnected",
                            )
                            self.assertEqual(marker.read_text(), "one")
                            await recovered.close_host()
                    finally:
                        task.cancel()
                        await asyncio.gather(task, return_exceptions=True)
