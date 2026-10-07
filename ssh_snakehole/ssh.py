"""AsyncSSH over an outbound relay, using a bounded local socket pair."""

from __future__ import annotations

import asyncio
import base64
import socket
import weakref

import asyncssh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .aio import close_stream
from .errors import (
    AuthenticationFailed,
    HostKeyMismatch,
)

WINDOW = 256 * 1024
CHUNK = 32768
SESSIONS: weakref.WeakSet[ServerProcess] = weakref.WeakSet()


def private_key(seed):
    return asyncssh.import_private_key(
        Ed25519PrivateKey.from_private_bytes(seed).private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.OpenSSH,
            serialization.NoEncryption(),
        )
    )


def key_blob(seed):
    return base64.b64decode(private_key(seed).export_public_key().split()[1])


def key_public(blob):
    key = asyncssh.import_public_key(b"ssh-ed25519 " + base64.b64encode(blob))
    if key.get_algorithm() != "ssh-ed25519":
        raise ValueError("Expected Ed25519 key")
    return key


class Bridge:
    """No network listener: adapt TCP or WebSocket Transit to AsyncSSH's socket API."""

    def __init__(self, reader, writer):
        self.reader, self.writer = reader, writer
        self.socket, self.peer = socket.socketpair()
        self.socket.setblocking(False)
        self.peer.setblocking(False)
        self.shutdown = None
        self.tasks = [asyncio.create_task(self.up()), asyncio.create_task(self.down())]
        for task in self.tasks:
            task.add_done_callback(self.finished)

    def finished(self, task):
        if not task.cancelled():
            task.exception()
        if self.shutdown is None:
            self.shutdown = asyncio.create_task(self.stop_pumps())

    async def stop_pumps(self):
        for task in self.tasks:
            task.cancel()
        try:
            await asyncio.gather(*self.tasks, return_exceptions=True)
        finally:
            self.peer.close()
            self.writer.close()

    async def up(self):
        loop = asyncio.get_running_loop()
        while data := await loop.sock_recv(self.peer, CHUNK):
            self.writer.write(data)
            async with asyncio.timeout(30):
                await self.writer.drain()

    async def down(self):
        loop = asyncio.get_running_loop()
        while data := await self.reader.read(CHUNK):
            async with asyncio.timeout(30):
                await loop.sock_sendall(self.peer, data)

    async def aclose(self):
        if self.shutdown is None:
            self.shutdown = asyncio.create_task(self.stop_pumps())
        try:
            await self.shutdown
        finally:
            self.socket.close()
            await close_stream(self.writer)


class ServerProcess(asyncssh.SSHServerProcess):
    def __init__(self, owner):
        self.owner = owner
        super().__init__(owner.serve, owner.sftp_factory, 3, False)

    def connection_made(self, channel):
        super().connection_made(channel)
        self.owner.task(self.owner.watch(self))

    def shell_requested(self):
        return False

    def pty_requested(self, *args):
        return False

    def exec_requested(self, command):
        return (
            len(command.encode("utf-8")) <= 65536
            and "\0" not in command
            and super().exec_requested(command)
        )

    def subsystem_requested(self, name):
        return name in (
            "sftp",
            "snakehole-argv",
            "snakehole-control",
        ) and super().subsystem_requested(name)


class Server(asyncssh.SSHServer):
    def __init__(self, owner):
        self.owner = owner

    def connection_made(self, connection):
        self.connection = connection
        self.owner.native = connection

    def begin_auth(self, username):
        return True

    def public_key_auth_supported(self):
        return True

    def validate_public_key(self, username, key):
        return key == key_public(self.owner.authorized)

    def session_requested(self):
        if len(self.owner.sessions) >= 16 or len(SESSIONS) >= 64:
            return False
        process = ServerProcess(self.owner)
        self.owner.sessions.add(process)
        SESSIONS.add(process)
        return self.connection.create_server_channel(
            encoding=None, window=WINDOW, max_pktsize=CHUNK
        ), process


class SSHConnection:
    def __init__(
        self,
        reader,
        writer,
        *,
        server=False,
        seed,
        pin=None,
        authorized=None,
        handler=None,
        sftp_factory=None,
    ):
        self.reader, self.writer, self.server = reader, writer, server
        self.seed, self.pin, self.authorized = seed, pin, authorized
        self.handler, self.sftp_factory = handler, sftp_factory
        self.native = None
        self.bridge = None
        self.sessions = set()
        self.tasks = set()
        self.closed = False
        self.ended = asyncio.Event()
        self.close_owner = None
        self.closing_tasks = set()

    def task(self, operation):
        task = asyncio.create_task(operation)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return task

    async def watch(self, process):
        try:
            await process.wait_closed()
        finally:
            self.sessions.discard(process)
            SESSIONS.discard(process)

    async def serve(self, process):
        work = self.task(self.handler(process))
        closing = asyncio.create_task(process.wait_closed())
        try:
            await asyncio.wait((work, closing), return_when=asyncio.FIRST_COMPLETED)
            if closing.done() and not work.done():
                work.cancel()
            await work
        except asyncio.CancelledError:
            raise
        except Exception:
            process.stderr.write(b"ssh-snakehole: remote operation failed\n")
            process.exit(126)
        finally:
            closing.cancel()
            work.cancel()
            await asyncio.gather(closing, work, return_exceptions=True)

    async def start(self):
        self.bridge = Bridge(self.reader, self.writer)
        common = dict(
            config=None,
            encoding=None,
            compression_algs=["none"],
            kex_algs=["curve25519-sha256", "curve25519-sha256@libssh.org"],
            encryption_algs=["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"],
            rekey_bytes=256 * 1024 * 1024,
            rekey_seconds=3600,
            keepalive_interval=15,
            keepalive_count_max=2,
            window=WINDOW,
            max_pktsize=CHUNK,
        )
        try:
            async with asyncio.timeout(10):
                if self.server:
                    self.native = await asyncssh.run_server(
                        self.bridge.socket,
                        server_factory=lambda: Server(self),
                        server_host_keys=[private_key(self.seed)],
                        password_auth=False,
                        kbdint_auth=False,
                        agent_forwarding=False,
                        x11_forwarding=False,
                        login_timeout=10,
                        **common,
                    )
                else:
                    self.native = await asyncssh.run_client(
                        self.bridge.socket,
                        host="ssh-snakehole",
                        username="help",
                        client_keys=[private_key(self.seed)],
                        known_hosts=([key_public(self.pin)], [], []),
                        agent_path=None,
                        preferred_auth="publickey",
                        **common,
                    )
            return self
        except asyncssh.HostKeyNotVerifiable as exc:
            await self.aclose()
            raise HostKeyMismatch(
                "SSH host key did not match the paired identity"
            ) from exc
        except asyncssh.PermissionDenied as exc:
            await self.aclose()
            raise AuthenticationFailed("SSH operator key was rejected") from exc
        except BaseException:
            await self.aclose()
            raise

    async def wait_closed(self):
        if self.native:
            await self.native.wait_closed()
        await self.aclose()

    async def aclose(self):
        current = asyncio.current_task()
        if self.closed:
            if current is not self.close_owner and current not in self.closing_tasks:
                await self.ended.wait()
            return
        self.close_owner = current
        self.closed = True
        tasks = [task for task in self.tasks if task is not current]
        self.closing_tasks.update(tasks)
        for task in tasks:
            task.cancel()
        try:
            if self.native:
                self.native.close()
                try:
                    async with asyncio.timeout(2):
                        await self.native.wait_closed()
                except BaseException:
                    self.native.abort()
                    raise
        finally:
            try:
                if self.bridge:
                    await self.bridge.aclose()
                else:
                    await close_stream(self.writer)
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)
            finally:
                self.ended.set()
