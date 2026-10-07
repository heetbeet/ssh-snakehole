"""A foreground host owns one invitation, SSH identities, connections and children."""
import asyncio
import os
import platform
import secrets
import time
import math
from pathlib import Path
from dataclasses import dataclass

from .errors import CodeConsumed, PairingExpired, ProtocolViolation, SessionExpired, UnsupportedOperation
from .pairing import Pairing, MAILBOX
from .platform import check_privilege,check_runtime,process_user
from .process import command_request, serve_command
from .sftp import SFTPServer
from .ssh import SSHConnection, key_blob, key_public
from .ticket import SCHEMA, HostInfo, digest, strict, timestamp
from .transit import RELAY, dial, endpoint
from .wire import Reader, b64, unb64


@dataclass(frozen=True)
class RelayConfig:
    mailbox: str = MAILBOX
    transit: str = RELAY

    def __post_init__(self): endpoint(self.transit)


@dataclass(frozen=True)
class CloseReason:
    reason: str
    timestamp: str


class Host:
    def __init__(self, *, lifetime=7200, admin=False, relay=None, executor=None, files=True):
        if isinstance(lifetime,bool) or not isinstance(lifetime,(int,float)) or not math.isfinite(lifetime) or not 0<lifetime<=7200: raise ValueError("Lifetime must be between 0 and 7200 seconds")
        self.lifetime,self.admin,self.relay,self.executor,self.files=lifetime,admin,relay or RelayConfig(),executor,files
        self.pairing=None; self.tasks=set(); self.connections=set()
        self.ready=asyncio.Event(); self.closed=asyncio.Event(); self.closing=False; self.error=None
        self._code=None; self.accepted=False; self.first_auth=False

    @property
    def code(self):
        if self.accepted: raise CodeConsumed("Pairing code has been consumed")
        return self._code

    def task(self, operation):
        task=asyncio.create_task(operation); self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return task

    async def __aenter__(self):
        check_runtime(host=True)
        privilege=check_privilege(self.admin)
        home=Path.home()
        self.cwd=str(home if home.is_dir() else Path.cwd())
        self.seed=secrets.token_bytes(32)
        self.expires=time.time()+self.lifetime; self.deadline=time.monotonic()+self.lifetime
        os_name="windows" if os.name=="nt" else "macos" if platform.system()=="Darwin" else "linux"
        self.offer=dict(schema=SCHEMA,type="offer",role="host",session_id=secrets.token_hex(16),
            host_key="ssh-ed25519 "+b64(key_blob(self.seed)),transit_key=b64(secrets.token_bytes(32)),
            host_side=secrets.token_hex(8),operator_side=secrets.token_hex(8),relay=self.relay.transit,direct=[],
            host_os=os_name,host_name=platform.node()[:128],process_user=process_user()[:128],privilege=privilege,expires_at=timestamp(self.expires))
        self.info=HostInfo.from_offer(self.offer)
        try:
            async with asyncio.timeout(40):
                self.pairing=await Pairing.open(self.relay.mailbox)
                self._code=await self.pairing.allocate()
            self.task(self._pair()); self.task(self._expire())
            return self
        except BaseException:
            await self.aclose(); raise

    async def __aexit__(self, *_): await self.aclose()

    async def _expire(self):
        await asyncio.sleep(max(0,self.deadline-time.monotonic()))
        self.error=SessionExpired("Host lifetime expired")
        await self.aclose()

    async def _pair(self):
        try:
            async with asyncio.timeout(min(600,self.lifetime)):
                await self.pairing.establish()
                await self.pairing.send("0",self.offer)
                accept=await self.pairing.receive("0")
                strict(accept,("session_id","offer_hash","client_key"),kind="accept",role="operator")
                if accept["session_id"]!=self.offer["session_id"] or accept["offer_hash"]!=digest(self.offer): raise ProtocolViolation("Pairing transcript mismatch")
                if not isinstance(accept["client_key"],str) or not accept["client_key"].startswith("ssh-ed25519 "): raise ProtocolViolation("Invalid operator key")
                self.authorized=unb64(accept["client_key"].split(" ")[1]); key_public(self.authorized)
                await self.pairing.send("1",dict(schema=SCHEMA,type="ready",role="host",session_id=self.offer["session_id"],accept_hash=digest(accept)))
                self.accepted=True; self._code=None
            await self.pairing.aclose(); self.pairing=None
            self.ready.set()
            self.task(self._accept_loop()); self.task(self._first_auth_deadline())
        except asyncio.CancelledError: raise
        except Exception as exc:
            self.error=PairingExpired("Pairing expired") if isinstance(exc,TimeoutError) else exc
            await self.aclose()

    async def _first_auth_deadline(self):
        await asyncio.sleep(120)
        if not self.first_auth:
            self.error=SessionExpired("No SSH authentication followed pairing")
            await self.aclose()

    async def _accept_loop(self):
        delay=1
        while not self.closing:
            try:
                if len(self.connections)>=8:
                    await asyncio.sleep(0.2); continue
                async with asyncio.timeout(min(270,max(0,self.deadline-time.monotonic()))):
                    reader,writer=await dial(unb64(self.offer["transit_key"],32),self.offer["host_side"],sender=True,relay=self.relay.transit)
                connection=SSHConnection(reader,writer,server=True,seed=self.seed,authorized=self.authorized,handler=self._request,close_handler=self._close_request)
                self.connections.add(connection)
                self.task(self._connection(connection)); delay=1
            except asyncio.CancelledError: raise
            except Exception:
                await asyncio.sleep(delay); delay=min(10,delay*2)

    async def _connection(self, connection):
        try:
            await connection.start(); self.first_auth=True
            await connection.wait_closed()
        except Exception: await connection.aclose()
        finally:
            await connection.aclose()
            self.connections.discard(connection)

    def _request(self, channel, name, payload):
        if sum(len(c.channels) for c in self.connections)>64: raise UnsupportedOperation("Host channel limit reached")
        if name==b"subsystem":
            reader=Reader(payload); subsystem=reader.string(256); reader.done()
            if subsystem!=b"sftp" or not self.files: raise UnsupportedOperation("Subsystem unavailable")
            return SFTPServer(self.cwd).serve(channel)
        command,shell=command_request(name,payload)
        return serve_command(channel,command,shell,executor=self.executor,session_id=self.info.session_id,cwd=self.cwd)

    def _close_request(self, session_id):
        if session_id!=self.info.session_id or self.closing: return False
        asyncio.get_running_loop().call_later(0.1,lambda:self.task(self.aclose()))
        return True

    async def wait_ready(self):
        await self.ready.wait()
        if not self.accepted: raise self.error or SessionExpired("Host closed")

    async def wait_closed(self):
        await self.closed.wait()
        return self.close_reason

    async def aclose(self):
        if self.closing:
            if asyncio.current_task() is not self.close_owner: await self.closed.wait()
            return
        self.close_owner=asyncio.current_task()
        self.closing=True; self._code=None
        tasks=[task for task in self.tasks if task is not asyncio.current_task()]
        for task in tasks: task.cancel()
        if self.pairing: await self.pairing.aclose(); self.pairing=None
        await asyncio.gather(*(connection.aclose() for connection in tuple(self.connections)),return_exceptions=True)
        if tasks: await asyncio.gather(*tasks,return_exceptions=True)
        self.seed=None; self.authorized=None; self.ready.set()
        self.close_reason=CloseReason(type(self.error).__name__ if self.error else "closed",timestamp(time.time()))
        self.closed.set()


def open_host(**kwargs): return Host(**kwargs)
