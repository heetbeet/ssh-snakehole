"""Importable operator API. Lost commands are never retried automatically."""
import asyncio
import contextlib
import secrets
import time
from dataclasses import dataclass

from .errors import (CloseUnconfirmed, CommandTimedOut, ConnectTimeout, OutputLimitExceeded,
                     PairingExpired, RemoteCommandFailed, UnsupportedOperation)
from .errors import RelayUnavailable
from .host import RelayConfig
from .pairing import Pairing
from .sftp import Files
from .ssh import SSHConnection, key_blob
from .ticket import SCHEMA, Ticket, digest, strict, timestamp, validate_offer, expiry
from .transit import dial
from .wire import b64, unb64, string, json_bytes
from .platform import check_runtime


async def pair(code, *, relay=None):
    check_runtime()
    config=relay or RelayConfig(); pairing=None
    try:
        async with asyncio.timeout(120):
            pairing=await Pairing.open(config.mailbox); await pairing.claim(code); await pairing.establish()
            offer=validate_offer(await pairing.receive("0"))
            if offer["relay"]!=config.transit: raise ValueError("Pairing relay contradicts the operator's selected relay")
            seed=secrets.token_bytes(32)
            accept=dict(schema=SCHEMA,type="accept",role="operator",session_id=offer["session_id"],offer_hash=digest(offer),client_key="ssh-ed25519 "+b64(key_blob(seed)))
            await pairing.send("0",accept)
            ready=await pairing.receive("1")
            strict(ready,("session_id","accept_hash"),kind="ready",role="host")
            if ready["session_id"]!=offer["session_id"] or ready["accept_hash"]!=digest(accept): raise ValueError("Pairing acceptance did not authenticate")
            ticket=Ticket(offer,seed); ticket.check_live(); return ticket
    except TimeoutError as exc: raise PairingExpired("Pairing expired") from exc
    except (OSError,EOFError) as exc: raise RelayUnavailable("Pairing relay disconnected") from exc
    finally:
        if pairing: await pairing.aclose()


@dataclass(frozen=True)
class CommandExit:
    exit_code: int | None
    exit_signal: str | None
    elapsed: float


@dataclass(frozen=True)
class CommandResult(CommandExit):
    stdout: bytes
    stderr: bytes

    def check_returncode(self):
        if self.exit_code!=0 or self.exit_signal: raise RemoteCommandFailed(self)
        return self


@dataclass(frozen=True)
class CloseReceipt:
    accepted: bool
    transport_closed: bool
    timestamp: str


class RemoteProcess:
    def __init__(self,channel):
        self.channel=channel; self.stdout=channel.stdout; self.stderr=channel.stderr
        self.started=time.monotonic()

    async def send(self,data): await self.channel.send(data)
    async def close_stdin(self): await self.channel.close_stdin()
    async def wait(self):
        status,signal=await self.channel.wait()
        return CommandExit(status,signal,time.monotonic()-self.started)


class Session:
    def __init__(self,ticket,connection):
        self.ticket=ticket; self.info=ticket.info; self.connection=connection; self._files=None
        self.close_receipt=None

    @contextlib.asynccontextmanager
    async def exec(self,command,*,timeout=None):
        self.ticket.check_live()
        channel=await self.connection.open_channel()
        try:
            await channel.request(b"exec",string(command))
            process=RemoteProcess(channel)
            remaining=max(0,expiry(self.info.expires_at)-time.time())
            async with asyncio.timeout(min(timeout,remaining) if timeout is not None else remaining): yield process
        except TimeoutError as exc: raise CommandTimedOut() from exc
        finally: await channel.aclose()

    async def _run(self,command,argv,stdin,timeout,max_output):
        if max_output<0: raise ValueError("Output limit must be nonnegative")
        self.ticket.check_live()
        channel=await self.connection.open_channel(); output=[bytearray(),bytearray()]; total=0
        try:
            if argv:
                if self.connection.peer_extensions.get(b"exec-argv@ssh-snakehole")!=b"1": raise UnsupportedOperation("Peer does not support argument vectors")
                await channel.request(b"exec-argv@ssh-snakehole",string(json_bytes(command)))
            else: await channel.request(b"exec",string(command))
            process=RemoteProcess(channel)
            async def capture(stream,index):
                nonlocal total
                async for data in stream:
                    room=max_output-total
                    output[index].extend(data[:max(0,room)]); total+=len(data)
                    if total>max_output: raise OutputLimitExceeded()
            async def feed(): await process.send(stdin); await process.close_stdin()
            tasks=[asyncio.create_task(capture(process.stdout,0)),asyncio.create_task(capture(process.stderr,1)),asyncio.create_task(feed())]
            try:
                remaining=max(0,expiry(self.info.expires_at)-time.time())
                async with asyncio.timeout(min(timeout,remaining) if timeout is not None else remaining):
                    await asyncio.gather(*tasks); result=await process.wait()
                return CommandResult(result.exit_code,result.exit_signal,result.elapsed,bytes(output[0]),bytes(output[1]))
            except (TimeoutError,OutputLimitExceeded) as exc:
                error=OutputLimitExceeded if isinstance(exc,OutputLimitExceeded) else CommandTimedOut
                raise error(stdout=bytes(output[0]),stderr=bytes(output[1])) from exc
            finally:
                for task in tasks: task.cancel()
                await asyncio.gather(*tasks,return_exceptions=True)
        finally: await channel.aclose()

    async def run(self,command,*,stdin=b"",timeout=300,max_output=8*1024*1024):
        return await self._run(command,False,stdin,timeout,max_output)

    async def run_argv(self,argv,*,stdin=b"",timeout=300,max_output=8*1024*1024):
        return await self._run(list(argv),True,stdin,timeout,max_output)

    async def files(self):
        if self._files is None: self._files=await Files(self.connection).start()
        return self._files

    async def put(self,source,destination,*,overwrite=False): return await (await self.files()).put(source,destination,overwrite=overwrite)
    async def get(self,source,destination,*,overwrite=False): return await (await self.files()).get(source,destination,overwrite=overwrite)

    async def close_host(self):
        if self.close_receipt: return self.close_receipt
        try:
            if not await self.connection.global_request(b"close@ssh-snakehole",string(self.info.session_id)): raise CloseUnconfirmed("Host rejected close request")
            async with asyncio.timeout(5): await self.connection.wait_closed()
            self.close_receipt=CloseReceipt(True,True,timestamp(time.time()))
            return self.close_receipt
        except (Exception,) as exc:
            if isinstance(exc,CloseUnconfirmed): raise
            raise CloseUnconfirmed("Remote close could not be confirmed") from exc

    async def aclose(self): await self.connection.aclose()


@contextlib.asynccontextmanager
async def connect(code_or_ticket,*,relay=None,timeout=40):
    check_runtime()
    ticket=code_or_ticket if isinstance(code_or_ticket,Ticket) else await pair(code_or_ticket,relay=relay)
    ticket.check_live()
    if relay is not None and relay.transit!=ticket.offer["relay"]: raise ValueError("Ticket relay contradicts explicit configuration")
    connection=None
    try:
        async with asyncio.timeout(timeout):
            reader,writer=await dial(unb64(ticket.offer["transit_key"],32),ticket.offer["operator_side"],relay=ticket.offer["relay"])
            connection=SSHConnection(reader,writer,seed=ticket.client_seed,pin=unb64(ticket.offer["host_key"].split(" ")[1]))
            await connection.start()
    except TimeoutError as exc:
        error=ConnectTimeout("SSH connection timed out; the accepted ticket can be retried")
        error.ticket=ticket
        raise error from exc
    except (OSError,EOFError) as exc:
        if connection: await connection.aclose()
        error=RelayUnavailable("SSH relay disconnected; the accepted ticket can be retried")
        error.ticket=ticket
        raise error from exc
    except BaseException as exc:
        if connection: await connection.aclose()
        if isinstance(exc,Exception): exc.ticket=ticket
        raise
    try: yield Session(ticket,connection)
    finally: await connection.aclose()
