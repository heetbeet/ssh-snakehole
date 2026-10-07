"""SSH v2 with one modern profile, public-key auth and bounded session channels.

Wire authorities: RFC 4251-4254, 5656, 8308, 8709, 8731 and OpenSSH
strict-KEX/ChaCha20-Poly1305. Native reference implementations are test-only.
"""
import asyncio
import contextlib
import hashlib
import secrets
import time
import weakref

from ._crypto import SSHCipher, public_key, sign, verify, x25519
from .errors import (AuthenticationFailed, HostKeyMismatch, OutcomeUnknown,
                     ProtocolViolation, UnsupportedPeer, UnsupportedOperation)
from .wire import Reader, mpint, string, uint

WINDOW = 256 * 1024
PACKET_LIMIT = 256 * 1024
CHUNK = 32768
IDENT = b"SSH-2.0-ssh_snakehole_1"
KEX = b"curve25519-sha256"
KEY = b"ssh-ed25519"
CIPHER = b"chacha20-poly1305@openssh.com"
CHANNELS = weakref.WeakSet()


def key_blob(seed):
    return string(KEY) + string(public_key(seed))


def key_public(blob):
    reader = Reader(blob)
    if reader.string() != KEY: raise ProtocolViolation("Expected Ed25519 key")
    public = reader.string(32)
    reader.done()
    if len(public) != 32: raise ProtocolViolation("Invalid Ed25519 key length")
    return public


def _names(data):
    if len(data) > 4096: raise ProtocolViolation("Algorithm list exceeds limit")
    result = data.split(b",") if data else []
    if len(result) > 64 or any(not x or len(x)>256 for x in result):
        raise ProtocolViolation("Invalid algorithm list")
    return result


class ByteStream:
    """Single-consumer stream with channel-window credit, not an unbounded queue."""
    def __init__(self, channel):
        self.channel = channel
        self.buffer = bytearray()
        self.eof = False
        self.event = asyncio.Event()

    def feed(self, data):
        if self.eof: raise ProtocolViolation("Channel data after EOF")
        self.buffer.extend(data)
        self.event.set()

    def finish(self):
        self.eof = True
        self.event.set()

    async def read(self, count=CHUNK):
        if count <= 0: return b""
        while not self.buffer and not self.eof:
            self.event.clear()
            await self.event.wait()
        if not self.buffer:
            if self.channel.conn.error: raise self.channel.conn.error
            return b""
        data = bytes(self.buffer[:count]); del self.buffer[:count]
        if not self.channel.closed:
            self.channel.receive_window += len(data)
            await self.channel.conn.send(93, uint(self.channel.remote_id)+uint(len(data)))
        return data

    async def readexactly(self, count):
        if count > PACKET_LIMIT: raise ProtocolViolation("Stream read exceeds limit")
        result = bytearray()
        while len(result) < count:
            chunk = await self.read(min(CHUNK,count-len(result)))
            if not chunk: raise EOFError("Channel ended inside a record")
            result.extend(chunk)
        return bytes(result)

    def __aiter__(self): return self

    async def __anext__(self):
        data = await self.read()
        if not data: raise StopAsyncIteration
        return data


class Channel:
    def __init__(self, conn, channel_id):
        if len(CHANNELS)>=64: raise UnsupportedOperation("Process channel buffer limit reached")
        CHANNELS.add(self)
        self.conn, self.id = conn, channel_id
        self.remote_id = None
        self.remote_window = 0
        self.remote_max = CHUNK
        self.receive_window = WINDOW
        self.stdout, self.stderr = ByteStream(self), ByteStream(self)
        self.window_event = asyncio.Event()
        self.opened = asyncio.get_running_loop().create_future()
        self.reply = None
        self.request_lock = asyncio.Lock()
        self.send_lock = asyncio.Lock()
        self.closed = False
        self.sent_eof = False
        self.started = False
        self.status = None
        self.exit_signal = None
        self.done = asyncio.Event()
        self.worker = None

    async def request(self, name, payload=b""):
        async with self.request_lock:
            if self.closed: raise OutcomeUnknown("SSH channel closed")
            self.reply = asyncio.get_running_loop().create_future()
            try:
                await self.conn.send(98, uint(self.remote_id)+string(name)+b"\1"+payload)
                if not await asyncio.wait_for(self.reply,10):
                    raise UnsupportedOperation("SSH channel request rejected")
            finally:
                self.reply = None

    async def send(self, data, *, stderr=False):
        async with self.send_lock:
            view = memoryview(data)
            while view:
                while not self.remote_window and not self.closed:
                    self.window_event.clear()
                    await self.window_event.wait()
                if self.closed: raise OutcomeUnknown("SSH channel closed during write")
                count = min(CHUNK,self.remote_max,self.remote_window,len(view))
                if count <= 0: raise ProtocolViolation("Invalid peer channel packet limit")
                self.remote_window -= count
                payload = uint(self.remote_id)
                if stderr: payload += uint(1)
                await self.conn.send(95 if stderr else 94,payload+string(bytes(view[:count])))
                view = view[count:]

    async def close_stdin(self):
        if not self.sent_eof and not self.closed:
            self.sent_eof = True
            await self.conn.send(96,uint(self.remote_id))

    async def exit(self, status):
        if not self.closed:
            if status >= 0:
                await self.conn.send(98,uint(self.remote_id)+string(b"exit-status")+b"\0"+uint(status & 0xffffffff))
            else:
                import signal
                name = signal.Signals(-status).name.removeprefix("SIG")
                await self.conn.send(98,uint(self.remote_id)+string(b"exit-signal")+b"\0"+string(name)+b"\0"+string(b"")+string(b""))
            await self.close_stdin()
            await self.aclose()

    def finish(self):
        if self.closed: return
        self.closed = True
        self.stdout.finish(); self.stderr.finish()
        self.window_event.set(); self.done.set()
        if not self.opened.done(): self.opened.set_result(False)
        if self.reply is not None and not self.reply.done(): self.reply.set_result(False)
        if self.worker is not None and self.worker is not asyncio.current_task(): self.worker.cancel()

    async def aclose(self):
        if not self.closed:
            self.finish()
            if self.remote_id is not None and not self.conn.closed:
                with contextlib.suppress(OSError,OutcomeUnknown):
                    await self.conn.send(97,uint(self.remote_id))
        self.conn.channels.pop(self.id,None)

    async def wait(self):
        await self.done.wait()
        if self.status is None and self.exit_signal is None:
            raise self.conn.error or OutcomeUnknown("No confirmed remote exit status")
        return self.status, self.exit_signal


class SSHConnection:
    def __init__(self, reader, writer, *, server=False, seed, pin=None,
                 authorized=None, handler=None, close_handler=None):
        self.reader, self.writer, self.server = reader, writer, server
        self.seed, self.pin, self.authorized = seed, pin, authorized
        self.handler, self.close_handler = handler, close_handler
        self.tx_cipher = self.rx_cipher = None
        self.tx_seq = self.rx_seq = 0
        self.tx_bytes = self.rx_bytes = 0
        self.session_identifier = None
        self.channels = {}
        self.next_channel = 0
        self.closed = False
        self.error = None
        self.send_lock = asyncio.Lock()
        self.global_lock = asyncio.Lock()
        self.global_reply = None
        self.ready = asyncio.Event()
        self.ready.set()
        self.ended = asyncio.Event()
        self.read_task = self.monitor_task = None
        self.last_activity = self.last_rekey = time.monotonic()
        self.local_init = None
        self.rekey_started = None
        self.peer_extensions = {}

    async def start(self):
        try:
            async with asyncio.timeout(10):
                self.writer.write(IDENT+b"\r\n"); await self.writer.drain()
                total = 0
                while True:
                    line = await self.reader.readuntil(b"\n")
                    total += len(line)
                    if total > 4096: raise ProtocolViolation("Excess SSH banner text")
                    if line.startswith(b"SSH-"):
                        if len(line)>255 or not line.startswith(b"SSH-2.0-"):
                            raise UnsupportedPeer("SSH 2.0 required")
                        self.peer_ident = line.rstrip(b"\r\n")
                        break
                await self._kex()
                await self._authenticate()
            self.read_task = asyncio.create_task(self._read_loop(),name="snakehole-ssh-read")
            self.monitor_task = asyncio.create_task(self._monitor(),name="snakehole-ssh-monitor")
            return self
        except BaseException:
            await self.aclose()
            raise

    async def send(self, message, payload=b""):
        while True:
            await self.ready.wait()
            async with self.send_lock:
                if not self.ready.is_set(): continue
                await self._write_packet(bytes([message])+payload)
                return

    async def _send_packet(self, payload):
        async with self.send_lock: await self._write_packet(payload)

    async def _write_packet(self,payload):
        if self.closed: raise self.error or OutcomeUnknown("SSH connection closed")
        if len(payload)>PACKET_LIMIT-16: raise ProtocolViolation("SSH packet exceeds limit")
        padding = (-(len(payload)+1+(0 if self.tx_cipher else 4))) % 8
        if padding<4: padding+=8
        packet = uint(len(payload)+padding+1)+bytes([padding])+payload+secrets.token_bytes(padding)
        if self.tx_cipher:
            packet = await asyncio.to_thread(self.tx_cipher.encrypt,self.tx_seq,packet)
        self.tx_seq += 1
        if self.tx_seq >= 2**32: raise ProtocolViolation("SSH sequence exhausted")
        self.tx_bytes += len(packet)
        self.writer.write(packet)
        await self.writer.drain()

    async def _receive(self):
        header = await self.reader.readexactly(4)
        count = self.rx_cipher.length(self.rx_seq,header) if self.rx_cipher else int.from_bytes(header,"big")
        if not 5<=count<=PACKET_LIMIT: raise ProtocolViolation("Invalid SSH packet length")
        rest = await self.reader.readexactly(count+(16 if self.rx_cipher else 0))
        packet = header+rest
        if self.rx_cipher:
            try: packet = await asyncio.to_thread(self.rx_cipher.decrypt,self.rx_seq,packet)
            except ValueError as exc: raise ProtocolViolation("SSH authentication tag failed") from exc
        padding = packet[4]
        if padding<4 or padding>=count: raise ProtocolViolation("Invalid SSH padding")
        self.rx_seq += 1
        if self.rx_seq >= 2**32: raise ProtocolViolation("SSH sequence exhausted")
        self.rx_bytes += len(packet)
        self.last_activity = time.monotonic()
        return packet[5:4+count-padding]

    def _init(self):
        role = b"s" if self.server else b"c"
        lists = [KEX+b",ext-info-"+role+b",kex-strict-"+role+b"-v00@openssh.com",KEY,CIPHER,CIPHER,
                 b"hmac-sha2-256",b"hmac-sha2-256",b"none",b"none",b"",b""]
        return b"\x14"+secrets.token_bytes(16)+b"".join(string(x) for x in lists)+b"\0"+uint(0)

    async def _kex(self, peer_init=None):
        first = self.session_identifier is None
        self.ready.clear()
        local = self.local_init or self._init()
        if self.local_init is None: await self._send_packet(local)
        self.local_init = None
        peer = peer_init or await self._receive()
        if not peer or peer[0]!=20: raise ProtocolViolation("Expected SSH KEXINIT")
        r = Reader(peer[1:]); r.take(16)
        lists = [_names(r.string(4096)) for _ in range(10)]
        guessed = r.byte(); reserved = r.uint(); r.done()
        strict = b"kex-strict-"+(b"c" if self.server else b"s")+b"-v00@openssh.com"
        if first and strict not in lists[0]: raise UnsupportedPeer("Strict key exchange required")
        expected = [KEX,KEY,CIPHER,CIPHER,b"hmac-sha2-256",b"hmac-sha2-256",b"none",b"none"]
        for available, required in zip(lists,expected):
            if required not in available: raise UnsupportedPeer("Peer does not support the SSH profile")
        if guessed not in (0,1) or reserved!=0: raise ProtocolViolation("Invalid KEX flags")
        if guessed and (lists[0][0]!=KEX or lists[1][0]!=KEY): await self._receive()
        secret = secrets.token_bytes(32)
        own_public = await asyncio.to_thread(x25519,secret)
        if self.server:
            message = await self._receive()
            if message[:1]!=b"\x1e": raise ProtocolViolation("Expected ECDH init")
            r = Reader(message[1:]); peer_public=r.string(32); r.done()
            host = key_blob(self.seed)
            qc,qs,ic,is_,vc,vs = peer_public,own_public,peer,local,self.peer_ident,IDENT
        else:
            await self._send_packet(b"\x1e"+string(own_public))
            message = await self._receive()
            if message[:1]!=b"\x1f": raise ProtocolViolation("Expected ECDH reply")
            r=Reader(message[1:]); host=r.string(128); peer_public=r.string(32); signature=r.string(128); r.done()
            if host!=self.pin: raise HostKeyMismatch("SSH host key differs from paired identity")
            qc,qs,ic,is_,vc,vs = own_public,peer_public,local,peer,IDENT,self.peer_ident
        try: shared = await asyncio.to_thread(x25519,secret,peer_public)
        except ValueError as exc: raise ProtocolViolation("Invalid SSH key agreement") from exc
        encoded = mpint(int.from_bytes(shared,"big"))
        exchange = hashlib.sha256(b"".join(string(x) for x in (vc,vs,ic,is_,host,qc,qs))+encoded).digest()
        if first: self.session_identifier=exchange
        if self.server:
            sig = string(KEY)+string(await asyncio.to_thread(sign,self.seed,exchange))
            await self._send_packet(b"\x1f"+string(host)+string(own_public)+string(sig))
        else:
            r=Reader(signature)
            if r.string()!=KEY: raise ProtocolViolation("Wrong host signature algorithm")
            sig=r.string(64); r.done()
            if not await asyncio.to_thread(verify,key_public(host),exchange,sig):
                raise HostKeyMismatch("SSH host signature did not verify")

        def derive(label):
            value = hashlib.sha256(encoded+exchange+label+self.session_identifier).digest()
            return value+hashlib.sha256(encoded+exchange+value).digest()

        tx = derive(b"D" if self.server else b"C")
        rx = derive(b"C" if self.server else b"D")
        await self._send_packet(b"\x15")
        self.tx_cipher=SSHCipher(tx); self.tx_seq=0
        message=await self._receive()
        if message!=b"\x15": raise ProtocolViolation("Expected SSH NEWKEYS")
        self.rx_cipher=SSHCipher(rx); self.rx_seq=0
        self.tx_bytes=self.rx_bytes=0; self.last_rekey=time.monotonic()
        self.rekey_started=None
        if first and self.server and b"ext-info-c" in lists[0]:
            extensions={b"server-sig-algs":KEY,b"exec-argv@ssh-snakehole":b"1"}
            await self._send_packet(b"\x07"+uint(len(extensions))+b"".join(string(k)+string(v) for k,v in extensions.items()))
        self.ready.set()

    def _extensions(self, message):
        r=Reader(message[1:]); count=r.uint()
        if count>32: raise ProtocolViolation("Excess SSH extensions")
        for _ in range(count):
            name,value=r.string(256),r.string(8192)
            if name in self.peer_extensions: raise ProtocolViolation("Duplicate SSH extension")
            self.peer_extensions[name]=value
        r.done()

    async def _auth_receive(self):
        while True:
            message=await self._receive()
            if message[:1]==b"\x07": self._extensions(message)
            elif message[:1] in (b"\x02",b"\x04",b"\x35"):
                continue
            else: return message

    async def _authenticate(self):
        if not self.server:
            await self._send_packet(b"\x05"+string(b"ssh-userauth"))
            message=await self._auth_receive()
            if message!=b"\x06"+string(b"ssh-userauth"):
                raise ProtocolViolation("SSH service not accepted")
            request=b"\x32"+string(b"help")+string(b"ssh-connection")+string(b"publickey")+b"\1"+string(KEY)+string(key_blob(self.seed))
            signature=await asyncio.to_thread(sign,self.seed,string(self.session_identifier)+request)
            await self._send_packet(request+string(string(KEY)+string(signature)))
            if await self._auth_receive()!=b"\x34": raise AuthenticationFailed("Operator key rejected")
            return
        message=await self._auth_receive()
        if message!=b"\x05"+string(b"ssh-userauth"):
            raise ProtocolViolation("Expected userauth service")
        await self._send_packet(b"\x06"+string(b"ssh-userauth"))
        failures=0
        while failures<3:
            message=await self._auth_receive()
            if message[:1]!=b"\x32": raise ProtocolViolation("Expected SSH userauth")
            r=Reader(message[1:]); user,service,method=r.string(256),r.string(256),r.string(256)
            accepted=False
            if user==b"help" and service==b"ssh-connection" and method==b"publickey":
                signed=r.byte(); algorithm,blob=r.string(256),r.string(128)
                prefix=message[:1+r.pos]
                if signed==0 and algorithm==KEY and blob==self.authorized:
                    r.done()
                    await self._send_packet(b"\x3c"+string(KEY)+string(blob)); continue
                if signed==1:
                    signature=r.string(128); r.done()
                    sr=Reader(signature); sigalgo=sr.string(256); sig=sr.string(64); sr.done()
                    if algorithm==KEY and sigalgo==KEY and blob==self.authorized:
                        accepted=await asyncio.to_thread(verify,key_public(blob),string(self.session_identifier)+prefix,sig)
            if accepted:
                await self._send_packet(b"\x34"); return
            failures+=1
            await self._send_packet(b"\x33"+string(b"publickey")+b"\0")
        raise AuthenticationFailed("Too many failed authentication attempts")

    async def open_channel(self):
        if len(self.channels)>=16: raise UnsupportedOperation("SSH channel limit reached")
        channel=Channel(self,self.next_channel); self.next_channel+=1
        self.channels[channel.id]=channel
        try:
            await self.send(90,string(b"session")+uint(channel.id)+uint(WINDOW)+uint(CHUNK))
            if not await asyncio.wait_for(channel.opened,10):
                raise UnsupportedOperation("SSH session channel rejected")
            return channel
        except BaseException:
            await channel.aclose(); raise

    async def global_request(self, name, payload=b"", timeout=10):
        async with self.global_lock:
            self.global_reply=asyncio.get_running_loop().create_future()
            try:
                await self.send(80,string(name)+b"\1"+payload)
                return await asyncio.wait_for(self.global_reply,timeout)
            finally: self.global_reply=None

    async def _read_loop(self):
        deferred=[]; deferred_size=0
        try:
            while not self.closed:
                if deferred and self.ready.is_set():
                    message=deferred.pop(0); deferred_size-=len(message)
                else: message=await self._receive()
                if not message: raise ProtocolViolation("Empty SSH packet")
                kind=message[0]; r=Reader(message[1:])
                if kind==20:
                    async with asyncio.timeout(10): await self._kex(message)
                    continue
                if self.local_init is not None:
                    deferred_size+=len(message)
                    if deferred_size>256*1024: raise ProtocolViolation("Too much data pending SSH key exchange")
                    deferred.append(message); continue
                if kind==1: raise OutcomeUnknown("SSH peer disconnected")
                if kind in (2,3,4): continue
                if kind==7: self._extensions(message); continue
                if kind==80:
                    name,want=r.string(256),r.byte()
                    if want not in (0,1): raise ProtocolViolation("Invalid SSH reply flag")
                    ok=False
                    if name==b"keepalive@openssh.com": r.done(); ok=True
                    elif name==b"close@ssh-snakehole" and self.server and self.close_handler:
                        session_id=r.text(64); r.done()
                        ok=self.close_handler(session_id)
                    if want: await self.send(81 if ok else 82)
                    continue
                if kind in (81,82):
                    r.done()
                    if self.global_reply is None or self.global_reply.done():
                        raise ProtocolViolation("Unexpected global SSH reply")
                    self.global_reply.set_result(kind==81); continue
                if kind==90:
                    channel_type,remote,window,max_packet=r.string(256),r.uint(),r.uint(),r.uint()
                    if not self.server or channel_type!=b"session" or len(self.channels)>=16 or len(CHANNELS)>=64:
                        await self.send(92,uint(remote)+uint(1)+string(b"Channel rejected")+string(b"")); continue
                    r.done()
                    if not 1<=max_packet<=PACKET_LIMIT: raise ProtocolViolation("Invalid channel maximum")
                    channel=Channel(self,self.next_channel); self.next_channel+=1
                    channel.remote_id,channel.remote_window,channel.remote_max=remote,window,max_packet
                    self.channels[channel.id]=channel
                    channel.opened.set_result(True)
                    await self.send(91,uint(remote)+uint(channel.id)+uint(WINDOW)+uint(CHUNK)); continue
                channel_id=r.uint()
                channel=self.channels.get(channel_id)
                if channel is None:
                    if channel_id<self.next_channel and kind in (93,94,95,96,97,99,100): continue
                    raise ProtocolViolation("Unknown SSH channel")
                if channel.closed and kind in (93,94,95,96,97,99,100): continue
                if kind==91:
                    if channel.remote_id is not None: raise ProtocolViolation("Duplicate channel confirmation")
                    channel.remote_id,channel.remote_window,channel.remote_max=r.uint(),r.uint(),r.uint(); r.done()
                    if not 1<=channel.remote_max<=PACKET_LIMIT: raise ProtocolViolation("Invalid channel maximum")
                    channel.opened.set_result(True)
                elif kind==92:
                    r.uint(); r.string(); r.string(); r.done()
                    channel.opened.set_result(False)
                elif kind==93:
                    adjustment=r.uint(); r.done()
                    if not adjustment or channel.remote_window+adjustment>=2**32:
                        raise ProtocolViolation("Invalid channel window adjustment")
                    channel.remote_window+=adjustment; channel.window_event.set()
                elif kind in (94,95):
                    extended=r.uint() if kind==95 else 0
                    data=r.string(CHUNK); r.done()
                    if len(data)>channel.receive_window: raise ProtocolViolation("Peer exceeded channel credit")
                    if extended not in (0,1): raise ProtocolViolation("Unknown extended data type")
                    channel.receive_window-=len(data)
                    (channel.stderr if extended else channel.stdout).feed(data)
                elif kind==96:
                    r.done(); channel.stdout.finish(); channel.stderr.finish()
                elif kind==97:
                    r.done()
                    await channel.aclose()
                elif kind in (99,100):
                    r.done()
                    if channel.reply is None or channel.reply.done(): raise ProtocolViolation("Unexpected channel reply")
                    channel.reply.set_result(kind==99)
                elif kind==98:
                    name,want=r.string(256),r.byte(); payload=r.take(len(r.data)-r.pos)
                    if want not in (0,1): raise ProtocolViolation("Invalid SSH reply flag")
                    if name==b"exit-status" and not self.server:
                        if channel.status is not None or channel.exit_signal is not None: raise ProtocolViolation("Duplicate SSH exit status")
                        er=Reader(payload); channel.status=er.uint(); er.done()
                        if want: await self.send(100,uint(channel.remote_id))
                    elif name==b"exit-signal" and not self.server:
                        if channel.status is not None or channel.exit_signal is not None: raise ProtocolViolation("Duplicate SSH exit status")
                        er=Reader(payload); channel.exit_signal=er.text(64); er.byte(); er.string(); er.string(); er.done()
                        if want: await self.send(100,uint(channel.remote_id))
                    elif self.server and not channel.started and self.handler and name in (b"exec",b"exec-argv@ssh-snakehole",b"shell",b"subsystem"):
                        try: operation=self.handler(channel,name,payload)
                        except (ValueError,ProtocolViolation,UnsupportedOperation): operation=None
                        if operation is not None:
                            channel.started=True
                            if want: await self.send(99,uint(channel.remote_id))
                            channel.worker=asyncio.create_task(operation,name="snakehole-channel")
                            channel.worker.add_done_callback(self._worker_done)
                        elif want: await self.send(100,uint(channel.remote_id))
                    elif want: await self.send(100,uint(channel.remote_id))
                else: raise ProtocolViolation("Unsupported SSH message")
        except asyncio.CancelledError:
            raise
        except (Exception,) as exc:
            self.error=exc if isinstance(exc,(ProtocolViolation,OutcomeUnknown,UnsupportedPeer)) else OutcomeUnknown("SSH transport lost")
            if self.error is not exc: self.error.__cause__=exc
        finally:
            await self.aclose()

    def _worker_done(self, task):
        if not task.cancelled():
            error=task.exception()
            if error and not self.closed:
                self.error=error if isinstance(error,ProtocolViolation) else OutcomeUnknown("Remote channel failed")
                if self.error is not error: self.error.__cause__=error
                asyncio.create_task(self.aclose())

    async def _monitor(self):
        try:
            while not self.closed:
                await asyncio.sleep(1)
                if self.ready.is_set() and (max(self.tx_bytes,self.rx_bytes)>=256*1024*1024 or time.monotonic()-self.last_rekey>=3600 or max(self.tx_seq,self.rx_seq)>=2**32-1024):
                    self.ready.clear(); self.local_init=self._init()
                    self.rekey_started=time.monotonic()
                    await self._send_packet(self.local_init)
                if self.rekey_started is not None and time.monotonic()-self.rekey_started>=10:
                    raise ProtocolViolation("SSH key exchange timed out")
                if time.monotonic()-self.last_activity>=15 and self.ready.is_set():
                    await self.global_request(b"keepalive@openssh.com")
        except asyncio.CancelledError: raise
        except Exception:
            self.error=OutcomeUnknown("SSH keepalive failed")
            await self.aclose()

    async def aclose(self):
        if self.closed: return
        self.closed=True; self.ready.set()
        workers=[]
        for channel in tuple(self.channels.values()):
            channel.finish()
            if channel.worker and channel.worker is not asyncio.current_task(): workers.append(channel.worker)
        self.channels.clear()
        if self.global_reply is not None and not self.global_reply.done(): self.global_reply.set_result(False)
        for task in (self.read_task,self.monitor_task):
            if task and task is not asyncio.current_task(): task.cancel(); workers.append(task)
        self.writer.close()
        with contextlib.suppress(Exception): await self.writer.wait_closed()
        if workers:
            with contextlib.suppress(TimeoutError):
                async with asyncio.timeout(5): await asyncio.gather(*workers,return_exceptions=True)
        self.ended.set()

    async def wait_closed(self): await self.ended.wait()
