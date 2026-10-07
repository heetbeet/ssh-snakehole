"""SFTP v3 client/server and sibling-file commits. Paths have account-wide access."""
import asyncio
import contextlib
import errno
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path

from .errors import AtomicCommitUnavailable, ProtocolViolation, TransferFailed, UnsupportedOperation
from .wire import Reader, U64, string, uint
from .aio import file_call

LIMIT = 65536
DATA = 32768


class SFTPFailure(OSError):
    """A negative status received from the peer, rather than a lost reply."""


def local_path(value):
    if "\0" in value: raise ValueError("NUL in path")
    if os.name != "nt": return value
    value = value.replace("\\", "/")
    if value.startswith("//") or value.startswith("/dev/"): raise ValueError("UNC and device paths are not supported")
    if len(value)>3 and value[0]=="/" and value[1].isalpha() and value[2:4]==":/": value=value[1:]
    drive, tail = os.path.splitdrive(value)
    if ":" in tail or drive and not tail.startswith("/"): raise ValueError("Alternate streams and drive-relative paths are not supported")
    for part in tail.split("/"):
        if part in (".",".."): continue
        if part.endswith(("."," ")) or part.split(".",1)[0].upper() in {"CON","PRN","AUX","NUL",*(f"COM{i}" for i in range(1,10)),*(f"LPT{i}" for i in range(1,10))}:
            raise ValueError("Ambiguous Windows path")
    return value


def remote_path(value):
    value = os.path.abspath(value).replace("\\", "/")
    return "/"+value if os.name == "nt" else value


def attributes(info):
    return uint(1|4|8)+U64.pack(info.st_size)+uint(info.st_mode)+uint(int(info.st_atime)&0xffffffff)+uint(int(info.st_mtime)&0xffffffff)


def read_attributes(r):
    flags=r.uint()
    if flags & ~15: raise ProtocolViolation("Unsupported SFTP attributes")
    result={}
    if flags&1: result["size"]=r.uint64()
    if flags&2: result["uid"],result["gid"]=r.uint(),r.uint()
    if flags&4: result["permissions"]=r.uint()
    if flags&8: result["atime"],result["mtime"]=r.uint(),r.uint()
    return result


async def packet(stream):
    count=int.from_bytes(await stream.readexactly(4),"big")
    if not 1<=count<=LIMIT: raise ProtocolViolation("Invalid SFTP record size")
    return await stream.readexactly(count)


async def send(channel, kind, payload=b""):
    data=bytes([kind])+payload
    if len(data)>LIMIT: raise ProtocolViolation("SFTP record exceeds limit")
    await channel.send(uint(len(data))+data)


def commit(source, destination, overwrite):
    if overwrite: os.replace(source,destination)
    else:
        os.link(source,destination)
        os.unlink(source)


class SFTPServer:
    def __init__(self,cwd=None): self.handles={}; self.cwd=cwd or os.getcwd()

    def path(self,value):
        value=local_path(value)
        return value if os.path.isabs(value) else os.path.join(self.cwd,value)

    def handle(self, r, directory=False):
        key=r.string(32)
        if key not in self.handles or self.handles[key][0]!=directory: raise OSError(errno.EBADF,"Invalid SFTP handle")
        return self.handles[key][1]

    def perform(self, kind, r):
        if kind==3:
            path=self.path(r.text()); flags=r.uint(); attrs=read_attributes(r); r.done()
            if flags & ~63 or not flags&3: raise ValueError("Invalid SFTP open flags")
            mode=os.O_RDWR if flags&3==3 else os.O_WRONLY if flags&2 else os.O_RDONLY
            for bit, option in ((4,os.O_APPEND),(8,os.O_CREAT),(16,os.O_TRUNC),(32,os.O_EXCL)):
                if flags&bit: mode|=option
            if len(self.handles)>=64: raise OSError(errno.EMFILE,"SFTP handle limit reached")
            fd=os.open(path,mode|getattr(os,"O_BINARY",0)|getattr(os,"O_NONBLOCK",0),attrs.get("permissions",0o600)&0o777)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                os.close(fd); raise UnsupportedOperation("SFTP file handles require regular files")
            key=secrets.token_bytes(16); self.handles[key]=(False,fd)
            return 102,string(key)
        if kind==4:
            key=r.string(32); r.done()
            directory,handle=self.handles.pop(key)
            if directory: handle.close()
            else: os.close(handle)
        elif kind==5:
            fd=self.handle(r); offset=r.uint64(); count=r.uint(); r.done()
            if offset>=2**63 or count>DATA: raise ValueError("Invalid SFTP read size or offset")
            os.lseek(fd,offset,0); data=os.read(fd,count)
            return (103,string(data)) if data else (101,uint(1)+string("")+string(""))
        elif kind==6:
            fd=self.handle(r); offset=r.uint64(); data=r.string(DATA); r.done()
            if offset>=2**63: raise ValueError("Invalid SFTP write offset")
            os.lseek(fd,offset,0)
            view=memoryview(data)
            while view:
                count=os.write(fd,view)
                if not count: raise OSError("Short SFTP write")
                view=view[count:]
        elif kind in (7,17):
            path=self.path(r.text()); r.done()
            return 105,attributes(os.stat(path,follow_symlinks=kind==17))
        elif kind==8:
            fd=self.handle(r); r.done(); return 105,attributes(os.fstat(fd))
        elif kind in (9,10):
            target=self.path(r.text()) if kind==9 else self.handle(r)
            attrs=read_attributes(r); r.done()
            if "uid" in attrs: raise UnsupportedOperation("SFTP ownership changes are not supported")
            if "size" in attrs:
                if isinstance(target,int): os.ftruncate(target,attrs["size"])
                else: os.truncate(target,attrs["size"])
            if "permissions" in attrs: os.chmod(target,attrs["permissions"]&0o777)
            if "atime" in attrs: os.utime(target,(attrs["atime"],attrs["mtime"]))
        elif kind==11:
            path=self.path(r.text()); r.done()
            if len(self.handles)>=64: raise OSError(errno.EMFILE,"SFTP handle limit reached")
            key=secrets.token_bytes(16); self.handles[key]=(True,os.scandir(path)); return 102,string(key)
        elif kind==12:
            iterator=self.handle(r,True); r.done(); entries=[]
            for _ in range(16):
                entry=next(iterator,None)
                if entry is None: break
                entries.append(string(entry.name)+string(entry.name)+attributes(entry.stat(follow_symlinks=False)))
            if not entries: return 101,uint(1)+string("")+string("")
            return 104,uint(len(entries))+b"".join(entries)
        elif kind in (13,14,15):
            path=self.path(r.text()); attrs=read_attributes(r) if kind==14 else {}; r.done()
            if kind==13: os.unlink(path)
            elif kind==14: os.mkdir(path,attrs.get("permissions",0o700)&0o777)
            else: os.rmdir(path)
        elif kind in (16,19):
            path=self.path(r.text()); r.done()
            value=remote_path(os.path.realpath(path)) if kind==16 else os.readlink(path)
            return 104,uint(1)+string(value)+string(value)+uint(0)
        elif kind==18:
            source,dest=self.path(r.text()),self.path(r.text()); r.done()
            commit(source,dest,False)
        elif kind==20:
            target,link=r.text(),self.path(r.text()); r.done(); os.symlink(local_path(target),link)
        elif kind==200:
            extension=r.string(128)
            if extension==b"fsync@openssh.com":
                fd=self.handle(r); r.done(); os.fsync(fd)
            elif extension in (b"posix-rename@openssh.com", b"commit@ssh-snakehole"):
                source,dest=self.path(r.text()),self.path(r.text())
                overwrite=True if extension==b"posix-rename@openssh.com" else r.byte()
                if overwrite not in (0,1,True): raise ValueError("Invalid overwrite flag")
                r.done(); commit(source,dest,overwrite)
            else: raise UnsupportedOperation("Unknown SFTP extension")
        else: raise UnsupportedOperation("Unknown SFTP operation")
        return 101,uint(0)+string("")+string("")

    async def serve(self, channel):
        try:
            initial=await packet(channel.stdout)
            if initial!=b"\1"+uint(3): raise ProtocolViolation("SFTP v3 required")
            extensions={"posix-rename@openssh.com":"1","fsync@openssh.com":"1","commit@ssh-snakehole":"1"}
            await send(channel,2,uint(3)+b"".join(string(k)+string(v) for k,v in extensions.items()))
            while True:
                data=await packet(channel.stdout); kind=data[0]; r=Reader(data[1:]); request=r.uint()
                try: reply,payload=await file_call(self.perform,kind,r)
                except (OSError,KeyError,ValueError,UnsupportedOperation) as exc:
                    code=2 if isinstance(exc,FileNotFoundError) else 3 if isinstance(exc,PermissionError) else 8 if isinstance(exc,UnsupportedOperation) else 4
                    reply,payload=101,uint(code)+string(str(exc)[:256])+string("")
                await send(channel,reply,uint(request)+payload)
        except EOFError: pass
        finally:
            for directory,handle in self.handles.values():
                with contextlib.suppress(OSError): handle.close() if directory else os.close(handle)
            self.handles.clear()
            await channel.aclose()


@dataclass(frozen=True)
class TransferResult:
    bytes_copied: int
    destination: str
    durable: bool


class Files:
    def __init__(self, connection):
        self.connection=connection; self.channel=None; self.lock=asyncio.Lock(); self.sequence=0; self.extensions={}

    async def start(self):
        self.channel=await self.connection.open_channel()
        try:
            await self.channel.request(b"subsystem",string(b"sftp"))
            await send(self.channel,1,uint(3))
            message=await packet(self.channel.stdout)
            r=Reader(message[1:])
            if message[0]!=2 or r.uint()!=3: raise UnsupportedOperation("SFTP v3 required")
            while r.pos<len(r.data):
                name,value=r.text(128),r.text(256)
                if name in self.extensions: raise ProtocolViolation("Duplicate SFTP extension")
                self.extensions[name]=value
            return self
        except BaseException:
            await self.channel.aclose(); raise

    async def request(self, kind, payload=b""):
        async with self.lock:
            self.sequence=(self.sequence+1)&0xffffffff
            await send(self.channel,kind,uint(self.sequence)+payload)
            message=await packet(self.channel.stdout); r=Reader(message[1:])
            if r.uint()!=self.sequence: raise ProtocolViolation("Unexpected SFTP reply ID")
            if message[0]==101:
                code=r.uint(); detail=r.text(); r.string(); r.done()
                if code not in (0,1):
                    if code==2: raise FileNotFoundError(detail)
                    if code==3: raise PermissionError(detail)
                    if code==8: raise UnsupportedOperation(detail)
                    raise SFTPFailure(detail)
                if code==1 and kind not in (5,12): raise ProtocolViolation("Unexpected SFTP EOF status")
                return code,r
            return message[0],r

    async def open(self, path, flags, mode=0o600):
        kind,r=await self.request(3,string(str(path))+uint(flags)+uint(4)+uint(mode))
        if kind!=102: raise ProtocolViolation("Expected SFTP handle")
        handle=r.string(32); r.done(); return handle

    async def close(self, handle): await self.request(4,string(handle))

    async def stat(self, path, *, follow_symlinks=True):
        kind,r=await self.request(17 if follow_symlinks else 7,string(str(path)))
        if kind!=105: raise ProtocolViolation("Expected SFTP attributes")
        result=read_attributes(r); r.done(); return result

    async def listdir(self, path="."):
        kind,r=await self.request(11,string(str(path)))
        if kind!=102: raise ProtocolViolation("Expected directory handle")
        handle=r.string(32); r.done(); result=[]
        try:
            while True:
                kind,r=await self.request(12,string(handle))
                if kind==1: break
                if kind!=104: raise ProtocolViolation("Expected SFTP names")
                count=r.uint()
                if count>128: raise ProtocolViolation("Too many SFTP names")
                for _ in range(count):
                    name=r.text(); r.string(); result.append((name,read_attributes(r)))
                r.done()
                if len(result)>100000: raise UnsupportedOperation("Directory listing exceeds limit")
        finally: await self.close(handle)
        return result

    async def mkdir(self, path): await self.request(14,string(str(path))+uint(4)+uint(0o700))
    async def remove(self, path): await self.request(13,string(str(path)))
    async def rmdir(self, path): await self.request(15,string(str(path)))

    async def rename(self, source, destination, *, overwrite=False):
        if "commit@ssh-snakehole" in self.extensions:
            await self.request(200,string("commit@ssh-snakehole")+string(str(source))+string(str(destination))+bytes([bool(overwrite)]))
        elif overwrite and "posix-rename@openssh.com" in self.extensions:
            await self.request(200,string("posix-rename@openssh.com")+string(str(source))+string(str(destination)))
        elif not overwrite:
            await self.request(18,string(str(source))+string(str(destination)))
        else: raise AtomicCommitUnavailable("Peer does not support atomic replacement")

    async def put(self, source, destination, *, overwrite=False):
        temporary=str(destination)+".snakehole-"+secrets.token_hex(8)
        handle=None; total=0; committed=False; commit_started=False
        try:
            handle=await self.open(temporary,2|8|32)
            with open(source,"rb") as file:
                while data:=await file_call(file.read,DATA):
                    await self.request(6,string(handle)+U64.pack(total)+string(data)); total+=len(data)
            durable="fsync@openssh.com" in self.extensions
            if durable: await self.request(200,string("fsync@openssh.com")+string(handle))
            await self.close(handle); handle=None
            commit_started=True
            await self.rename(temporary,str(destination),overwrite=overwrite); committed=True
            return TransferResult(total,str(destination),durable)
        except asyncio.CancelledError: raise
        except Exception as exc:
            known_failure=isinstance(exc,(SFTPFailure,FileNotFoundError,PermissionError,UnsupportedOperation))
            raise TransferFailed(str(exc),committed=None if commit_started and not known_failure else committed,temporary=temporary) from exc
        finally:
            if handle:
                with contextlib.suppress(Exception): await self.close(handle)
            if not committed:
                with contextlib.suppress(Exception): await self.remove(temporary)

    async def get(self, source, destination, *, overwrite=False):
        destination=Path(destination)
        temporary=destination.with_name(destination.name+".snakehole-"+secrets.token_hex(8))
        handle=None; total=0; committed=False; commit_started=False
        try:
            handle=await self.open(str(source),1)
            fd=os.open(temporary,os.O_CREAT|os.O_EXCL|os.O_WRONLY|getattr(os,"O_BINARY",0),0o600)
            with os.fdopen(fd,"wb") as file:
                while True:
                    kind,r=await self.request(5,string(handle)+U64.pack(total)+uint(DATA))
                    if kind==1: break
                    if kind!=103: raise ProtocolViolation("Expected SFTP data")
                    data=r.string(DATA); r.done()
                    if not data: raise ProtocolViolation("Empty SFTP data without EOF")
                    await file_call(file.write,data); total+=len(data)
                await file_call(file.flush); await file_call(os.fsync,file.fileno())
            await self.close(handle); handle=None
            commit_started=True
            await file_call(commit,temporary,destination,overwrite); committed=True
            return TransferResult(total,str(destination),True)
        except asyncio.CancelledError: raise
        except Exception as exc: raise TransferFailed(str(exc),committed=None if commit_started and not isinstance(exc,FileExistsError) else committed,temporary=str(temporary)) from exc
        finally:
            if handle:
                with contextlib.suppress(Exception): await self.close(handle)
            if not committed:
                with contextlib.suppress(OSError): temporary.unlink()

    async def aclose(self):
        if self.channel: await self.channel.aclose()
