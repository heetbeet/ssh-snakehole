"""Optional native SSH adapter. The core library never launches an SSH program."""
import asyncio
import base64
import contextlib
import os
import secrets
import shlex
import sys
from pathlib import Path

from ._crypto import public_key
from .platform import private_file
from .ssh import key_blob
from .transit import dial
from .wire import uint,string,unb64


def private_key(seed):
    check=secrets.randbits(32)
    private=uint(check)+uint(check)+string(b"ssh-ed25519")+string(public_key(seed))+string(seed+public_key(seed))+string(b"")
    private+=bytes(range(1,(-len(private))%8+1))
    data=b"openssh-key-v1\0"+string(b"none")+string(b"none")+string(b"")+uint(1)+string(key_blob(seed))+string(private)
    body=base64.b64encode(data).decode("ascii")
    return "-----BEGIN OPENSSH PRIVATE KEY-----\n"+"\n".join(body[i:i+70] for i in range(0,len(body),70))+"\n-----END OPENSSH PRIVATE KEY-----\n"


def export(ticket,directory,ticket_path):
    """Export is explicit: it writes an unencrypted native key to protected files."""
    ticket.check_live(); root=Path(directory).resolve(); root.mkdir(parents=True,exist_ok=True,mode=0o700)
    if os.name=="nt": private_file(root)
    identifier="snakehole-"+ticket.info.session_id
    for name,data in (("key",private_key(ticket.client_seed)),("known_hosts",identifier+" "+ticket.offer["host_key"]+"\n")):
        path=root/name
        fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        try:
            private_file(path)
            with os.fdopen(fd,"w",encoding="utf-8",newline="\n") as file: fd=None; file.write(data)
        finally:
            if fd is not None: os.close(fd)
    entry=str(Path(__file__).resolve().parent.parent)
    # OpenSSH tokenization, followed by its local shell. Use double quotes on Windows.
    quote=(lambda value:'"'+str(value).replace("\\","/").replace('"','\\"')+'"') if os.name=="nt" else lambda value:shlex.quote(str(value))
    proxy=f"{quote(sys.executable)} {quote(entry)} proxy {quote(Path(ticket_path).resolve())}" if Path(entry).is_file() else f"{quote(sys.executable)} -m ssh_snakehole proxy {quote(Path(ticket_path).resolve())}"
    text=f'Host {identifier}\n    HostName {identifier}\n    User help\n    IdentityFile "{(root/"key").as_posix()}"\n    UserKnownHostsFile "{(root/"known_hosts").as_posix()}"\n    StrictHostKeyChecking yes\n    IdentitiesOnly yes\n    ProxyCommand {proxy}\n    RequestTTY no\n'
    path=root/"config"
    with path.open("x",encoding="utf-8") as file: file.write(text)
    private_file(path)
    return f'ssh -F "{path}" {identifier} "COMMAND"; delete {root} after use'


async def proxy(ticket):
    ticket.check_live()
    if os.name=="nt":
        import msvcrt
        msvcrt.setmode(0,os.O_BINARY); msvcrt.setmode(1,os.O_BINARY)
    async with asyncio.timeout(40):
        reader,writer=await dial(unb64(ticket.offer["transit_key"],32),ticket.offer["operator_side"],relay=ticket.offer["relay"])
    async def upstream():
        if os.name=="nt":
            import ctypes as c
            import msvcrt
            from ctypes import wintypes as w
            kernel=c.WinDLL("kernel32",use_last_error=True)
            kernel.PeekNamedPipe.argtypes=[w.HANDLE,c.c_void_p,w.DWORD,c.c_void_p,c.POINTER(w.DWORD),c.c_void_p]
            handle=msvcrt.get_osfhandle(0)
            while True:
                available=w.DWORD()
                if not kernel.PeekNamedPipe(handle,None,0,None,c.byref(available),None):
                    if c.get_last_error()==109: break
                    raise c.WinError(c.get_last_error())
                if not available.value: await asyncio.sleep(0.01); continue
                data=os.read(0,min(available.value,32768))
                if not data: break
                writer.write(data); await writer.drain()
        else:
            pipe=asyncio.StreamReader(limit=65536)
            transport,_=await asyncio.get_running_loop().connect_read_pipe(lambda:asyncio.StreamReaderProtocol(pipe),sys.stdin.buffer)
            try:
                while data:=await pipe.read(32768): writer.write(data); await writer.drain()
            finally: transport.close()
        with contextlib.suppress(Exception): writer.write_eof()
    async def downstream():
        while data:=await reader.read(32768):
            view=memoryview(data)
            while view:
                count=await asyncio.to_thread(os.write,1,view); view=view[count:]
    tasks=[asyncio.create_task(upstream()),asyncio.create_task(downstream())]
    try:
        done,_=await asyncio.wait(tasks,return_when=asyncio.FIRST_COMPLETED)
        for task in done: await task
    finally:
        for task in tasks: task.cancel()
        writer.close()
        await writer.wait_closed()
