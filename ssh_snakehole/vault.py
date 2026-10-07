"""Optional encrypted ticket files. Importing the library never creates a vault."""
import asyncio
import hashlib
import os
import secrets
import sys
from pathlib import Path

from ._crypto import seal, unseal
from .errors import VaultUnlockFailed
from .platform import private_file
from .ticket import Ticket
from .wire import b64, unb64, json_bytes, parse_json


def directory():
    if os.name=="nt": root=Path(os.environ["LOCALAPPDATA"])
    elif sys.platform=="darwin": root=Path.home()/"Library/Application Support"
    else: root=Path(os.environ.get("XDG_STATE_HOME",Path.home()/".local/state"))
    if not root.is_absolute(): raise ValueError("Ticket state root must be an absolute path")
    return root/"ssh-snakehole"/"tickets"


def derive(passphrase,salt):
    return hashlib.scrypt(passphrase.encode("utf-8"),salt=salt,n=32768,r=8,p=1,dklen=32,maxmem=64*1024*1024)


async def save(ticket,passphrase,path=None):
    if len(passphrase)<12: raise ValueError("Use a vault passphrase of at least 12 characters")
    default=path is None
    path=Path(path) if path is not None else directory()/(ticket.info.session_id+".json")
    created=not path.parent.exists()
    path.parent.mkdir(parents=True,exist_ok=True)
    # Restrict owned/new state, without changing a caller's existing directory ACL.
    if default or created:
        if path.parent.is_symlink(): raise ValueError("Ticket state directory cannot be a symbolic link")
        if os.name=="nt": private_file(path.parent)
        else: path.parent.chmod(0o700)
    salt=secrets.token_bytes(16)
    key=await asyncio.to_thread(derive,passphrase,salt)
    data=json_bytes({"schema":"ssh-snakehole/vault/1","scrypt":{"n":32768,"r":8,"p":1},"salt":b64(salt),"box":b64(seal(key,ticket.to_bytes()))})
    temporary=path.with_name(path.name+"."+secrets.token_hex(8))
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try:
        private_file(temporary)
        with os.fdopen(fd,"wb") as file:
            fd=None; file.write(data); file.flush(); os.fsync(file.fileno())
        os.replace(temporary,path)
    finally:
        if fd is not None: os.close(fd)
        temporary.unlink(missing_ok=True)
    return path


async def load(path,passphrase):
    try:
        with open(path,"rb") as file: data=file.read(32769)
        value=parse_json(data,32768)
        if set(value)!={"schema","scrypt","salt","box"} or value["schema"]!="ssh-snakehole/vault/1" or value["scrypt"]!={"n":32768,"r":8,"p":1} or any(type(x)!=int for x in value["scrypt"].values()): raise ValueError()
        salt=unb64(value["salt"],16); encrypted=unb64(value["box"])
        key=await asyncio.to_thread(derive,passphrase,salt)
        return Ticket.from_bytes(unseal(key,encrypted))
    except Exception as exc: raise VaultUnlockFailed("Ticket could not be unlocked") from exc


def resolve(value):
    candidate=Path(value)
    if candidate.is_file(): return candidate
    import re
    if not re.fullmatch(r"[0-9a-f]{32}",value): raise ValueError("Expected a ticket ID or a ticket file")
    return directory()/(value+".json")
