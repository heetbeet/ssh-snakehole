"""Encrypted local tickets unlocked by independent random reconnection tokens."""

import base64
import hashlib
import os
import re
import secrets
import sys
from pathlib import Path

from .aio import open_regular
from .crypto import hkdf, seal, unseal
from .errors import VaultUnlockFailed
from .platform import private_file
from .ticket import Ticket
from .wire import b64, json_bytes, parse_json, unb64


def directory():
    if os.name == "nt":
        root = Path(os.environ["LOCALAPPDATA"])
    elif sys.platform == "darwin":
        root = Path.home() / "Library/Application Support"
    else:
        root = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state"))
    if not root.is_absolute():
        raise ValueError("Ticket state root must be an absolute path")
    return root / "ssh-snakehole" / "tickets"


def secret(token):
    if not isinstance(token, str) or not re.fullmatch(
        r"snake1_[A-Za-z0-9_-]{43}", token
    ):
        raise ValueError("Invalid reconnection token")
    raw = base64.b64decode(token[7:] + "=", altchars=b"-_", validate=True)
    if (
        len(raw) != 32
        or base64.urlsafe_b64encode(raw).decode().rstrip("=") != token[7:]
    ):
        raise ValueError("Invalid reconnection token")
    return raw


def resolve(token, root=None):
    identifier = hashlib.sha256(
        b"ssh-snakehole/ticket-index/2\0" + secret(token)
    ).hexdigest()
    return (Path(root) if root is not None else directory()) / (identifier + ".json")


async def save(ticket: Ticket, *, root=None) -> str:
    token = "snake1_" + secrets.token_urlsafe(32)
    path = resolve(token, root)
    created = not path.parent.exists()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise ValueError("Ticket state directory cannot be a symbolic link")
    if root is None or created:
        private_file(path.parent) if os.name == "nt" else path.parent.chmod(0o700)
    key = hkdf(secret(token), b"ssh-snakehole/ticket-encryption/2")
    data = json_bytes(
        {"schema": "ssh-snakehole/vault/2", "box": b64(seal(key, ticket.to_bytes()))}
    )
    temporary = path.with_name(path.name + "." + secrets.token_hex(8))
    fd: int | None = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        private_file(temporary)
        assert fd is not None
        with os.fdopen(fd, "wb") as file:
            fd = None
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
    finally:
        if fd is not None:
            os.close(fd)
        temporary.unlink(missing_ok=True)
    return token


async def load(token: str, *, root=None) -> Ticket:
    try:
        path = resolve(token, root)
        if path.is_symlink():
            raise ValueError("Symbolic ticket file")
        with open_regular(path) as file:
            value = parse_json(file.read(32769), 32768)
        if (
            set(value) != {"schema", "box"}
            or value["schema"] != "ssh-snakehole/vault/2"
        ):
            raise ValueError()
        key = hkdf(secret(token), b"ssh-snakehole/ticket-encryption/2")
        return Ticket.from_bytes(unseal(key, unb64(value["box"])))
    except Exception as exc:
        raise VaultUnlockFailed("Saved credentials could not be unlocked") from exc
