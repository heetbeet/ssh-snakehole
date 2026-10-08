"""Temporary SSH access through established Python SSH and crypto packages."""

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .client import (
        CloseReceipt,
        CommandExit,
        CommandResult,
        RemoteProcess,
        Session,
        connect,
        pair,
    )
    from .host import CloseReason, Host, RelayConfig, open_host
    from .sftp import TransferResult
    from .ticket import HostInfo, Ticket

__version__ = "0.5.2"
__all__ = [
    "open_host",
    "connect",
    "pair",
    "Host",
    "Session",
    "Ticket",
    "HostInfo",
    "RelayConfig",
    "RemoteProcess",
    "CommandResult",
    "CommandExit",
    "CloseReceipt",
    "CloseReason",
    "TransferResult",
]


def __getattr__(name: str) -> Any:
    # Command workers need containment and JSON, not the SSH/crypto stack.
    modules = {
        "client": (
            "CloseReceipt",
            "CommandExit",
            "CommandResult",
            "RemoteProcess",
            "Session",
            "connect",
            "pair",
        ),
        "host": ("CloseReason", "Host", "RelayConfig", "open_host"),
        "sftp": ("TransferResult",),
        "ticket": ("HostInfo", "Ticket"),
    }
    for module, exports in modules.items():
        if name in exports:
            value = getattr(import_module(f".{module}", __name__), name)
            globals()[name] = value
            return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
