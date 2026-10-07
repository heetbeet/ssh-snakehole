"""Temporary SSH access through established Python SSH and crypto packages."""

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

__version__ = "0.2.1"
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
