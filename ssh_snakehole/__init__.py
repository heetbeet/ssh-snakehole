"""Temporary SSH access over an outbound relay, using Python and source-only deps."""
from .host import Host, RelayConfig, CloseReason, open_host
from .client import (Session, RemoteProcess, CommandResult, CommandExit, CloseReceipt,
                     connect, pair)
from .ticket import Ticket, HostInfo
from .sftp import TransferResult
from .process import ExecRequest

__version__ = "0.1.0"
__all__ = ["open_host","connect","pair","Host","Session","Ticket","HostInfo","RelayConfig",
           "RemoteProcess","CommandResult","CommandExit","CloseReceipt","CloseReason","TransferResult","ExecRequest"]
