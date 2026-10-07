"""Foreground commands, with opt-in encrypted persistence for operator tickets."""

import argparse
import asyncio
import getpass
import os
import sys

from . import __version__, vault
from .client import connect, pair
from .errors import SnakeholeError
from .host import RelayConfig, open_host


def passphrase(confirm=False):
    value = os.environ.get("SSH_SNAKEHOLE_PASSPHRASE") or getpass.getpass(
        "Ticket passphrase: "
    )
    if (
        confirm
        and "SSH_SNAKEHOLE_PASSPHRASE" not in os.environ
        and value != getpass.getpass("Again: ")
    ):
        raise ValueError("Passphrases differ")
    if confirm and len(value) < 12:
        raise ValueError("Use a vault passphrase of at least 12 characters")
    return value


def parser():
    p = argparse.ArgumentParser(
        prog="python -m ssh_snakehole",
        description="Temporary SSH access through an outbound relay. CPython 3.11-3.14 required.",
    )
    p.add_argument("--mailbox", default=None, help="Explicit mailbox WebSocket URL")
    p.add_argument(
        "--relay", default=None, help="Explicit tcp://host:port Transit relay"
    )
    sub = p.add_subparsers(dest="action", required=True)
    host = sub.add_parser("open", help="Show a code and host until close or Ctrl+C")
    host.add_argument("--admin", action="store_true")
    host.add_argument("--lifetime", type=int, default=7200)
    join = sub.add_parser(
        "connect", help="Pair and save an encrypted reconnection ticket"
    )
    join.add_argument("code")
    execute = sub.add_parser("exec", help="Run one command using a saved ticket")
    execute.add_argument("ticket")
    execute.add_argument("command")
    execute.add_argument("--timeout", type=float, default=300)
    for action in ("put", "get"):
        item = sub.add_parser(action)
        item.add_argument("ticket")
        item.add_argument("source")
        item.add_argument("destination")
        item.add_argument("--overwrite", action="store_true")
    for action in ("close", "forget", "status", "proxy", "export-ssh"):
        item = sub.add_parser(action)
        item.add_argument("ticket")
        if action == "export-ssh":
            item.add_argument("directory")
    sub.add_parser("version")
    return p


def config(args):
    if args.mailbox or args.relay:
        defaults = RelayConfig()
        return RelayConfig(
            args.mailbox or defaults.mailbox, args.relay or defaults.transit
        )
    return None


async def run(args):
    if args.action == "version":
        print(__version__)
        return 0
    if args.action == "open":
        async with open_host(
            lifetime=args.lifetime, admin=args.admin, relay=config(args)
        ) as host:
            print(host.code, flush=True)
            print(
                f"Access as {host.info.process_user} ({host.info.privilege}); Ctrl+C ends access.",
                file=sys.stderr,
            )
            await host.wait_closed()
            if host.error:
                raise host.error
        return 0
    if args.action == "connect":
        password = passphrase(confirm=True)
        ticket = await pair(args.code, relay=config(args))
        await vault.save(ticket, password)
        print(ticket.info.session_id, flush=True)
        async with connect(ticket, relay=config(args)) as session:
            print(
                f"Connected to {session.info.host_name} as {session.info.process_user}. Use the ticket ID for exec, put, get and close.",
                file=sys.stderr,
            )
        return 0
    path = vault.resolve(args.ticket)
    if args.action == "forget":
        path.unlink()
        return 0
    ticket = await vault.load(path, passphrase())
    if args.action == "status":
        ticket.check_live()
        print(ticket.info)
        return 0
    if args.action == "export-ssh":
        from .native import export

        print(export(ticket, args.directory, path))
        return 0
    if args.action == "proxy":
        from .native import proxy

        await proxy(ticket)
        return 0
    async with connect(ticket, relay=config(args)) as session:
        if args.action == "exec":
            result = await session.run(args.command, timeout=args.timeout)
            sys.stdout.buffer.write(result.stdout)
            sys.stdout.buffer.flush()
            sys.stderr.buffer.write(result.stderr)
            sys.stderr.buffer.flush()
            return result.exit_code if result.exit_code is not None else 128
        if args.action in ("put", "get"):
            result = await getattr(session, args.action)(
                args.source, args.destination, overwrite=args.overwrite
            )
            print(f"{result.bytes_copied} bytes to {result.destination}")
            return 0
        if args.action == "close":
            await session.close_host()
            path.unlink(missing_ok=True)
            print("Access closed.")
            return 0


def main():
    if sys.implementation.name != "cpython" or not (3, 11) <= sys.version_info[:2] < (
        3,
        15,
    ):
        raise SystemExit("CPython 3.11-3.14 required")
    try:
        status = asyncio.run(run(parser().parse_args()))
    except KeyboardInterrupt:
        status = 130
    except (SnakeholeError, OSError, ValueError, TimeoutError, EOFError) as exc:
        print(f"ssh-snakehole: {exc}", file=sys.stderr)
        status = 1
    raise SystemExit(status or 0)
