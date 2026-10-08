"""Foreground assistance and encrypted, token-selected reconnection."""

import argparse
import asyncio
import math
import sys

from . import __version__, vault
from .client import connect, pair
from .console import lines, read_secret
from .errors import SnakeholeError
from .host import RelayConfig, open_host


class Parser(argparse.ArgumentParser):
    def error(self, message):
        # Unknown positional arguments may themselves be secrets.
        self.exit(2, "Invalid arguments. Use --help for the command syntax.\n")


def parser():
    p = Parser(
        prog="python -m ssh_snakehole",
        description="Temporary SSH through outbound relays. CPython 3.11-3.14.",
    )
    p.add_argument("--mailbox", help="Explicit mailbox WebSocket URL")
    p.add_argument("--relay", help="Explicit Transit relay URL")
    sub = p.add_subparsers(dest="action", required=True)
    host = sub.add_parser(
        "open", help="Print a one-use code and host until revoked or inactive"
    )
    host.add_argument("--admin", action="store_true")
    host.add_argument(
        "--lifetime",
        type=float,
        help="Optional hard lifetime in seconds, including active work",
    )
    join = sub.add_parser(
        "connect", help="Pair using hidden code input and open a command prompt"
    )
    join.add_argument(
        "--code-stdin", action="store_true", help="Read CODE from one stdin line"
    )
    join.add_argument(
        "--detach",
        action="store_true",
        help="Print only the new token on stdout, then disconnect",
    )
    for action in (
        "resume",
        "exec",
        "put",
        "get",
        "close",
        "forget",
        "status",
        "keepalive",
        "export-ssh",
    ):
        item = sub.add_parser(action)
        item.add_argument(
            "--token-stdin",
            action="store_true",
            help="Read the reconnection token from one stdin line",
        )
        if action == "exec":
            item.add_argument("command")
            item.add_argument(
                "--timeout", type=float, help="Optional command timeout in seconds"
            )
        elif action in ("put", "get"):
            item.add_argument("source")
            item.add_argument("destination")
            item.add_argument("--overwrite", action="store_true")
        elif action == "keepalive":
            item.add_argument(
                "--interval",
                type=float,
                help="Send renewals every N seconds until this process ends",
            )
        elif action == "export-ssh":
            item.add_argument("directory")
    proxy = sub.add_parser("proxy", help="Native SSH route adapter")
    proxy.add_argument("route")
    sub.add_parser("version")
    return p


def config(args):
    if args.mailbox or args.relay:
        defaults = RelayConfig()
        return RelayConfig(
            args.mailbox or defaults.mailbox, args.relay or defaults.transit
        )
    return None


def require_console():
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise ValueError(
            "Interactive mode requires a terminal; agents can use connect --code-stdin --detach or the Python API"
        )


def output(data, stream):
    stream.buffer.write(data)
    stream.buffer.flush()


async def execute(session, command, timeout=None):
    async with session.exec(command, timeout=timeout) as process:
        await process.close_stdin()

        async def copy(reader, stream):
            while data := await reader.read(32768):
                output(data, stream)

        tasks = [
            asyncio.create_task(copy(process.stdout, sys.stdout)),
            asyncio.create_task(copy(process.stderr, sys.stderr)),
        ]
        try:
            await asyncio.gather(*tasks)
            result = await process.wait()
            return result.exit_code if result.exit_code is not None else 128
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)


async def interactive(session):
    source = lines()
    disconnected = asyncio.create_task(session.connection.wait_closed())
    pending = None
    try:
        while True:
            print("snakehole> ", end="", flush=True)
            pending = asyncio.create_task(anext(source))
            done, _ = await asyncio.wait(
                (pending, disconnected), return_when=asyncio.FIRST_COMPLETED
            )
            if disconnected in done:
                print(
                    "\nConnection ended. Use your reconnection token if access is still open."
                )
                return False
            try:
                command = pending.result().strip()
            except StopAsyncIteration:
                return False
            if command == "exit":
                return False
            if command == "close":
                await session.close_host()
                print("Access closed.")
                return True
            if command == "keepalive":
                await session.keepalive()
                print("Access renewed.")
            elif command:
                status = await execute(session, command)
                if status:
                    print(f"Exit status {status}.", file=sys.stderr)
    finally:
        if pending is not None:
            pending.cancel()
        disconnected.cancel()
        await asyncio.gather(
            *(task for task in (pending, disconnected) if task is not None),
            return_exceptions=True,
        )
        await source.aclose()


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
                f"Access as {host.info.process_user} ({host.info.privilege}); Ctrl+C revokes access. Access expires after 30 minutes of inactivity.",
                file=sys.stderr,
            )
            await host.wait_closed()
            if host.error:
                raise host.error
        return 0
    if args.action == "proxy":
        from .native import proxy

        await proxy(args.route)
        return 0
    if args.action == "connect":
        if not args.detach:
            require_console()
        code = read_secret("Code: ", args.code_stdin)
        try:
            ticket = await pair(code, relay=config(args))
        finally:
            code = None
        async with connect(ticket, relay=config(args)) as session:
            token = await vault.save(ticket)
            if args.detach:
                print(token, flush=True)
            else:
                print(
                    f"Connected to {session.info.host_name} as {session.info.process_user}.\n\nReconnection token: {token}\nKeep this private if you want to reconnect later. It unlocks the saved credentials here.\n\nAccess expires after 30 minutes of inactivity.\nType close to revoke access; exit disconnects this client."
                )
                if await interactive(session):
                    vault.resolve(token).unlink(missing_ok=True)
        return 0
    if args.action == "resume":
        require_console()
    if args.action == "keepalive" and args.interval is not None:
        if not math.isfinite(args.interval) or not 0 < args.interval < 1800:
            raise ValueError("Keepalive interval must be between 0 and 1800 seconds")
    token = read_secret("Reconnection token: ", args.token_stdin, 50)
    if args.action == "forget":
        vault.resolve(token).unlink()
        return 0
    ticket = await vault.load(token)
    if args.action == "status":
        ticket.check_live()
        print(ticket.info)
        return 0
    if args.action == "export-ssh":
        from .native import export

        print(export(ticket, args.directory, token))
        return 0
    async with connect(ticket, relay=config(args)) as session:
        if args.action == "resume":
            print(
                f"Connected to {session.info.host_name} as {session.info.process_user}.\nAccess expires after 30 minutes of inactivity.\nType close to revoke access; exit disconnects this client."
            )
            if await interactive(session):
                vault.resolve(token).unlink(missing_ok=True)
        elif args.action == "exec":
            return await execute(session, args.command, args.timeout)
        elif args.action in ("put", "get"):
            result = await getattr(session, args.action)(
                args.source, args.destination, overwrite=args.overwrite
            )
            print(f"{result.bytes_copied} bytes to {result.destination}")
        elif args.action == "keepalive":
            while True:
                await session.keepalive()
                print("Access renewed.", flush=True)
                if args.interval is None:
                    break
                if args.interval >= ticket.info.idle_timeout:
                    raise ValueError(
                        "Keepalive interval must be shorter than the host inactivity timeout"
                    )
                await asyncio.sleep(args.interval)
        elif args.action == "close":
            await session.close_host()
            vault.resolve(token).unlink(missing_ok=True)
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
