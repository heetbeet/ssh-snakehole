"""Foreground assistance and encrypted, token-selected reconnection."""

import argparse
import asyncio
import math
import os
import sys

from . import __version__, vault
from .client import connect, pair
from .console import chunks, raw_terminal, read_secret
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
    p.add_argument("--stun", help="STUN URL; none uses local ICE candidates only")
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
    for action, help_text in (
        ("connect", "Pair using CODE and open the remote shell"),
        ("pair", "Exchange CODE for a reconnection token; print only the token"),
    ):
        join = sub.add_parser(action, help=help_text)
        join.add_argument(
            "code", nargs="?", metavar="CODE", help="One-use invitation code"
        )
        join.add_argument(
            "--code-stdin", action="store_true", help="Read CODE from one stdin line"
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
        credentials = item.add_mutually_exclusive_group()
        credentials.add_argument(
            "--token", metavar="TOKEN", help="Local reconnection token"
        )
        credentials.add_argument(
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
    if args.mailbox or args.relay or args.stun:
        defaults = RelayConfig()
        return RelayConfig(
            args.mailbox or defaults.mailbox,
            args.relay or defaults.transit,
            None if args.stun == "none" else args.stun or defaults.stun,
        )
    return None


def require_console():
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise ValueError(
            "Interactive mode requires a terminal; agents can use pair CODE, then exec --token TOKEN, or the Python API"
        )


def output(data, stream):
    stream.buffer.write(data)
    stream.buffer.flush()


async def execute(session, command, timeout=None):
    async with session.exec(command, timeout=timeout) as process:

        async def feed():
            if not sys.stdin.isatty():
                async for data in chunks():
                    await process.send(data)
            await process.close_stdin()

        async def copy(reader, stream):
            while data := await reader.read(32768):
                output(data, stream)

        tasks = [
            asyncio.create_task(copy(process.stdout, sys.stdout)),
            asyncio.create_task(copy(process.stderr, sys.stderr)),
        ]
        feeding = asyncio.create_task(feed())
        waiting = asyncio.create_task(process.wait())
        try:
            pending = {feeding, waiting, *tasks}
            while not waiting.done():
                done, pending = await asyncio.wait(
                    pending, return_when=asyncio.FIRST_COMPLETED
                )
                for task in done:
                    await task
            await asyncio.gather(*tasks)
            result = waiting.result()
            return result.exit_code if result.exit_code is not None else 128
        finally:
            for task in (*tasks, feeding, waiting):
                task.cancel()
            await asyncio.gather(*tasks, feeding, waiting, return_exceptions=True)


async def interactive(session):
    size = os.get_terminal_size(sys.stdout.fileno())
    term_type = os.environ.get("TERM") or "xterm-256color"
    async with session.terminal(term_type=term_type, size=tuple(size)) as process:

        async def feed():
            async for data in chunks():
                await process.send(data)
            await process.close_stdin()

        async def copy(reader, stream):
            while data := await reader.read(32768):
                output(data, stream)

        async def resize():
            previous = size
            while True:
                await asyncio.sleep(0.1)
                current = os.get_terminal_size(sys.stdout.fileno())
                if current != previous:
                    process.resize(*current)
                    previous = current

        with raw_terminal():
            tasks = [
                asyncio.create_task(feed()),
                asyncio.create_task(copy(process.stdout, sys.stdout)),
                asyncio.create_task(copy(process.stderr, sys.stderr)),
                asyncio.create_task(resize()),
            ]
            waiting = asyncio.create_task(process.wait())
            try:
                pending = {waiting, *tasks}
                while not waiting.done():
                    done, pending = await asyncio.wait(
                        pending, return_when=asyncio.FIRST_COMPLETED
                    )
                    for task in done:
                        await task
                await asyncio.gather(*tasks[1:3])
                result = waiting.result()
                return result.exit_code if result.exit_code is not None else 128
            finally:
                waiting.cancel()
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, waiting, return_exceptions=True)


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
    if args.action in ("connect", "pair"):
        if args.code is not None and args.code_stdin:
            raise ValueError("Use either CODE or --code-stdin")
        if args.action == "connect":
            require_console()
        code = (
            args.code
            if args.code is not None
            else read_secret("Code: ", args.code_stdin)
        )
        args.code = None
        try:
            ticket = await pair(code, relay=config(args))
        finally:
            code = None
        # Pairing consumes CODE. Preserve accepted credentials even if the first
        # network connection fails, so resume can recover without a new code.
        token = await vault.save(ticket)
        if args.action == "pair":
            print(token, flush=True)
            return 0
        print(
            f"Reconnection token: {token}\nResume later: python -m ssh_snakehole resume --token TOKEN\n",
            flush=True,
        )
        async with connect(ticket, relay=config(args)) as session:
            print(
                f"Connected to {session.info.host_name} as {session.info.process_user} ({session.transport}).\nExit the remote shell to disconnect. Use close --token TOKEN to revoke access.",
                flush=True,
            )
            return await interactive(session)
    if args.action == "resume":
        require_console()
    if args.action == "keepalive" and args.interval is not None:
        if not math.isfinite(args.interval) or not 0 < args.interval < 1800:
            raise ValueError("Keepalive interval must be between 0 and 1800 seconds")
    token = (
        args.token
        if args.token is not None
        else read_secret("Reconnection token: ", args.token_stdin, 50)
    )
    args.token = None
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
                f"Connected to {session.info.host_name} as {session.info.process_user} ({session.transport}).",
                flush=True,
            )
            return await interactive(session)
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
                try:
                    async with asyncio.timeout(args.interval):
                        await session.connection.wait_closed()
                except TimeoutError:
                    continue
                raise SnakeholeError("Connection ended; access renewal stopped")
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
