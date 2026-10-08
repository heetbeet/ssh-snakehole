"""Real SSH PTYs, interactive programs, state, signals and channel lifetime."""

import asyncio
import base64
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ssh_snakehole import RelayConfig, connect, open_host
from ssh_snakehole.platform import elevated
from ssh_snakehole.relay import Relay

ANSI = re.compile(rb"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")


class Output:
    def __init__(self, reader):
        self.reader = reader
        self.pending = bytearray()
        self.all = bytearray()

    async def until(self, marker):
        try:
            async with asyncio.timeout(20):
                while marker not in ANSI.sub(b"", self.pending):
                    data = await self.reader.read(32768)
                    if not data:
                        raise AssertionError(
                            f"Terminal ended before {marker!r}: {bytes(self.pending)!r}"
                        )
                    self.pending.extend(data)
                    self.all.extend(data)
        except TimeoutError:
            raise AssertionError(
                f"Missing {marker!r}: {bytes(self.pending)!r}"
            ) from None
        result = ANSI.sub(b"", self.pending)
        end = result.index(marker) + len(marker)
        self.pending = bytearray(result[end:])
        return result[:end]


class LocalTTY:
    """Exercise the installed CLI with an actual local console on either OS."""

    def __init__(self, argv, environment, *, emulate=True):
        self.size = [100, 30]
        self.keys = {"left": "\x1b[D", "end": "\x1b[F"}
        self.emulator = (
            subprocess.Popen(
                ["node", str(Path(__file__).with_name("terminal_emulator.cjs"))],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
            )
            if emulate
            else None
        )
        if sys.platform == "win32":
            from winpty import PTY, Backend

            self.pty = PTY(100, 30, backend=Backend.ConPTY)
            self.pty.spawn(
                argv[0],
                " " + subprocess.list2cmdline(argv[1:]),
                env="\0".join(f"{k}={v}" for k, v in environment.items()) + "\0",
            )
        else:
            import termios

            self.master, slave = os.openpty()
            termios.tcsetwinsize(slave, (30, 100))
            try:
                self.process = subprocess.Popen(
                    argv,
                    env=environment,
                    stdin=slave,
                    stdout=slave,
                    stderr=slave,
                    start_new_session=True,
                )
            finally:
                os.close(slave)
            os.set_blocking(self.master, False)

    async def send(self, data):
        if sys.platform == "win32":
            self.pty.write(data.decode())
        else:
            os.write(self.master, data)

    async def key(self, key):
        await self.send(self.keys[key].encode())

    def resize(self, width, height):
        self.size = [width, height]
        if sys.platform == "win32":
            self.pty.set_size(width, height)
        else:
            import termios

            termios.tcsetwinsize(self.master, (height, width))

    def alive(self):
        return (
            self.pty.isalive()
            if sys.platform == "win32"
            else self.process.poll() is None
        )

    async def read(self, count):
        while True:
            if sys.platform == "win32":
                data = self.pty.read().encode()
            else:
                try:
                    data = os.read(self.master, count)
                except BlockingIOError:
                    data = b""
                except OSError:
                    return b""
            if data:
                # Real TUIs query cursor position. A fixed fake reply corrupts
                # the new Python REPL's cursor calculations and editing.
                if not self.emulator:
                    return data
                self.emulator.stdin.write(
                    json.dumps(
                        {"data": base64.b64encode(data).decode(), "resize": self.size}
                    ).encode()
                    + b"\n"
                )
                self.emulator.stdin.flush()
                state = json.loads(self.emulator.stdout.readline())
                self.keys = state["keys"]
                if state["replies"]:
                    await self.send(state["replies"].encode())
                return data
            if not self.alive():
                return b""
            await asyncio.sleep(0.01)

    async def wait(self):
        async with asyncio.timeout(20):
            while self.alive():
                await asyncio.sleep(0.02)
        return (
            self.pty.get_exitstatus()
            if sys.platform == "win32"
            else self.process.returncode
        )

    def close(self):
        if self.emulator:
            self.emulator.stdin.close()
            self.emulator.wait(timeout=5)
            self.emulator.stdout.close()
        if sys.platform == "win32":
            # Own only this test process. Never signal PID 0 on Windows.
            import ctypes as c
            from ctypes import wintypes as w

            kernel = c.WinDLL("kernel32", use_last_error=True)
            kernel.TerminateProcess.argtypes = [w.HANDLE, w.UINT]
            if self.pty.isalive():
                kernel.TerminateProcess(self.pty.fd, 1)
            self.pty.cancel_io()
        else:
            if self.process.poll() is None:
                self.process.kill()
            self.process.wait(timeout=5)
            os.close(self.master)


@unittest.skipIf(elevated(), "Host requires a non-admin account")
class Terminal(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.relay = await Relay().start()
        self.config = RelayConfig(
            f"ws://127.0.0.1:{self.relay.mailbox_port}/v1",
            f"tcp://127.0.0.1:{self.relay.transit_port}",
            stun=None,
        )

    async def asyncTearDown(self):
        await self.relay.aclose()

    async def test_explicit_lifetime_ends_terminal_with_a_clear_error(self):
        from ssh_snakehole.errors import SessionExpired

        async with open_host(relay=self.config, lifetime=1.5) as host:
            async with connect(host.code, relay=self.config) as session:
                with self.assertRaisesRegex(SessionExpired, "Host lifetime expired"):
                    async with session.terminal():
                        await asyncio.sleep(10)
                await asyncio.wait_for(host.wait_closed(), 3)

    async def test_split_utf8_and_legacy_bytes(self):
        import shlex

        text = "é 汉 🐍 e\u0301"
        script = "import sys; print('READY',flush=True); data=sys.stdin.buffer.readline().rstrip(b'\\r\\n'); print('GOT-'+data.hex(),flush=True)"
        command = (
            f"& '{sys.executable}' -c '{script.replace(chr(39), chr(39) * 2)}'"
            if sys.platform == "win32"
            else shlex.join([sys.executable, "-c", script])
        )
        async with open_host(relay=self.config) as host:
            async with connect(host.code, relay=self.config) as session:
                async with session.terminal(command) as process:
                    out = Output(process.stdout)
                    await out.until(b"READY")
                    for byte in text.encode("utf-8") + b"\r":
                        await process.send(bytes([byte]))
                        await asyncio.sleep(0.01)
                    await out.until(("GOT-" + text.encode().hex()).encode())
                    await process.stdout.read()
                    self.assertEqual((await process.wait()).exit_code, 0)
                # Exec is binary on every platform; encoding belongs to callers.
                data = b"latin1:\xe9 utf8:\xc3\xa9\0\xff"
                result = await session.run_argv(
                    [
                        sys.executable,
                        "-c",
                        "import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())",
                    ],
                    stdin=data,
                )
                self.assertEqual(result.stdout, data)
                if sys.platform != "win32":
                    script = "import os,tty; tty.setraw(0); os.write(1,b'READY'); os.write(1,os.read(0,1))"
                    async with session.terminal(
                        shlex.join([sys.executable, "-c", script])
                    ) as process:
                        out = Output(process.stdout)
                        await out.until(b"READY")
                        await process.send(b"\xe9")
                        self.assertEqual(await process.stdout.read(), b"\xe9")
                        self.assertEqual((await process.wait()).exit_code, 0)
                else:
                    async with session.terminal(
                        f"& '{sys.executable}' -i -q"
                    ) as process:
                        out = Output(process.stdout)
                        await out.until(b">>> ")
                        await process.send(b"\xff")
                        stderr = await process.stderr.read()
                        await process.stdout.read()
                        self.assertNotEqual((await process.wait()).exit_code, 0)
                        self.assertIn(b"Windows terminal input requires UTF-8", stderr)
                await session.close_host()

    async def test_python_repl_resize_unicode_colors_and_ctrl_c(self):
        command = (
            f"& '{sys.executable}' -i -q; exit $LASTEXITCODE"
            if sys.platform == "win32"
            else f"'{sys.executable}' -i -q"
        )
        async with open_host(relay=self.config, idle_timeout=1.5) as host:
            async with connect(host.code, relay=self.config) as session:
                async with session.terminal(size=(88, 25)) as process:
                    out = Output(process.stdout)
                    if sys.platform == "win32":
                        await out.until(b"> ")
                        await process.send(
                            b"Remove-Module PSReadLine -ErrorAction SilentlyContinue\r"
                        )
                        await out.until(b"> ")
                        await process.send(f"& '{sys.executable}' -i -q\r".encode())
                    else:
                        await process.send(("exec " + command + "\r").encode())
                    await out.until(b">>> ")
                    await process.send(
                        b"import os,sys; x=41; print('TTY'+str(sys.stdin.isatty()))\r"
                    )
                    await out.until(b"TTYTrue")
                    await out.until(b">>> ")
                    await process.send(b"print('VALUE'+str(x+1))\r")
                    await out.until(b"VALUE42")
                    await out.until(b">>> ")
                    process.resize(104, 37)
                    await process.send(
                        b"print('SIZE'+str(tuple(os.get_terminal_size())))\r"
                    )
                    await out.until(b"SIZE(104, 37)")
                    await out.until(b">>> ")
                    await process.send(
                        b"print(chr(27)+'[31m'+chr(233)+chr(27)+'[0m')\r"
                    )
                    await out.until("é".encode())
                    await out.until(b">>> ")
                    self.assertRegex(bytes(out.all), rb"\x1b\[[0-9;]*31m")
                    await process.send(b"import time; time.sleep(60)\r")
                    await asyncio.sleep(1.8)
                    self.assertFalse(host.closed.is_set())
                    await process.send(b"\x03")
                    await out.until(b"KeyboardInterrupt")
                    await out.until(b">>> ")
                    await process.send(b"exit(7)\r")
                    if sys.platform == "win32":
                        await out.until(b"> ")
                        await process.send(b"exit $LASTEXITCODE\r")
                    await process.stdout.read()
                    self.assertEqual((await process.wait()).exit_code, 7)
                self.assertFalse(host.closed.is_set())
                await asyncio.wait_for(host.wait_closed(), 4)
                self.assertEqual(host.idle.active, 0)

    async def test_shell_preserves_state_and_exit_allows_reconnection(self):
        with tempfile.TemporaryDirectory() as directory:
            async with open_host(relay=self.config) as host:
                async with connect(host.code, relay=self.config) as session:
                    ticket = session.ticket
                    async with session.terminal() as process:
                        out = Output(process.stdout)
                        if sys.platform == "win32":
                            await out.until(b"> ")
                            # Keep this pipeline test independent of local PSReadLine profiles.
                            await process.send(
                                b"Remove-Module PSReadLine -ErrorAction SilentlyContinue\r"
                            )
                            await out.until(b"> ")
                            command = f"Set-Location '{directory}'; $x=41; Write-Output ('STATE'+($x+1))\r"
                            await process.send(command.encode())
                            self.assertIn(b"STATE42", await out.until(b"> "))
                            await process.send(
                                b"Write-Output ('CWD'+(Get-Location).Path)\r"
                            )
                            self.assertIn(
                                ("CWD" + directory).encode(), await out.until(b"> ")
                            )
                        else:
                            # No dependence on shell prompt wording or colors.
                            await process.send(
                                f"cd '{directory}'; x=41; printf 'STATE%s\\n' $((x+1))\n".encode()
                            )
                            self.assertIn(b"STATE42", await out.until(b"STATE42\r\n"))
                            await process.send(b"printf 'CWD%s\\n' \"$PWD\"\n")
                            self.assertIn(
                                ("CWD" + directory).encode(),
                                await out.until(("CWD" + directory + "\r\n").encode()),
                            )
                        await process.send(b"exit\r")
                        await process.stdout.read()
                        self.assertEqual((await process.wait()).exit_code, 0)
                self.assertFalse(host.closed.is_set())
                async with connect(ticket, relay=self.config) as recovered:
                    self.assertEqual(
                        (
                            await recovered.run_argv(
                                [sys.executable, "-c", "print('resume')"]
                            )
                        ).stdout.strip(),
                        b"resume",
                    )
                    await recovered.close_host()

    async def test_disconnected_pty_stops_ordinary_foreground_child(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "heartbeat"
            script = f"import pathlib,time; p=pathlib.Path({str(marker)!r}); exec('while True:\\n p.write_text(str(time.monotonic()))\\n time.sleep(.05)')"
            import shlex

            command = (
                "& '" + sys.executable + "' -c '" + script.replace("'", "''") + "'"
                if sys.platform == "win32"
                else shlex.join([sys.executable, "-c", script])
            )
            async with open_host(relay=self.config) as host:
                async with connect(host.code, relay=self.config) as session:
                    async with session.terminal(command):
                        async with asyncio.timeout(20):
                            while not marker.exists():
                                await asyncio.sleep(0.05)
                    await asyncio.sleep(0.4)
                    first = marker.read_text()
                    await asyncio.sleep(0.3)
                    self.assertEqual(marker.read_text(), first)
                    await session.close_host()

    async def test_crashed_host_stops_pty_child_after_ctrl_c(self):
        import shlex

        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "heartbeat"
            script = f"import pathlib,time,signal; signal.signal(signal.SIGINT,signal.SIG_IGN); p=pathlib.Path({str(marker)!r}); exec('while True:\\n p.write_text(str(time.monotonic()))\\n time.sleep(.05)')"
            command = (
                "& '" + sys.executable + "' -c '" + script.replace("'", "''") + "'"
                if sys.platform == "win32"
                else "exec " + shlex.join([sys.executable, "-c", script])
            )
            host = await asyncio.create_subprocess_exec(
                sys.executable,
                "-I",
                "-m",
                "ssh_snakehole",
                "--mailbox",
                self.config.mailbox,
                "--relay",
                self.config.transit,
                "--stun",
                "none",
                "open",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                async with asyncio.timeout(20):
                    code = (await host.stdout.readline()).strip().decode()
                async with connect(code, relay=self.config) as session:
                    async with session.terminal(command) as process:
                        async with asyncio.timeout(20):
                            while not marker.exists():
                                await asyncio.sleep(0.05)
                        await process.send(b"\x03")
                        await asyncio.sleep(0.2)
                        before = marker.read_text()
                        await asyncio.sleep(0.2)
                        self.assertNotEqual(marker.read_text(), before)
                        host.kill()
                        await host.wait()
                    await asyncio.sleep(0.4)
                    after = marker.read_text()
                    await asyncio.sleep(0.3)
                    self.assertEqual(marker.read_text(), after)
            finally:
                if host.returncode is None:
                    host.kill()
                await host.communicate()

    async def test_installed_cli_connect_resume_and_terminal_restoration(self):
        from ssh_snakehole import vault

        with tempfile.TemporaryDirectory() as directory:
            environment = dict(
                os.environ,
                LOCALAPPDATA=directory,
                HOME=directory,
                XDG_STATE_HOME=directory,
            )
            argv = [
                sys.executable,
                "-I",
                "-m",
                "ssh_snakehole",
                "--mailbox",
                self.config.mailbox,
                "--relay",
                self.config.transit,
                "--stun",
                "none",
            ]
            async with open_host(relay=self.config) as host:

                async def terminal(action, credential, *, remote_close=False):
                    # Run two sessions in one console to verify mode restoration.
                    wrapper = (
                        "import asyncio,sys; from ssh_snakehole.cli import parser,run; "
                    )
                    if sys.platform == "win32":
                        wrapper += "import ctypes,msvcrt; from ctypes import wintypes as w; k=ctypes.WinDLL('kernel32'); k.GetConsoleMode.argtypes=[w.HANDLE,ctypes.POINTER(w.DWORD)]; h=msvcrt.get_osfhandle(0); m=w.DWORD(); k.GetConsoleMode(h,ctypes.byref(m)); old=m.value; "
                        check = (
                            "k.GetConsoleMode(h,ctypes.byref(m)); assert m.value==old; "
                        )
                    else:
                        wrapper += "import termios,os; old=termios.tcgetattr(0); blocking=os.get_blocking(0); "
                        # macOS sets PENDIN as input arrives. It is kernel state,
                        # not a terminal mode which a client can restore.
                        check = "new=termios.tcgetattr(0); old[3]&=~getattr(termios,'PENDIN',0); new[3]&=~getattr(termios,'PENDIN',0); assert new==old, (old,new); assert os.get_blocking(0)==blocking; "
                    arguments = argv[4:] + (
                        ["connect", credential]
                        if action == "connect"
                        else ["resume", "--token", credential]
                    )
                    wrapper += (
                        "\nfrom ssh_snakehole.errors import SnakeholeError\ntry:\n status=asyncio.run(run(parser().parse_args(sys.argv[1:])))\nexcept SnakeholeError:\n status=1\n"
                        + check
                        + "print('RESTORED'); sys.exit(status)"
                    )
                    tty = LocalTTY(
                        [sys.executable, "-I", "-c", wrapper, *arguments], environment
                    )
                    out = Output(tty)
                    try:
                        initial = await out.until(b"Connected to ")
                        if sys.platform == "win32":
                            await out.until(b"> ")
                            await tty.send(
                                b"Remove-Module PSReadLine -ErrorAction SilentlyContinue\r"
                            )
                            await out.until(b"> ")
                            await tty.send(b"Write-Output ('REAL'+'SHELL')\r")
                        else:
                            await out.until(b"$ ")
                            await tty.send(b"printf 'REAL%s\\n' SHELL\r")
                        await out.until(b"REALSHELL\r\n")
                        await tty.send(
                            (
                                f"& '{sys.executable}' -i -q\r"
                                if sys.platform == "win32"
                                else f"'{sys.executable}' -i -q\r"
                            ).encode()
                        )
                        await out.until(b">>> ")
                        await tty.send(b"print('CLI'+str(6*7))\r")
                        await out.until(b"CLI42")
                        await out.until(b">>> ")
                        # Left arrow and backspace must reach Python's line editor.
                        await tty.send(b"print('EDIT'+str(6*8))")
                        await asyncio.sleep(0.1)
                        await tty.key("left")
                        await tty.key("left")
                        await tty.send(b"\x7f7\r")
                        await out.until(b"EDIT42")
                        await out.until(b">>> ")
                        tty.resize(104, 37)
                        await asyncio.sleep(0.3)
                        await tty.send(
                            b"print('CLI-SIZE'+str(tuple(__import__('os').get_terminal_size())))\r"
                        )
                        await out.until(b"CLI-SIZE(104, 37)")
                        await out.until(b">>> ")
                        if remote_close:
                            await host.aclose()
                        else:
                            await tty.send(b"exit()\r")
                            if sys.platform == "win32":
                                await out.until(b"> ")
                            await tty.send(b"exit\r")
                        await out.until(b"RESTORED")
                        self.assertEqual(await tty.wait(), 1 if remote_close else 0)
                        return initial
                    finally:
                        tty.close()

                output = await terminal("connect", host.code)
                token = re.search(rb"snake1_[A-Za-z0-9_-]{43}", output).group().decode()
                self.assertFalse(host.closed.is_set())
                await terminal("resume", token)
                await terminal("resume", token, remote_close=True)
                state = (
                    Path(directory) / "Library/Application Support"
                    if sys.platform == "darwin"
                    else Path(directory)
                )
                ticket = await vault.load(token, root=state / "ssh-snakehole/tickets")
                self.assertEqual(ticket.info.session_id, host.info.session_id)
                self.assertTrue(host.closed.is_set())

    @unittest.skipIf(sys.platform == "win32", "POSIX exit signals")
    async def test_native_terminal_signal_is_reported(self):
        async with open_host(relay=self.config) as host:
            async with connect(host.code, relay=self.config) as session:
                async with session.terminal("kill -TERM $$") as process:
                    await process.stdout.read()
                    self.assertEqual((await process.wait()).exit_signal, "TERM")
                await session.close_host()
