"""Render a real full-screen application through the installed SSH CLI."""

import asyncio
import base64
import contextlib
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

import test_terminal

from ssh_snakehole import open_host
from ssh_snakehole.platform import elevated

LocalTTY = test_terminal.LocalTTY
Output = test_terminal.Output


class Screen:
    def __init__(self, emulator, terminal):
        self.emulator = emulator
        self.terminal = terminal
        self.lock = asyncio.Lock()
        self.changed = asyncio.Event()
        self.state = {"screen": "", "buffer": "normal"}
        self.alternate = False

    async def update(self, request):
        async with self.lock:
            self.emulator.stdin.write(json.dumps(request).encode() + b"\n")
            await self.emulator.stdin.drain()
            reply = await self.emulator.stdout.readline()
            if not reply:
                raise AssertionError("Terminal emulator stopped")
            self.state = json.loads(reply)
            self.terminal.keys = self.state["keys"]
            self.alternate |= self.state["buffer"] == "alternate"
            if self.state["replies"]:
                await self.terminal.send(self.state["replies"].encode())
            self.changed.set()

    async def copy(self):
        while data := await self.terminal.read(32768):
            await self.update({"data": base64.b64encode(data).decode()})

    async def until(self, text):
        try:
            async with asyncio.timeout(30):
                while text not in self.state["screen"]:
                    self.changed.clear()
                    await self.changed.wait()
        except TimeoutError:
            raise AssertionError(f"Missing {text!r}: {self.state!r}") from None


@unittest.skipUnless(
    shutil.which("node"), "npm ci is required for terminal rendering tests"
)
@unittest.skipIf(elevated(), "Host requires a non-admin account")
class FullScreen(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = test_terminal.Terminal.asyncSetUp
    asyncTearDown = test_terminal.Terminal.asyncTearDown

    async def test_fullscreen_unicode_editing_paste_resize_and_restore(self):
        fixture = Path(__file__).with_name("terminal_app.py").resolve()
        emulator_file = Path(__file__).with_name("terminal_emulator.cjs").resolve()
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "edited.txt"
            env = dict(
                os.environ,
                LOCALAPPDATA=directory,
                HOME=directory,
                XDG_STATE_HOME=directory,
            )
            async with open_host(relay=self.config) as host:
                tty = LocalTTY(
                    [
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
                        "connect",
                        host.code,
                    ],
                    env,
                    emulate=False,
                )
                emulator = await asyncio.create_subprocess_exec(
                    "node",
                    str(emulator_file),
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                copying = None
                try:
                    out = Output(tty)
                    await out.until(b"Connected to ")
                    import shlex

                    command = (
                        f"& '{sys.executable}' '{fixture}' '{target}'\r"
                        if sys.platform == "win32"
                        else shlex.join([sys.executable, str(fixture), str(target)])
                        + "\r"
                    )
                    if sys.platform == "win32":
                        await out.until(b"> ")
                        await tty.send(
                            b"Remove-Module PSReadLine -ErrorAction SilentlyContinue\r"
                        )
                        await out.until(b"> ")
                    if sys.platform != "win32":
                        await out.until(b"$ ")
                    await tty.send(command.encode())
                    screen = Screen(emulator, tty)
                    copying = asyncio.create_task(screen.copy())
                    await screen.until("READY FULL-SCREEN é 汉 🐍")
                    self.assertTrue(screen.alternate)
                    await asyncio.sleep(1)
                    await tty.send(b"AB")
                    await asyncio.sleep(0.3)
                    await tty.key("left")
                    await asyncio.sleep(0.3)
                    await tty.send(b"\x7f")
                    await asyncio.sleep(0.3)
                    await tty.send(b"Z")
                    await screen.until("ZB")
                    await tty.key("end")
                    await asyncio.sleep(0.3)
                    await tty.send(
                        "\x1b[200~\né 汉 🐍 e\u0301\nPASTED\x1b[201~".encode()
                    )
                    await screen.until("PASTED")
                    tty.resize(110, 35)
                    await screen.update({"resize": [110, 35]})
                    await asyncio.sleep(0.3)
                    await tty.key("end")
                    await screen.until("SIZE(110, 35)")
                    await tty.send(b"\x11")
                    await screen.until("APP-DONE")
                    self.assertEqual(screen.state["buffer"], "normal")
                    self.assertEqual(
                        target.read_text("utf-8"), "ZB\né 汉 🐍 e\u0301\nPASTED"
                    )
                    await tty.send(b"exit\r")
                    self.assertEqual(await tty.wait(), 0)
                finally:
                    if copying:
                        copying.cancel()
                        await asyncio.gather(copying, return_exceptions=True)
                    tty.close()
                    emulator.stdin.close()
                    with contextlib.suppress(TimeoutError):
                        async with asyncio.timeout(5):
                            await emulator.communicate()
                    if emulator.returncode is None:
                        emulator.kill()
                        await emulator.communicate()
