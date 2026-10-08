"""Cancellable foreground console input without a stranded input thread."""

import asyncio
import getpass
import sys
import warnings


def read_secret(prompt, piped=False, limit=256):
    if piped:
        data = sys.stdin.buffer.readline(limit + 2)
        if not data.endswith(b"\n") or len(data.rstrip(b"\r\n")) > limit:
            raise ValueError("Expected one bounded secret line on stdin")
        try:
            value = data.rstrip(b"\r\n").decode("ascii")
        except UnicodeError:
            raise ValueError("Invalid secret input") from None
    else:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            try:
                value = getpass.getpass(prompt)
            except getpass.GetPassWarning:
                raise ValueError(
                    "Hidden input unavailable; use a dedicated stdin pipe"
                ) from None
    if not value or len(value) > limit:
        raise ValueError("Invalid secret input")
    return value


async def lines():
    if sys.platform == "win32":
        import msvcrt

        buffer: list[str] = []
        while True:
            if not msvcrt.kbhit():
                await asyncio.sleep(0.02)
                continue
            char = msvcrt.getwch()
            if char in ("\x00", "\xe0"):
                msvcrt.getwch()
            elif char == "\x03":
                raise KeyboardInterrupt
            elif char == "\x1a":
                return
            elif char in ("\r", "\n"):
                print()
                yield "".join(buffer)
                buffer.clear()
            elif char == "\b":
                if buffer:
                    buffer.pop()
                    print("\b \b", end="", flush=True)
            elif len(buffer) < 65536:
                buffer.append(char)
                print(char, end="", flush=True)
    else:
        reader = asyncio.StreamReader(limit=65537)
        transport, _ = await asyncio.get_running_loop().connect_read_pipe(
            lambda: asyncio.StreamReaderProtocol(reader), sys.stdin.buffer
        )
        try:
            while data := await reader.readline():
                if len(data) > 65536:
                    raise ValueError("Command exceeds limit")
                yield data.decode("utf-8").rstrip("\r\n")
        finally:
            transport.close()
