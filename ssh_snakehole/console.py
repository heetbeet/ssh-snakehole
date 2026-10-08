"""Foreground console input with owned, cancellable readers."""

import asyncio
import contextlib
import getpass
import os
import stat
import sys
import warnings


def read_secret(prompt, piped=False, limit=256):
    if piped:
        source = getattr(sys.stdin.buffer, "raw", sys.stdin.buffer)
        data = bytearray()
        while len(data) < limit + 2:
            char = source.read(1)
            if not char:
                break
            data.extend(char)
            if char == b"\n":
                break
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


@contextlib.contextmanager
def raw_terminal():
    """Forward keystrokes, including Ctrl+C, and restore the local terminal."""
    if sys.platform != "win32":
        import termios
        import tty

        previous = termios.tcgetattr(sys.stdin.fileno())
        try:
            tty.setraw(sys.stdin.fileno())
            yield
        finally:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, previous)
        return
    import ctypes as c
    import msvcrt
    from ctypes import wintypes as w

    kernel = c.WinDLL("kernel32", use_last_error=True)
    kernel.GetConsoleMode.argtypes = [w.HANDLE, c.POINTER(w.DWORD)]
    kernel.SetConsoleMode.argtypes = [w.HANDLE, w.DWORD]
    saved = []
    try:
        for stream, input_mode in ((sys.stdin, True), (sys.stdout, False)):
            handle = msvcrt.get_osfhandle(stream.fileno())
            mode = w.DWORD()
            if not kernel.GetConsoleMode(handle, c.byref(mode)):
                raise OSError("A Windows console is required for an interactive shell")
            saved.append((handle, mode.value))
            flags = (mode.value & ~0x7) | 0x200 if input_mode else mode.value | 0xC
            if not kernel.SetConsoleMode(handle, flags):
                raise c.WinError(c.get_last_error())
        yield
    finally:
        for handle, original in reversed(saved):
            kernel.SetConsoleMode(handle, original)


async def chunks():
    source = getattr(sys.stdin.buffer, "raw", sys.stdin.buffer)
    if stat.S_ISREG(os.fstat(sys.stdin.fileno()).st_mode):
        while data := source.read(32768):
            yield data
        return
    if sys.platform == "win32" and not sys.stdin.isatty():
        import ctypes as c
        import msvcrt
        from ctypes import wintypes as w

        kernel = c.WinDLL("kernel32", use_last_error=True)
        kernel.PeekNamedPipe.argtypes = [
            w.HANDLE,
            c.c_void_p,
            w.DWORD,
            c.c_void_p,
            c.POINTER(w.DWORD),
            c.c_void_p,
        ]
        handle = msvcrt.get_osfhandle(sys.stdin.fileno())
        while True:
            available = w.DWORD()
            if not kernel.PeekNamedPipe(
                handle, None, 0, None, c.byref(available), None
            ):
                if c.get_last_error() == 109:
                    return
                raise c.WinError(c.get_last_error())
            if available.value:
                yield source.read(min(available.value, 32768))
            else:
                await asyncio.sleep(0.01)
    if sys.platform == "win32":
        import codecs
        import ctypes as c
        import msvcrt
        import queue
        import threading
        from ctypes import wintypes as w

        kernel = c.WinDLL("kernel32", use_last_error=True)
        kernel.ReadConsoleW.argtypes = [
            w.HANDLE,
            c.c_void_p,
            w.DWORD,
            c.POINTER(w.DWORD),
            c.c_void_p,
        ]
        kernel.OpenThread.argtypes = [w.DWORD, w.BOOL, w.DWORD]
        kernel.OpenThread.restype = w.HANDLE
        kernel.CancelSynchronousIo.argtypes = [w.HANDLE]
        kernel.CloseHandle.argtypes = [w.HANDLE]
        handle = msvcrt.get_osfhandle(sys.stdin.fileno())
        messages: queue.Queue[bytes | OSError] = queue.Queue(maxsize=16)
        stopping = threading.Event()
        handles = []

        def read():
            thread_handle = kernel.OpenThread(1, False, threading.get_native_id())
            if not thread_handle:
                messages.put(c.WinError(c.get_last_error()))
                return
            handles.append(thread_handle)
            buffer = c.create_unicode_buffer(2048)
            count = w.DWORD()
            while not stopping.is_set():
                # ReadConsole performs Windows' VT key translation. CRT getwch
                # and ReadConsoleInput bypass it and return DOS/raw key events.
                success = kernel.ReadConsoleW(
                    handle, buffer, 2048, c.byref(count), None
                )
                if stopping.is_set():
                    return
                message = (
                    "".join(buffer[: count.value]).encode("utf-16-le", "surrogatepass")
                    if success
                    else c.WinError(c.get_last_error())
                )
                while not stopping.is_set():
                    try:
                        messages.put(message, timeout=0.05)
                        break
                    except queue.Full:
                        pass
                if not success:
                    return

        thread = threading.Thread(target=read, daemon=True)
        thread.start()
        decoder = codecs.getincrementaldecoder("utf-16-le")()
        try:
            while True:
                try:
                    message = messages.get_nowait()
                except queue.Empty:
                    await asyncio.sleep(0.01)
                    continue
                if isinstance(message, OSError):
                    raise message
                if text := decoder.decode(message):
                    yield text.encode("utf-8")
        finally:
            stopping.set()
            # Repeat cancellation across the race before the next blocking read.
            # Join this owned reader before restoring console modes.
            while thread.is_alive():
                if handles:
                    kernel.CancelSynchronousIo(handles[0])
                thread.join(0.01)
            if handles:
                kernel.CloseHandle(handles[0])
    else:
        reader = asyncio.StreamReader(limit=65536)
        # asyncio owns and closes its pipe. Give it a duplicate so it cannot
        # close the caller's stdin before raw terminal settings are restored.
        descriptor = sys.stdin.fileno()
        was_blocking = os.get_blocking(descriptor)
        with os.fdopen(os.dup(descriptor), "rb", buffering=0) as pipe:
            transport, _ = await asyncio.get_running_loop().connect_read_pipe(
                lambda: asyncio.StreamReaderProtocol(reader), pipe
            )
            try:
                while data := await reader.read(32768):
                    yield data
            finally:
                transport.close()
                # Duplicates share the file description and its blocking flag.
                os.set_blocking(descriptor, was_blocking)
