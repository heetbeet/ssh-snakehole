"""Native PTY worker. SSH bytes stay bytes; ConPTY uses incremental UTF-8."""

import codecs
import contextlib
import os
import signal
import struct
import subprocess
import sys
import threading
import time

from .worker import exact, watch_parent


def serve(request, descriptor):
    terminal = request["terminal"]
    cols, rows = terminal["size"]
    cols, rows = cols or 80, rows or 24
    os.environ["TERM"] = terminal["term"]
    command = request["command"]
    if sys.platform == "win32":
        from winpty import PTY, Backend

        pty = PTY(cols, rows, backend=Backend.ConPTY)
        if not pty.spawn(command[0], " " + subprocess.list2cmdline(command[1:])):
            raise OSError("ConPTY could not start the shell")
        # ConPTY starts a new screen at (0, 0). Clear its viewport first so its
        # absolute cursor movements cannot overwrite the client's old prompt.
        os.write(1, b"\x1b[2J\x1b[H")
    else:
        import termios

        from ptyprocess import PtyProcess

        argv = ["/bin/sh", "-c", command] if request["shell"] else command

        def setup():
            watch_parent(descriptor)
            os.close(descriptor)
            # Apply RFC 4254 terminal flags using the platform's termios values.
            attrs = termios.tcgetattr(0)
            for number, name, index in (
                (30, "IGNPAR", 0),
                (31, "PARMRK", 0),
                (32, "INPCK", 0),
                (33, "ISTRIP", 0),
                (34, "INLCR", 0),
                (35, "IGNCR", 0),
                (36, "ICRNL", 0),
                (38, "IXON", 0),
                (40, "IXOFF", 0),
                (50, "ISIG", 3),
                (51, "ICANON", 3),
                (53, "ECHO", 3),
                (54, "ECHOE", 3),
                (55, "ECHOK", 3),
                (56, "ECHONL", 3),
                (59, "IEXTEN", 3),
                (70, "OPOST", 1),
                (72, "ONLCR", 1),
            ):
                value = terminal["modes"].get(str(number))
                flag = getattr(termios, name, 0)
                if value is not None:
                    attrs[index] = (
                        attrs[index] | flag if value else attrs[index] & ~flag
                    )
            for number, name in (
                (1, "VINTR"),
                (2, "VQUIT"),
                (3, "VERASE"),
                (4, "VKILL"),
                (5, "VEOF"),
                (6, "VEOL"),
                (9, "VSUSP"),
            ):
                value = terminal["modes"].get(str(number))
                if value is not None and 0 <= value <= 255:
                    attrs[6][getattr(termios, name)] = bytes([value])
            termios.tcsetattr(0, termios.TCSANOW, attrs)

        pty = PtyProcess.spawn(
            argv, dimensions=(rows, cols), pass_fds=(descriptor,), preexec_fn=setup
        )
        os.close(descriptor)
        os.set_blocking(pty.fd, False)

    failures = []

    def feed():
        decoder = codecs.getincrementaldecoder("utf-8")()
        try:
            while True:
                count = struct.unpack(">I", exact(4))[0]
                if not 1 <= count <= 32769:
                    raise ValueError("Terminal input exceeds limit")
                frame = exact(count)
                kind, data = frame[:1], frame[1:]
                if kind == b"D":
                    if sys.platform == "win32":
                        text = decoder.decode(data)
                        if text:
                            # VT text is not a physical down/up pair. ConPTY's
                            # default surrogate key-up synthesis breaks raw-key
                            # readers. Explicit Unicode key-downs preserve pairs.
                            text = "".join(
                                char
                                if ord(char) <= 0xFFFF
                                else "".join(
                                    f"\x1b[0;0;{unit};1;0;1_"
                                    for unit in struct.unpack(
                                        "<HH", char.encode("utf-16-le")
                                    )
                                )
                                for char in text
                            )
                            pty.write(text)
                    else:
                        view = memoryview(data)
                        while view:
                            try:
                                count = os.write(pty.fd, view)
                                view = view[count:]
                            except BlockingIOError:
                                time.sleep(0.01)
                elif kind == b"R":
                    width, height = struct.unpack(">II", data)
                    if not all(1 <= n <= 1000 for n in (width, height)):
                        raise ValueError("Invalid terminal size")
                    if sys.platform == "win32":
                        pty.set_size(width, height)
                    else:
                        pty.setwinsize(height, width)
                elif kind == b"S":
                    name = data.decode("ascii")
                    if name not in ("INT", "QUIT", "TERM", "HUP", "KILL", "WINCH"):
                        continue
                    if sys.platform == "win32":
                        if name == "INT":
                            pty.write("\x03")
                        elif name in ("TERM", "HUP", "KILL"):
                            from .win32 import checked, k

                            checked(k.TerminateProcess(pty.fd, 1))
                    else:
                        os.killpg(os.tcgetpgrp(pty.fd), getattr(signal, "SIG" + name))
                else:
                    raise ValueError("Invalid terminal input")
        except (EOFError, OSError):
            # SSH EOF is input EOF, not a request to stop the output stream.
            if sys.platform == "win32":
                try:
                    decoder.decode(b"", final=True)
                except UnicodeError:
                    failures.append("Windows terminal input requires complete UTF-8")
                    return
            with contextlib.suppress(Exception):
                pty.write("\x04" if sys.platform == "win32" else b"\x04")
        except UnicodeError:
            failures.append("Windows terminal input requires UTF-8")
        except (ValueError, struct.error):
            failures.append("Invalid terminal input")

    # This thread exists only inside the owned worker, which dies with the channel.
    threading.Thread(target=feed, daemon=True).start()
    exited = None
    startup = sys.platform == "win32"
    pending = ""
    try:
        while True:
            if failures:
                raise OSError(failures[0])
            try:
                data = pty.read() if sys.platform == "win32" else os.read(pty.fd, 32768)
            except BlockingIOError:
                data = b""
            except (EOFError, OSError):
                break
            if startup and data:
                assert isinstance(data, str)
                data = pending + data
                pending = ""
                for query in ("\x1b[c", "\x1b[0c"):
                    if query in data:
                        # This is ConPTY's own startup query, not an application's
                        # query. A conservative VT100 reply avoids its 3s wait,
                        # even when a nested local ConPTY consumes DA replies.
                        pty.write("\x1b[?1;2c")
                        data = data.replace(query, "", 1)
                        startup = False
                        break
                else:
                    for count in range(min(3, len(data)), 0, -1):
                        if any(
                            query.startswith(data[-count:])
                            for query in ("\x1b[c", "\x1b[0c")
                        ):
                            pending, data = data[-count:], data[:-count]
                            break
            if data:
                data = data.encode("utf-8") if isinstance(data, str) else data
                view = memoryview(data)
                while view:
                    view = view[os.write(1, view) :]
                exited = None
            if not pty.isalive():
                if exited is None:
                    exited = time.monotonic()
                # ConPTY flushes output asynchronously after the child exits.
                if not data and (
                    sys.platform != "win32" or time.monotonic() - exited > 0.25
                ):
                    break
            if not data:
                time.sleep(0.01)
        if sys.platform == "win32":
            if pending:
                os.write(1, pending.encode("utf-8"))
            return pty.get_exitstatus() or 0
        pty.wait()
        return (
            pty.exitstatus
            if pty.exitstatus is not None
            else -(pty.signalstatus or signal.SIGHUP)
        )
    finally:
        if sys.platform == "win32":
            pty.cancel_io()
        else:
            pty.close(force=True)
