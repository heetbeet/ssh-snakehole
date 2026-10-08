"""Fixed local startup worker. Remote payload is read only after containment."""

import os
import struct
import subprocess
import sys
from pathlib import Path

from .platform import enter_worker
from .wire import parse_json


def exact(count):
    result = bytearray()
    while len(result) < count:
        part = os.read(0, count - len(result))
        if not part:
            raise EOFError("Command parent closed")
        result.extend(part)
    return bytes(result)


def watch_parent(descriptor):
    """The watcher keeps its process group alive until the host closes the pipe."""
    bootstrap = "import sys;sys.path.insert(0,sys.argv.pop(1));from ssh_snakehole.worker import main;main()"
    watcher = subprocess.Popen(
        [
            sys.executable,
            *(["-I"] if sys.flags.isolated else []),
            "-c",
            bootstrap,
            str(Path(__file__).resolve().parent.parent),
            "--watch",
            str(descriptor),
            str(os.getpid()),
        ],
        pass_fds=(descriptor,),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    assert watcher.stdout is not None
    if watcher.stdout.read(6) != b"READY\n":
        raise RuntimeError("Command lifetime watcher did not start")
    watcher.stdout.close()


def main():
    if sys.platform != "win32" and sys.argv[1] == "--watch":
        import signal

        watch_fd, group = int(sys.argv[2]), int(sys.argv[3])
        # The lifetime watcher is in the command group. Terminal Ctrl+C and
        # hangup must reach the command without prematurely killing its owner.
        for name in (
            "SIGINT",
            "SIGQUIT",
            "SIGHUP",
            "SIGTERM",
            "SIGTSTP",
            "SIGTTIN",
            "SIGTTOU",
        ):
            signal.signal(getattr(signal, name), signal.SIG_IGN)
        os.write(1, b"READY\n")
        os.close(1)
        try:
            while os.read(watch_fd, 1):
                pass
        finally:
            os.killpg(group, signal.SIGKILL)
        return
    enter_worker(sys.argv[1], int(sys.argv[2]))
    descriptor = int(sys.argv[3]) if os.name != "nt" else None
    if descriptor is not None:
        watch_parent(descriptor)
    os.write(1, b"READY\n")
    count = struct.unpack(">I", exact(4))[0]
    if count > 65536:
        raise ValueError("Command exceeds limit")
    request = parse_json(exact(count), 65536)
    if request["terminal"] is not None:
        from .pty_worker import serve

        status = serve(request, descriptor)
    else:
        if descriptor is not None:
            os.close(descriptor)
        process = subprocess.Popen(
            request["command"], shell=request["shell"], stdin=0, stdout=1, stderr=2
        )
        status = process.wait()
    if status < 0 and os.name != "nt":
        import signal

        signal.signal(-status, signal.SIG_DFL)
        os.kill(os.getpid(), -status)
    raise SystemExit(status)


if __name__ == "__main__":
    main()
