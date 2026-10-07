"""Built-in operating-system APIs for identity, private files and child lifetime."""

import os
import sys
from pathlib import Path

from .errors import PlatformContainmentUnavailable, UnsupportedRuntime


def elevated():
    if sys.platform != "win32":
        return os.geteuid() == 0
    import ctypes as c
    from ctypes import wintypes as w

    adv = c.WinDLL("advapi32", use_last_error=True)
    kernel = c.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = w.HANDLE
    adv.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, c.POINTER(w.HANDLE)]
    adv.GetTokenInformation.argtypes = [
        w.HANDLE,
        c.c_int,
        c.c_void_p,
        w.DWORD,
        c.POINTER(w.DWORD),
    ]
    kernel.CloseHandle.argtypes = [w.HANDLE]
    token, count, value = w.HANDLE(), w.DWORD(), w.DWORD()
    if not adv.OpenProcessToken(kernel.GetCurrentProcess(), 8, c.byref(token)):
        raise c.WinError(c.get_last_error())
    try:
        if not adv.GetTokenInformation(
            token, 20, c.byref(value), c.sizeof(value), c.byref(count)
        ):
            raise c.WinError(c.get_last_error())
        return bool(value.value)
    finally:
        kernel.CloseHandle(token)


def process_user():
    if sys.platform == "win32":
        return _win().username()
    import pwd

    return pwd.getpwuid(os.geteuid()).pw_name


def check_privilege(admin):
    actual = elevated()
    if actual != admin:
        raise UnsupportedRuntime(
            "Use --admin in an elevated terminal"
            if actual
            else "Admin mode requires an elevated terminal"
        )
    if admin:
        if not sys.flags.isolated:
            raise UnsupportedRuntime(
                "Admin launch requires Python -I and a protected installation"
            )
        paths = [
            Path(sys.executable).resolve(),
            Path(__file__).resolve(),
            Path(sys.prefix).resolve(),
            Path(sys.base_prefix).resolve(),
        ]
        if sys.platform == "win32":
            roots = [
                Path(os.environ[key]).resolve()
                for key in ("ProgramFiles", "SystemRoot")
            ]
            if any(not any(p.is_relative_to(root) for root in roots) for p in paths):
                raise UnsupportedRuntime(
                    "Admin mode requires Python and this package installed in Program Files or Windows"
                )
            for path in paths:
                root = next(root for root in roots if path.is_relative_to(root))
                while not path.exists():
                    path = path.parent
                for parent in (path, *path.parents):
                    if not parent.is_relative_to(root):
                        break
                    if not _win().protected_path(parent):
                        raise UnsupportedRuntime(
                            "Admin installation grants write access outside trusted system administrators"
                        )
        else:
            for path in paths:
                while not path.exists():
                    path = path.parent
                for parent in (path, *path.parents):
                    info = parent.stat()
                    if info.st_uid != 0 or info.st_mode & 0o022:
                        raise UnsupportedRuntime(
                            "Admin mode requires a root-owned installation without group or public write access"
                        )
    return "admin" if actual else "user"


def check_runtime(*, host=False):
    import asyncio
    import hashlib
    import ssl

    if (
        sys.implementation.name != "cpython"
        or not (3, 11) <= sys.version_info[:2] < (3, 15)
        or not hasattr(hashlib, "scrypt")
        or not ssl.HAS_TLSv1_2
    ):
        raise UnsupportedRuntime("CPython 3.11-3.14 with ssl and scrypt is required")
    if (
        host
        and sys.platform == "win32"
        and not isinstance(asyncio.get_running_loop(), asyncio.ProactorEventLoop)
    ):
        raise UnsupportedRuntime(
            "Windows host requires the default Proactor event loop for subprocess pipes"
        )


def private_file(path):
    """Restrict a newly created local credential file to its owner and SYSTEM."""
    if sys.platform != "win32":
        os.chmod(path, 0o600)
        return
    _win().private_file(str(path))


def _win():
    from . import win32

    return win32


def create_job():
    return _win().Job()


def enter_worker(job_name, expected_parent):
    if sys.platform == "win32":
        _win().enter_job(job_name)
    else:
        if os.getppid() != expected_parent:
            raise PlatformContainmentUnavailable("Command parent exited during startup")
