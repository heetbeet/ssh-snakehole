"""Narrow ctypes access to Windows system APIs; no third-party DLLs."""

import ctypes as c
import secrets
import sys
from ctypes import wintypes as w

from .errors import PlatformContainmentUnavailable

assert sys.platform == "win32", "Windows system APIs require Windows"

k = c.WinDLL("kernel32", use_last_error=True)
a = c.WinDLL("advapi32", use_last_error=True)
k.GetCurrentProcess.restype = w.HANDLE
k.CloseHandle.argtypes = [w.HANDLE]
k.LocalFree.argtypes = [c.c_void_p]
k.CreateJobObjectW.argtypes = [c.c_void_p, w.LPCWSTR]
k.CreateJobObjectW.restype = w.HANDLE
k.OpenJobObjectW.argtypes = [w.DWORD, w.BOOL, w.LPCWSTR]
k.OpenJobObjectW.restype = w.HANDLE
k.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
k.SetInformationJobObject.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.DWORD]
k.TerminateJobObject.argtypes = [w.HANDLE, w.UINT]
a.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, c.POINTER(w.HANDLE)]
a.GetTokenInformation.argtypes = [
    w.HANDLE,
    c.c_int,
    c.c_void_p,
    w.DWORD,
    c.POINTER(w.DWORD),
]
a.ConvertSidToStringSidW.argtypes = [c.c_void_p, c.POINTER(w.LPWSTR)]
a.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
    w.LPCWSTR,
    w.DWORD,
    c.POINTER(c.c_void_p),
    c.c_void_p,
]
a.SetFileSecurityW.argtypes = [w.LPCWSTR, w.DWORD, c.c_void_p]
a.GetNamedSecurityInfoW.argtypes = [
    w.LPWSTR,
    c.c_int,
    w.DWORD,
    c.POINTER(c.c_void_p),
    c.c_void_p,
    c.POINTER(c.c_void_p),
    c.c_void_p,
    c.POINTER(c.c_void_p),
]
a.GetAce.argtypes = [c.c_void_p, w.DWORD, c.POINTER(c.c_void_p)]
a.GetUserNameW.argtypes = [w.LPWSTR, c.POINTER(w.DWORD)]


def checked(value):
    if not value:
        raise c.WinError(c.get_last_error())
    return value


def username():
    buffer = c.create_unicode_buffer(257)
    count = w.DWORD(len(buffer))
    checked(a.GetUserNameW(buffer, c.byref(count)))
    return buffer.value


def sid():
    token, needed, result = w.HANDLE(), w.DWORD(), w.LPWSTR()
    checked(a.OpenProcessToken(k.GetCurrentProcess(), 8, c.byref(token)))
    try:
        a.GetTokenInformation(token, 1, None, 0, c.byref(needed))
        data = c.create_string_buffer(needed.value)
        checked(a.GetTokenInformation(token, 1, data, len(data), c.byref(needed)))
        checked(
            a.ConvertSidToStringSidW(
                c.cast(data, c.POINTER(c.c_void_p))[0], c.byref(result)
            )
        )
        try:
            return result.value
        finally:
            k.LocalFree(result)
    finally:
        k.CloseHandle(token)


def descriptor():
    result = c.c_void_p()
    checked(
        a.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            f"D:P(A;;GA;;;{sid()})(A;;GA;;;SY)", 1, c.byref(result), None
        )
    )
    return result


def sid_string(pointer):
    value = w.LPWSTR()
    checked(a.ConvertSidToStringSidW(pointer, c.byref(value)))
    try:
        return value.value
    finally:
        k.LocalFree(value)


def protected_path(path):
    owner, acl, sd = c.c_void_p(), c.c_void_p(), c.c_void_p()
    error = a.GetNamedSecurityInfoW(
        str(path), 1, 1 | 4, c.byref(owner), None, c.byref(acl), None, c.byref(sd)
    )
    if error:
        raise c.WinError(error)
    trusted = {
        "S-1-5-18",
        "S-1-5-32-544",
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
    }
    try:
        if not acl.value or sid_string(owner) not in trusted:
            return False
        count = c.cast(acl, c.POINTER(c.c_ushort))[2]
        for i in range(count):
            ace = c.c_void_p()
            checked(a.GetAce(acl, i, c.byref(ace)))
            kind = c.cast(ace, c.POINTER(c.c_ubyte))[0]
            if kind == 1:
                continue  # Denies cannot broaden write authority.
            if kind != 0:
                return False  # Unusual conditional/object ACLs require review.
            mask = c.cast(ace, c.POINTER(w.DWORD))[1]
            if mask & (
                0x40000000
                | 0x10000000
                | 2
                | 4
                | 16
                | 64
                | 256
                | 0x10000
                | 0x40000
                | 0x80000
            ):
                assert ace.value is not None
                if sid_string(ace.value + 8) not in trusted:
                    return False
        return True
    finally:
        k.LocalFree(sd)


def private_file(path):
    sd = descriptor()
    try:
        checked(a.SetFileSecurityW(path, 4 | 0x80000000, sd))
    finally:
        k.LocalFree(sd)


class SecurityAttributes(c.Structure):
    _fields_ = [("length", w.DWORD), ("descriptor", c.c_void_p), ("inherit", w.BOOL)]


class BasicLimits(c.Structure):
    _fields_ = [
        ("process_time", c.c_int64),
        ("job_time", c.c_int64),
        ("flags", w.DWORD),
        ("min_working", c.c_size_t),
        ("max_working", c.c_size_t),
        ("active_processes", w.DWORD),
        ("affinity", c.c_size_t),
        ("priority", w.DWORD),
        ("scheduling", w.DWORD),
    ]


class ExtendedLimits(c.Structure):
    _fields_ = [
        ("basic", BasicLimits),
        ("io", c.c_uint64 * 6),
        ("process_memory", c.c_size_t),
        ("job_memory", c.c_size_t),
        ("peak_process", c.c_size_t),
        ("peak_job", c.c_size_t),
    ]


class Job:
    def __init__(self):
        self.name = "Local\\ssh-snakehole-" + secrets.token_hex(16)
        self.handle = None
        sd = descriptor()
        attributes = SecurityAttributes(c.sizeof(SecurityAttributes), sd, False)
        try:
            c.set_last_error(0)
            self.handle = checked(k.CreateJobObjectW(c.byref(attributes), self.name))
            if c.get_last_error() == 183:
                k.CloseHandle(self.handle)
                self.handle = None
                raise PlatformContainmentUnavailable("Command job name already exists")
            limits = ExtendedLimits()
            limits.basic.flags = 0x2000
            checked(
                k.SetInformationJobObject(
                    self.handle, 9, c.byref(limits), c.sizeof(limits)
                )
            )
        except BaseException:
            self.close()
            raise
        finally:
            k.LocalFree(sd)

    def close(self):
        if self.handle:
            k.TerminateJobObject(self.handle, 125)
            k.CloseHandle(self.handle)
            self.handle = None


def enter_job(name):
    handle = checked(k.OpenJobObjectW(1, False, name))
    try:
        if not k.AssignProcessToJobObject(handle, k.GetCurrentProcess()):
            raise PlatformContainmentUnavailable("Windows refused command containment")
    finally:
        k.CloseHandle(handle)
