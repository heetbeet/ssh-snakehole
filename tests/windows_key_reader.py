"""Exercise raw key events as Windows TUIs with surrogate pairing consume them."""

import ctypes as c
import msvcrt
from ctypes import wintypes as w


class Key(c.Structure):
    _fields_ = [
        ("down", w.BOOL),
        ("repeat", w.WORD),
        ("vk", w.WORD),
        ("scan", w.WORD),
        ("char", w.WCHAR),
        ("control", w.DWORD),
    ]


class Data(c.Union):
    _fields_ = [("key", Key), ("raw", c.c_byte * 16)]


class Record(c.Structure):
    _fields_ = [("kind", w.WORD), ("data", Data)]


kernel = c.WinDLL("kernel32", use_last_error=True)
kernel.GetConsoleMode.argtypes = [w.HANDLE, c.POINTER(w.DWORD)]
kernel.SetConsoleMode.argtypes = [w.HANDLE, w.DWORD]
kernel.ReadConsoleInputW.argtypes = [
    w.HANDLE,
    c.POINTER(Record),
    w.DWORD,
    c.POINTER(w.DWORD),
]
handle = msvcrt.get_osfhandle(0)
mode = w.DWORD()
if not kernel.GetConsoleMode(handle, c.byref(mode)):
    raise c.WinError(c.get_last_error())
if not kernel.SetConsoleMode(handle, (mode.value & ~7) | 8):
    raise c.WinError(c.get_last_error())
print("KEY-READY", flush=True)
record, count = Record(), w.DWORD()
text, pending = [], None
while kernel.ReadConsoleInputW(handle, c.byref(record), 1, c.byref(count)):
    if record.kind != 1:
        continue
    key = record.data.key
    unit = ord(key.char)
    if 0xD800 <= unit <= 0xDFFF:
        # Crossterm 0.29 pairs surrogate events before filtering key-up events.
        # Interleaved high-down/high-up/low-down/low-up loses the character.
        if pending is None:
            pending = unit
        else:
            pair = pending.to_bytes(2, "little") + unit.to_bytes(2, "little")
            try:
                text.append(pair.decode("utf-16-le"))
            except UnicodeError:
                pass
            pending = None
    elif key.down and key.char == "\r":
        break
    elif key.down and unit:
        text.append(key.char)
print("KEY-TEXT-" + "".join(text).encode("utf-8").hex(), flush=True)
