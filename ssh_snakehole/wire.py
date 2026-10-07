"""Bounded JSON and SSH binary encodings shared by the protocol engines."""
import base64
import json
import struct

from .errors import ProtocolViolation

U32 = struct.Struct(">I")
U64 = struct.Struct(">Q")


def uint(value):
    return U32.pack(value)


def string(value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    return uint(len(value)) + value


def mpint(value):
    if value < 0:
        raise ValueError("Only nonnegative SSH integers are used")
    data = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if data and data[0] & 128:
        data = b"\0" + data
    return string(data)


class Reader:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, count):
        if count < 0 or self.pos + count > len(self.data):
            raise ProtocolViolation("Truncated binary record")
        result = self.data[self.pos:self.pos + count]
        self.pos += count
        return result

    def byte(self): return self.take(1)[0]
    def uint(self): return U32.unpack(self.take(4))[0]
    def uint64(self): return U64.unpack(self.take(8))[0]

    def string(self, limit=262144):
        count = self.uint()
        if count > limit:
            raise ProtocolViolation("Binary string exceeds limit")
        return self.take(count)

    def text(self, limit=16384):
        try:
            return self.string(limit).decode("utf-8")
        except UnicodeError as exc:
            raise ProtocolViolation("Invalid UTF-8") from exc

    def done(self):
        if self.pos != len(self.data):
            raise ProtocolViolation("Trailing binary data")


def json_bytes(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


def parse_json(data, limit=8192):
    if len(data) > limit:
        raise ProtocolViolation("JSON record exceeds limit")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result or len(result) >= 128:
                raise ValueError("Duplicate or excessive JSON keys")
            result[key] = value
        return result

    def reject(value):
        raise ValueError("Non-finite JSON number")

    def check(value, depth=0):
        if depth > 8:
            raise ValueError("JSON nesting exceeds limit")
        if isinstance(value, dict):
            for item in value.values(): check(item, depth + 1)
        elif isinstance(value, list):
            if len(value) > 128: raise ValueError("JSON list exceeds limit")
            for item in value: check(item, depth + 1)

    try:
        value = json.loads(data, object_pairs_hook=pairs, parse_constant=reject)
        check(value)
        return value
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ProtocolViolation("Invalid JSON record") from exc


def b64(data): return base64.b64encode(data).decode("ascii")


def unb64(value, length=None):
    try:
        if not isinstance(value, str): raise ValueError()
        result = base64.b64decode(value, validate=True)
        if length is not None and len(result) != length: raise ValueError()
        return result
    except (ValueError, TypeError) as exc:
        raise ProtocolViolation("Invalid base64 value") from exc
