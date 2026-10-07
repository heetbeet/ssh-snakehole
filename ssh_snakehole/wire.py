"""Bounded JSON, length prefixes and base64 for pairing and worker messages."""

import base64
import json
import math
import struct
from typing import Any

from .errors import ProtocolViolation

U32 = struct.Struct(">I")


def uint(value: int) -> bytes:
    return U32.pack(value)


def json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")


def parse_json(data: bytes, limit: int = 8192) -> Any:
    if len(data) > limit:
        raise ProtocolViolation("JSON record exceeds limit")

    def pairs(items):
        result: dict[str, Any] = {}
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
            for item in value.values():
                check(item, depth + 1)
        elif isinstance(value, list):
            if len(value) > 128:
                raise ValueError("JSON list exceeds limit")
            for item in value:
                check(item, depth + 1)
        elif isinstance(value, float) and not math.isfinite(value):
            raise ValueError("Non-finite JSON number")

    try:
        value = json.loads(data, object_pairs_hook=pairs, parse_constant=reject)
        check(value)
        return value
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ProtocolViolation("Invalid JSON record") from exc


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(value: str, length: int | None = None) -> bytes:
    try:
        if not isinstance(value, str):
            raise ValueError()
        result = base64.b64decode(value, validate=True)
        if length is not None and len(result) != length:
            raise ValueError()
        return result
    except (ValueError, TypeError) as exc:
        raise ProtocolViolation("Invalid base64 value") from exc
