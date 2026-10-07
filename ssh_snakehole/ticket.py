"""Strict paired identities. Tickets contain credentials and have redacted reprs."""

from __future__ import annotations

import datetime
import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from .errors import InvalidTicket, ProtocolViolation, SessionExpired
from .ssh import key_public
from .transit import endpoint
from .wire import b64, json_bytes, parse_json, unb64

SCHEMA = "ssh-snakehole/1"


def timestamp(value: float) -> str:
    return datetime.datetime.fromtimestamp(value, datetime.UTC).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def expiry(value: str) -> float:
    try:
        if not isinstance(value, str) or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value
        ):
            raise ValueError()
        return (
            datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
            .replace(tzinfo=datetime.UTC)
            .timestamp()
        )
    except ValueError as exc:
        raise ProtocolViolation("Invalid session expiry") from exc


def strict(value: Any, fields: Iterable[str], *, kind: str, role: str) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != set(fields) | {"schema", "type", "role"}
        or value.get("schema") != SCHEMA
        or value.get("type") != kind
        or value.get("role") != role
    ):
        raise ProtocolViolation("Invalid pairing message schema")


def validate_offer(offer: dict[str, Any]) -> dict[str, Any]:
    strict(
        offer,
        (
            "session_id",
            "host_key",
            "transit_key",
            "host_side",
            "operator_side",
            "relay",
            "host_os",
            "host_name",
            "process_user",
            "privilege",
            "expires_at",
        ),
        kind="offer",
        role="host",
    )
    for key, count in (("session_id", 32), ("host_side", 16), ("operator_side", 16)):
        if not isinstance(offer[key], str) or not re.fullmatch(
            f"[0-9a-f]{{{count}}}", offer[key]
        ):
            raise ProtocolViolation("Invalid pairing identifier")
    if offer["host_side"] == offer["operator_side"]:
        raise ProtocolViolation("Reflected Transit side")
    if not isinstance(offer["host_key"], str) or not offer["host_key"].startswith(
        "ssh-ed25519 "
    ):
        raise ProtocolViolation("Invalid paired host key")
    key_public(unb64(offer["host_key"].split(" ")[1]))
    unb64(offer["transit_key"], 32)
    endpoint(offer["relay"])
    if offer["host_os"] not in ("windows", "linux", "macos") or offer[
        "privilege"
    ] not in ("user", "admin"):
        raise ProtocolViolation("Invalid host information")
    for key in ("host_name", "process_user"):
        if (
            not isinstance(offer[key], str)
            or len(offer[key].encode("utf-8")) > 256
            or any(ord(c) < 32 for c in offer[key])
        ):
            raise ProtocolViolation("Invalid host label")
    expiry(offer["expires_at"])
    return offer


@dataclass(frozen=True)
class HostInfo:
    session_id: str
    host_name: str
    process_user: str
    host_os: str
    privilege: str
    expires_at: str

    @classmethod
    def from_offer(cls, offer: dict[str, Any]) -> HostInfo:
        return cls(**{key: offer[key] for key in cls.__dataclass_fields__})


@dataclass(frozen=True, init=False, repr=False)
class Ticket:
    _offer: dict[str, Any] = field(repr=False)
    client_seed: bytes = field(repr=False)

    def __init__(self, offer: dict[str, Any], client_seed: bytes) -> None:
        validate_offer(offer)
        if not isinstance(client_seed, bytes) or len(client_seed) != 32:
            raise InvalidTicket("Invalid operator seed")
        object.__setattr__(self, "_offer", dict(offer))
        object.__setattr__(self, "client_seed", client_seed)

    @property
    def offer(self) -> dict[str, Any]:
        return dict(self._offer)

    def __repr__(self) -> str:
        return (
            f"Ticket(session_id={self.offer['session_id']!r}, credentials=<redacted>)"
        )

    @property
    def info(self) -> HostInfo:
        return HostInfo.from_offer(self.offer)

    def check_live(self) -> None:
        import time

        if time.time() >= expiry(self.offer["expires_at"]):
            raise SessionExpired("Host lifetime has expired")

    def to_bytes(self) -> bytes:
        return json_bytes(
            {
                "schema": SCHEMA,
                "offer": self._offer,
                "client_seed": b64(self.client_seed),
            }
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> Ticket:
        try:
            value = parse_json(data)
            if (
                set(value) != {"schema", "offer", "client_seed"}
                or value["schema"] != SCHEMA
            ):
                raise ValueError()
            return cls(value["offer"], unb64(value["client_seed"], 32))
        except (ValueError, TypeError, KeyError, ProtocolViolation) as exc:
            raise InvalidTicket("Invalid accepted ticket") from exc


def digest(value: Any) -> str:
    return hashlib.sha256(json_bytes(value)).hexdigest()
