"""Stable failure types. None of their messages should contain credentials."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .client import CommandResult
    from .ticket import Ticket


class SnakeholeError(Exception):
    @property
    def code(self) -> str:
        return type(self).__name__


class ProtocolViolation(SnakeholeError):
    pass


class InvalidCode(SnakeholeError):
    pass


class InvalidTicket(SnakeholeError):
    pass


class UnsupportedRuntime(SnakeholeError):
    pass


class PlatformContainmentUnavailable(SnakeholeError):
    pass


class PairingFailed(SnakeholeError):
    pass


class PairingExpired(SnakeholeError):
    pass


class CodeConsumed(SnakeholeError):
    pass


class RelayUnavailable(SnakeholeError):
    ticket: "Ticket | None" = None


class ConnectTimeout(SnakeholeError):
    ticket: "Ticket | None" = None


class HostKeyMismatch(SnakeholeError):
    pass


class AuthenticationFailed(SnakeholeError):
    pass


class UnsupportedOperation(SnakeholeError):
    pass


class OutcomeUnknown(SnakeholeError):
    pass


class SessionExpired(SnakeholeError):
    pass


class CloseUnconfirmed(SnakeholeError):
    pass


class VaultUnlockFailed(SnakeholeError):
    pass


class RemoteCommandFailed(SnakeholeError):
    def __init__(self, result: "CommandResult") -> None:
        super().__init__(
            f"Remote command exited with {result.exit_code or result.exit_signal}"
        )
        self.result = result


class CommandTimedOut(SnakeholeError):
    def __init__(
        self,
        message: str = "Remote command timed out",
        *,
        stdout: bytes = b"",
        stderr: bytes = b"",
    ) -> None:
        super().__init__(message)
        self.stdout, self.stderr = stdout, stderr


class OutputLimitExceeded(CommandTimedOut):
    def __init__(
        self,
        message: str = "Remote command output exceeded its limit",
        *,
        stdout: bytes = b"",
        stderr: bytes = b"",
    ) -> None:
        super().__init__(message, stdout=stdout, stderr=stderr)


class TransferFailed(SnakeholeError):
    def __init__(
        self,
        message: str,
        *,
        committed: bool | None = None,
        temporary: str | None = None,
    ) -> None:
        super().__init__(message)
        self.committed, self.temporary = committed, temporary
