"""Stable failure types. None of their messages should contain credentials."""


class SnakeholeError(Exception):
    @property
    def code(self):
        return type(self).__name__


class ProtocolViolation(SnakeholeError): pass
class InvalidCode(SnakeholeError): pass
class InvalidTicket(SnakeholeError): pass
class UnsupportedRuntime(SnakeholeError): pass
class PlatformContainmentUnavailable(SnakeholeError): pass
class PairingFailed(SnakeholeError): pass
class PairingExpired(SnakeholeError): pass
class CodeConsumed(SnakeholeError): pass
class RelayUnavailable(SnakeholeError): pass
class ConnectTimeout(SnakeholeError): pass
class HostKeyMismatch(SnakeholeError): pass
class AuthenticationFailed(SnakeholeError): pass
class UnsupportedPeer(SnakeholeError): pass
class UnsupportedOperation(SnakeholeError): pass
class OutcomeUnknown(SnakeholeError): pass
class SessionExpired(SnakeholeError): pass
class CloseUnconfirmed(SnakeholeError): pass
class VaultUnlockFailed(SnakeholeError): pass
class AtomicCommitUnavailable(SnakeholeError): pass


class RemoteCommandFailed(SnakeholeError):
    def __init__(self, result):
        super().__init__(f"Remote command exited with {result.exit_code or result.exit_signal}")
        self.result = result


class CommandTimedOut(SnakeholeError):
    def __init__(self, message="Remote command timed out", *, stdout=b"", stderr=b""):
        super().__init__(message)
        self.stdout, self.stderr = stdout, stderr


class OutputLimitExceeded(CommandTimedOut): pass


class TransferFailed(SnakeholeError):
    def __init__(self, message, *, committed=None, temporary=None):
        super().__init__(message)
        self.committed, self.temporary = committed, temporary
