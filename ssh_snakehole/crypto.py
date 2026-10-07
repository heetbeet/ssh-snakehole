"""Established crypto packages for Wormhole phases and encrypted tickets."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nacl.exceptions import CryptoError
from nacl.secret import SecretBox


def hkdf(key: bytes, info: bytes = b"", length: int = 32, salt: bytes = b"") -> bytes:
    return HKDF(hashes.SHA256(), length, salt or None, info).derive(key)


def seal(key: bytes, plaintext: bytes, nonce: bytes | None = None) -> bytes:
    return bytes(SecretBox(key).encrypt(plaintext, nonce))


def unseal(key: bytes, record: bytes) -> bytes:
    try:
        return SecretBox(key).decrypt(bytes(record))
    except CryptoError as exc:
        raise ValueError("SecretBox authentication failed") from exc
