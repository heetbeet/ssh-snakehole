"""Verified WebSocket TLS, including an explicitly trusted private CA."""

import ssl
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from ssh_snakehole.relay import Relay
from ssh_snakehole.websocket import WebSocket


class TLS(unittest.IsolatedAsyncioTestCase):
    async def test_private_ca_does_not_bypass_expiry_or_hostname_validation(self):
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.now(UTC)
        with tempfile.TemporaryDirectory() as directory:
            pem = Path(directory) / "cert.pem"
            secret = Path(directory) / "key.pem"
            secret.write_bytes(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            for expired in (False, True):
                certificate = (
                    x509.CertificateBuilder()
                    .subject_name(subject)
                    .issuer_name(subject)
                    .public_key(key.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(now - timedelta(days=2))
                    .not_valid_after(now + timedelta(days=-1 if expired else 1))
                    .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
                    .add_extension(
                        x509.SubjectAlternativeName([x509.DNSName("localhost")]), False
                    )
                    .add_extension(
                        x509.KeyUsage(
                            True, False, False, False, False, True, True, False, False
                        ),
                        True,
                    )
                    .add_extension(
                        x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                        False,
                    )
                    .add_extension(
                        x509.AuthorityKeyIdentifier.from_issuer_public_key(
                            key.public_key()
                        ),
                        False,
                    )
                    .sign(key, hashes.SHA256())
                )
                pem.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(pem, secret)
                relay = await Relay().start(tls=context)
                try:
                    url = f"wss://localhost:{relay.mailbox_port}/v1"
                    with patch.dict(
                        "os.environ", {"SSL_CERT_FILE": "", "SSL_CERT_DIR": ""}
                    ):
                        with self.assertRaises(ssl.SSLCertVerificationError):
                            await WebSocket.connect(url)
                    with patch.dict(
                        "os.environ", {"SSL_CERT_FILE": str(pem), "SSL_CERT_DIR": ""}
                    ):
                        if expired:
                            with self.assertRaises(ssl.SSLCertVerificationError):
                                await WebSocket.connect(url)
                        else:
                            ws = await WebSocket.connect(url)
                            await ws.aclose()
                            with self.assertRaises(ssl.SSLCertVerificationError):
                                await WebSocket.connect(
                                    f"wss://127.0.0.1:{relay.mailbox_port}/v1"
                                )
                finally:
                    await relay.aclose()
