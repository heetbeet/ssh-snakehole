"""Wire compatibility of the small package-backed Wormhole crypto adapter."""

import secrets
import unittest

from ssh_snakehole.crypto import hkdf, seal, unseal


class PhaseCrypto(unittest.TestCase):
    def test_hkdf_rfc5869(self):
        result = hkdf(
            bytes([11]) * 22,
            bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
            42,
            bytes.fromhex("000102030405060708090a0b0c"),
        )
        self.assertEqual(
            result.hex(),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        )

    def test_authenticated_phase_rejects_tampering(self):
        key = secrets.token_bytes(32)
        payload = bytes(range(256))
        record = seal(key, payload)
        self.assertEqual(unseal(key, record), payload)
        altered = bytearray(record)
        altered[25] ^= 1
        with self.assertRaises(ValueError):
            unseal(key, altered)
