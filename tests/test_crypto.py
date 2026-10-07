import hashlib
import secrets
import unittest

from ssh_snakehole._crypto import SPAKE, SSHCipher, hkdf, public_key, seal, sign, unseal, verify, x25519


class CryptoTests(unittest.TestCase):
    def test_ed25519_published_vector_and_invalid_signature(self):
        seed = bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
        public = bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
        expected = bytes.fromhex('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b')
        self.assertEqual(public_key(seed), public)
        self.assertEqual(sign(seed,b''), expected)
        self.assertTrue(verify(public,b'',expected))
        self.assertFalse(verify(public,b'changed',expected))
        self.assertFalse(verify(public,b'',expected[:32]+bytes([255])*32))

    def test_hkdf_rfc5869(self):
        result = hkdf(bytes([11])*22, bytes.fromhex('f0f1f2f3f4f5f6f7f8f9'),42,bytes.fromhex('000102030405060708090a0b0c'))
        self.assertEqual(result.hex(),'3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865')

    def test_x25519_rfc7748(self):
        a = bytes.fromhex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')
        b = bytes.fromhex('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb')
        self.assertEqual(x25519(a).hex(),'8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a')
        self.assertEqual(x25519(a,x25519(b)).hex(),'4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742')
        with self.assertRaises(ValueError): x25519(a,bytes(32))

    def test_spake_exchange_wrong_password_and_reflection(self):
        a,b = SPAKE(b'42-code',b'app'),SPAKE(b'42-code',b'app')
        self.assertEqual(a.finish(b.start()),b.finish(a.start()))
        a,b = SPAKE(b'wrong',b'app'),SPAKE(b'right',b'app')
        self.assertNotEqual(a.finish(b.start()),b.finish(a.start()))
        a = SPAKE(b'pw',b'app')
        with self.assertRaises(ValueError): a.finish(a.start())

    def test_secretbox_tampering(self):
        key=secrets.token_bytes(32)
        for length in (0,1,15,16,31,32,63,64,65,8192):
            payload=secrets.token_bytes(length); record=seal(key,payload)
            self.assertEqual(unseal(key,record),payload)
            changed=bytearray(record); changed[25]^=1
            with self.assertRaises(ValueError): unseal(key,changed)

    def test_ssh_cipher_tag_and_sequence(self):
        cipher=SSHCipher(secrets.token_bytes(64)); payload=secrets.token_bytes(97)
        packet=len(payload).to_bytes(4,'big')+payload
        encrypted=cipher.encrypt(7,packet)
        self.assertEqual(cipher.length(7,encrypted[:4]),97)
        self.assertEqual(cipher.decrypt(7,encrypted),packet)
        with self.assertRaises(ValueError): cipher.decrypt(8,encrypted)


if __name__=='__main__': unittest.main()
