"""Python cryptographic operations. No constant-time guarantee is made."""
import hashlib
import hmac
import secrets
import struct


def hkdf(key, info=b"", length=32, salt=b""):
    if not 0 < length <= 255 * 32:
        raise ValueError("Invalid HKDF length")
    prk = hmac.digest(salt or bytes(32), key, "sha256")
    previous, output = b"", b""
    for i in range(1, (length + 31) // 32 + 1):
        previous = hmac.digest(prk, previous + info + bytes([i]), "sha256")
        output += previous
    return output[:length]


def expand_arbitrary_element_seed(seed, length):
    return hkdf(seed, b"SPAKE2 arbitrary element", length)


def x25519(secret, public=b"\x09" + bytes(31)):
    if len(secret) != 32 or len(public) != 32:
        raise ValueError("X25519 keys must be 32 bytes")
    p = 2**255 - 19
    k = int.from_bytes(secret, "little") & ((1 << 254) - 8) | 1 << 254
    x1 = int.from_bytes(public, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for bit in range(254, -1, -1):
        current = (k >> bit) & 1
        swap ^= current
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = current
        a, b = (x2 + z2) % p, (x2 - z2) % p
        aa, bb = a*a % p, b*b % p
        e = (aa - bb) % p
        c, d = (x3 + z3) % p, (x3 - z3) % p
        da, cb = d*a % p, c*b % p
        x3, z3 = (da + cb)**2 % p, x1*(da - cb)**2 % p
        x2, z2 = aa*bb % p, e*(aa + 121665*e) % p
    if swap: x2, z2 = x3, z3
    result = (x2 * pow(z2, p-2, p) % p).to_bytes(32, "little")
    if result == bytes(32): raise ValueError("Invalid X25519 shared secret")
    return result


def _point(data):
    from .edwards import bytes_to_element, NotOnCurve
    if len(data) != 32 or (int.from_bytes(data, "little") & ((1 << 255)-1)) >= 2**255-19:
        raise ValueError("Noncanonical Edwards point")
    try: point = bytes_to_element(data)
    except NotOnCurve as exc: raise ValueError("Invalid Edwards point") from exc
    if point.to_bytes() != data: raise ValueError("Noncanonical Edwards point")
    return point


def public_key(seed):
    from .edwards import Base, bytes_to_clamped_scalar
    if len(seed) != 32: raise ValueError("Ed25519 seed must be 32 bytes")
    return Base.scalarmult(bytes_to_clamped_scalar(hashlib.sha512(seed).digest()[:32])).to_bytes()


def sign(seed, message):
    from .edwards import Base, L, bytes_to_clamped_scalar
    hashed = hashlib.sha512(seed).digest()
    scalar = bytes_to_clamped_scalar(hashed[:32])
    public = Base.scalarmult(scalar).to_bytes()
    r = int.from_bytes(hashlib.sha512(hashed[32:] + message).digest(), "little") % L
    encoded_r = Base.scalarmult(r).to_bytes()
    challenge = int.from_bytes(hashlib.sha512(encoded_r + public + message).digest(), "little") % L
    return encoded_r + ((r + challenge*scalar) % L).to_bytes(32, "little")


def verify(public, message, signature):
    from .edwards import Base, L
    try:
        if len(signature) != 64: return False
        s = int.from_bytes(signature[32:], "little")
        if s >= L: return False
        a, r = _point(public), _point(signature[:32])
        h = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % L
        return hmac.compare_digest(Base.scalarmult(s).to_bytes(), r.add(a.scalarmult(h)).to_bytes())
    except (ValueError, AssertionError):
        return False


def _rotate(x, n):
    return ((x << n) | (x >> (32-n))) & 0xffffffff


def _chacha_round(x, a, b, c, d):
    x[a] = (x[a]+x[b]) & 0xffffffff; x[d] = _rotate(x[d]^x[a], 16)
    x[c] = (x[c]+x[d]) & 0xffffffff; x[b] = _rotate(x[b]^x[c], 12)
    x[a] = (x[a]+x[b]) & 0xffffffff; x[d] = _rotate(x[d]^x[a], 8)
    x[c] = (x[c]+x[d]) & 0xffffffff; x[b] = _rotate(x[b]^x[c], 7)


def chacha(key, nonce, length, counter=0):
    if len(key) != 32 or len(nonce) != 8: raise ValueError("Invalid SSH ChaCha key/nonce")
    words = list(struct.unpack("<12I", b"expand 32-byte k" + key))
    output = bytearray()
    for count in range(counter, counter + (length+63)//64):
        original = words + [count & 0xffffffff, count >> 32] + list(struct.unpack("<2I", nonce))
        x = original.copy()
        for _ in range(10):
            for indices in ((0,4,8,12),(1,5,9,13),(2,6,10,14),(3,7,11,15),(0,5,10,15),(1,6,11,12),(2,7,8,13),(3,4,9,14)):
                _chacha_round(x, *indices)
        output += struct.pack("<16I", *((a+b)&0xffffffff for a,b in zip(x,original)))
    return bytes(output[:length])


def _salsa_round(x, a, b, c, d):
    x[b] ^= _rotate((x[a]+x[d]) & 0xffffffff, 7)
    x[c] ^= _rotate((x[b]+x[a]) & 0xffffffff, 9)
    x[d] ^= _rotate((x[c]+x[b]) & 0xffffffff, 13)
    x[a] ^= _rotate((x[d]+x[c]) & 0xffffffff, 18)


def _salsa_state(key, middle):
    k = struct.unpack("<8I", key); c = struct.unpack("<4I", b"expand 32-byte k")
    return [c[0], *k[:4], c[1], *struct.unpack("<4I", middle), c[2], *k[4:], c[3]]


def _salsa_permute(original):
    x = original.copy()
    for _ in range(10):
        for indices in ((0,4,8,12),(5,9,13,1),(10,14,2,6),(15,3,7,11),(0,1,2,3),(5,6,7,4),(10,11,8,9),(15,12,13,14)):
            _salsa_round(x, *indices)
    return x


def xsalsa(key, nonce, length):
    if len(key) != 32 or len(nonce) != 24: raise ValueError("Invalid SecretBox key/nonce")
    x = _salsa_permute(_salsa_state(key, nonce[:16]))
    subkey = struct.pack("<8I", *(x[i] for i in (0,5,10,15,6,7,8,9)))
    result = bytearray()
    for count in range((length+63)//64):
        original = _salsa_state(subkey, nonce[16:] + count.to_bytes(8, "little"))
        x = _salsa_permute(original)
        result += struct.pack("<16I", *((a+b)&0xffffffff for a,b in zip(x,original)))
    return bytes(result[:length])


def poly1305(key, message):
    r = int.from_bytes(key[:16], "little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key[16:], "little")
    acc = 0
    for start in range(0, len(message), 16):
        acc = (acc + int.from_bytes(message[start:start+16] + b"\1", "little")) * r % (2**130-5)
    return ((acc+s) % 2**128).to_bytes(16, "little")


def xor(a, b): return bytes(x ^ y for x,y in zip(a,b,strict=True))


def seal(key, plaintext, nonce=None):
    nonce = nonce or secrets.token_bytes(24)
    stream = xsalsa(key, nonce, len(plaintext)+32)
    encrypted = xor(plaintext, stream[32:])
    return nonce + poly1305(stream[:32], encrypted) + encrypted


def unseal(key, record):
    if len(record) < 40: raise ValueError("Truncated SecretBox")
    nonce, tag, encrypted = record[:24], record[24:40], record[40:]
    auth = xsalsa(key, nonce, 32)
    if not hmac.compare_digest(tag, poly1305(auth, encrypted)):
        raise ValueError("SecretBox authentication failed")
    return xor(encrypted, xsalsa(key, nonce, len(encrypted)+32)[32:])


class SSHCipher:
    def __init__(self, key):
        if len(key) != 64: raise ValueError("SSH AEAD requires 64 bytes")
        self.key = key

    def length(self, seq, header):
        return int.from_bytes(xor(header, chacha(self.key[32:], seq.to_bytes(8,"big"), 4)), "big")

    def encrypt(self, seq, packet):
        nonce = seq.to_bytes(8,"big")
        encrypted = xor(packet[:4], chacha(self.key[32:], nonce, 4)) + xor(packet[4:], chacha(self.key[:32], nonce, len(packet)-4, 1))
        return encrypted + poly1305(chacha(self.key[:32], nonce, 32), encrypted)

    def decrypt(self, seq, packet):
        nonce = seq.to_bytes(8,"big")
        encrypted, tag = packet[:-16], packet[-16:]
        if not hmac.compare_digest(tag, poly1305(chacha(self.key[:32], nonce, 32), encrypted)):
            raise ValueError("SSH packet authentication failed")
        return xor(encrypted[:4], chacha(self.key[32:], nonce, 4)) + xor(encrypted[4:], chacha(self.key[:32], nonce, len(encrypted)-4, 1))


class SPAKE:
    """Used symmetric python-spake2 mode, with stdlib HKDF and no persistence."""
    def __init__(self, password, identity, entropy=secrets.token_bytes):
        from .edwards import Base, L, arbitrary_element, random_scalar
        self.password, self.identity = password, identity
        self.scalar = random_scalar(entropy)
        self.pw = int.from_bytes(hkdf(password, b"SPAKE2 pw", 48), "big") % L
        self.blinding = arbitrary_element(b"symmetric")
        self.outbound = Base.scalarmult(self.scalar).add(self.blinding.scalarmult(self.pw)).to_bytes()
        self.finished = False

    def start(self): return b"S" + self.outbound

    def finish(self, message):
        if self.finished: raise ValueError("SPAKE exchange already finished")
        self.finished = True
        if len(message) != 33 or message[:1] != b"S" or message[1:] == self.outbound:
            raise ValueError("Invalid or reflected SPAKE message")
        inbound = _point(message[1:])
        shared = inbound.add(self.blinding.scalarmult(-self.pw)).scalarmult(self.scalar)
        from .edwards import Zero
        if shared == Zero: raise ValueError("Invalid SPAKE result")
        first, second = sorted((message[1:], self.outbound))
        return hashlib.sha256(hashlib.sha256(self.password).digest() + hashlib.sha256(self.identity).digest() + first + second + shared.to_bytes()).digest()
