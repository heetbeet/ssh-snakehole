import secrets
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ssh_snakehole._crypto import SPAKE,SSHCipher,public_key,seal,sign,unseal,verify,x25519
from spake2 import SPAKE2_Symmetric
from nacl.secret import SecretBox
from cryptography.hazmat.primitives.asymmetric import ed25519,x25519 as reference_x
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from asyncssh.crypto.chacha import ChachaCipher

for i in range(10):
    seed=secrets.token_bytes(32); data=secrets.token_bytes(i*100+1)
    ref=ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    assert ref.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)==public_key(seed)
    assert ref.sign(data)==sign(seed,data)
    assert verify(public_key(seed),data,ref.sign(data))
    refx=reference_x.X25519PrivateKey.from_private_bytes(seed)
    assert refx.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)==x25519(seed)
    key,nonce=secrets.token_bytes(32),secrets.token_bytes(24)
    assert seal(key,data,nonce)==bytes(SecretBox(key).encrypt(data,nonce))
    assert unseal(key,bytes(SecretBox(key).encrypt(data,nonce)))==data
    a,b=SPAKE(b'42-code',b'app'),SPAKE2_Symmetric(b'42-code',idSymmetric=b'app')
    assert a.finish(b.start())==b.finish(a.start())
    key=secrets.token_bytes(64); packet=len(data).to_bytes(4,'big')+data
    cipher=ChachaCipher(key)
    encrypted,tag=cipher.encrypt_and_sign(packet[:4],data,i.to_bytes(8,'big'))
    assert SSHCipher(key).encrypt(i,packet)==encrypted+tag
print('Independent Ed25519, X25519, SPAKE2, SecretBox and OpenSSH cipher comparisons passed')
