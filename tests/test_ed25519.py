from ed25519_python.ed25519 import generate, derive_public_key, sign, verify, sha3_256, sha3_512
from base64 import b64decode, b64encode
import struct


def test_generate():
    public_key, private_key = generate()
    assert len(b64decode(public_key)) == 32
    assert len(b64decode(private_key)) == 32
    print(b64decode(public_key))
    print(b64decode(private_key))


def test_derive_public_key():
    public_key, private_key = generate()
    for _ in range(1000):
        assert derive_public_key(private_key) == public_key


def test_sign():
    message = b"deadbeef"
    public_key, private_key = generate()

    signature = sign(message, public_key, private_key)
    print(b64decode(signature))
    assert len(b64decode(signature)) == 64

    for _ in range(1000):
        assert signature == sign(message, public_key, private_key)


def test_iroha_verify():
    message = "7d4e3eec80026719639ed4dba68916eb94c7a49a053e05c8f9578fe4e5a3d7ea"
    public_key = '359f925e4eeecfdd6aa1abc0b79a6a121a5dd63bb612b603247ea4f8ad160156'
    signature = '62fb363de8785e5cee29c64222c7a558ce8b2ca6f7efac1bb2ac2feabfc240ff03e1538afc1a087856a8f7225c0b8ff2bc6471c77ea29290cc5040ee30d55c0c'

    message = struct.pack('<32s', message)
    public_key = b64encode(struct.pack('<32s', public_key))
    signature = b64encode(struct.pack('<64s', signature))

    assert sign(message, public_key, signature)


def test_verify():
    message = b"deadbeef"
    public_key, private_key = generate()
    signature = sign(message, public_key, private_key)

    assert verify(message, signature, public_key)
    assert type(verify(message, signature, public_key)) is bool
    assert verify(message + b'dummy', signature, public_key) is False


def test_hash():
    assert len(set([sha3_256(b'deadbeef') for _ in range(10000)])) == 1
    assert len(sha3_256(b'deadbeef')) == 32
    assert len(set([sha3_512(b'deadbeef') for _ in range(10000)])) == 1
    assert len(sha3_512(b'deadbeef')) == 64
    print(sha3_256(b'deadbeef'))
    print(sha3_512(b'deadbeef'))
