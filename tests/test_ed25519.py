from ed25519_python.ed25519 import generate, derive_public_key, sign, verify, sha3_256, sha3_512
from base64 import b64decode

def test_generate():
    public_key, private_key = generate()
    assert len(b64decode(public_key)) == 32
    assert len(b64decode(private_key)) == 32
    print(b64decode(public_key))
    print(b64decode(private_key))

def test_derive_public_key():
    public_key, private_key = generate()
    for i in range(1000):
        assert derive_public_key(private_key) == public_key


def test_sign():
    message = b"deadbeef"
    public_key, private_key = generate()

    signature = sign(message, public_key, private_key)
    print(b64decode(signature))
    assert len(b64decode(signature)) == 64

    for i in range(1000):
        assert signature == sign(message, public_key, private_key)

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
