#! /usr/bin/python import os
from ctypes import *
import struct
import ctypes
import ctypes.util
import base64
import binascii

# ToDo change use `ctypes.util.find_library`
wd = os.path.dirname(os.path.abspath(__file__))
# ToDo change use `ctypes.util.find_library`
libed2559 = None
try:
    libed2559 = cdll.LoadLibrary('{}/libed25519.so'.format(wd))
except OSError:
    pass
try:
    libed2559 = cdll.LoadLibrary('{}/libed25519.dylib'.format(wd))
except OSError:
    pass
if not libed2559:
    print("Library loading failed")

def _encode(byte32_string):
    return base64.b64encode(struct.unpack('<32s', byte32_string)[0])

def _malloc_ubytes(length):
    value = (c_ubyte * 32)()
    pointer_of_value = POINTER(c_ubyte)(value)
    return value, pointer_of_value

def _malloc_ubytes_from_bytes(byte_string):
    value = (c_ubyte * len(byte_string)).from_buffer_copy(byte_string)
    pointer_of_value = POINTER(c_ubyte)(value)
    return value, pointer_of_value

def generate():
    public_key, pointer_of_public_key = _malloc_ubytes(32)
    private_key, pointer_of_private_key = _malloc_ubytes(32)
    libed2559.ed25519_create_keypair.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte)]
    libed2559.ed25519_create_keypair(pointer_of_private_key, pointer_of_public_key)
    return _encode(public_key),_encode(private_key)

def derive_public_key(base64_private_key):
    public_key, pointer_of_public_key = _malloc_ubytes(32)
    private_key, pointer_of_private_key = _malloc_ubytes_from_bytes(base64.b64decode(base64_private_key))
    libed2559.ed25519_derive_public_key.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte)]
    libed2559.ed25519_derive_public_key(pointer_of_private_key,pointer_of_public_key)
    return _encode(public_key)


def sign(message, base64_public_key, base64_private_key):
    signature, pointer_of_signature = _malloc_ubytes(64)
    libed2559.ed25519_sign.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte), c_long, POINTER(c_ubyte), POINTER(c_ubyte)]
    libed2559.ed25519_sign(
        pointer_of_signature,
        _malloc_ubytes_from_bytes(message)[1],
        len(message),
        _malloc_ubytes_from_bytes(base64.b64decode(base64_private_key))[1],
        _malloc_ubytes_from_bytes(base64.b64decode(base64_public_key))[1]
    )
    return _encode(signature)

def verify(message, base64_signature, base64_public_key):
    libed2559.ed25519_verify.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte), c_long, POINTER(c_ubyte)]
    return libed2559.ed25519_verify(
        _malloc_ubytes_from_bytes(base64.b64decode(base64_signature))[1],
        _malloc_ubytes_from_bytes(message)[1],
        len(message),
        _malloc_ubytes_from_bytes(base64.b64decode(base64_public_key))[1],
    )

def sha3_256(message):
    res, pointer_of_res = _malloc_ubytes(64)
    libed2559.ed25519_verify.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte), c_long]
    libed2559.sha256(
        pointer_of_res,
        _malloc_ubytes_from_bytes(message)[1],
        len(message)
    )
    return _encode(res)

def sha3_512(message):
    res, pointer_of_res = _malloc_ubytes(128)
    libed2559.ed25519_verify.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte), c_long]
    libed2559.sha512(
        pointer_of_res,
        _malloc_ubytes_from_bytes(message)[1],
        len(message)
    )
    return _encode(res)

message = bytearray.fromhex("7d4e3eec80026719639ed4dba68916eb94c7a49a053e05c8f9578fe4e5a3d7ea")
pub_ = '359f925e4eeecfdd6aa1abc0b79a6a121a5dd63bb612b603247ea4f8ad160156'
sig_ = '62fb363de8785e5cee29c64222c7a558ce8b2ca6f7efac1bb2ac2feabfc240ff03e1538afc1a087856a8f7225c0b8ff2bc6471c77ea29290cc5040ee30d55c0c'

print(1 == verify(
    message,
    base64.b64encode(bytearray.fromhex(sig_)).decode(),
    base64.b64encode(bytearray.fromhex(pub_)).decode()
))

account_id = "admin@test"
pub, pri = generate()


with open("{}/.irohac/{}.pub".format(os.environ['HOME'], account_id), "r") as pubKeyFile:
    publicKey = pubKeyFile.read()
with open("{}/.irohac/{}".format(os.environ['HOME'], account_id), "r") as priKeyFile:
    privateKey = priKeyFile.read()
print('pub:{}'.format(publicKey))
print('pri:{}'.format(privateKey))
pub = base64.b64encode(bytearray.fromhex(publicKey))
pri = base64.b64encode(bytearray.fromhex(privateKey))

signatureb = sign(message, pub, pri)
print("sig:")
print(1 == verify(
    message,
    signatureb,
    pub
))

pub, pri = generate()
print(message)
signatureb = sign(message, pub, pri)
print("sig:")
print(1 == verify(
    message,
    signatureb,
    pub
))

