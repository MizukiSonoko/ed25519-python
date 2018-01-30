#! /usr/bin/python 
from ctypes import *
import os
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


def _unpack(byte_string, length):
    return struct.unpack('<{length}s'.format(length=length), byte_string)[0]

def _encode(byte_string, length=32):
    return base64.b64encode(_unpack(byte_string, length))

def _malloc_ubytes(length):
    value = (c_ubyte * length)()
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
    message, pointer_of_message = _malloc_ubytes_from_bytes(message)
    private_key, pointer_of_private_key = _malloc_ubytes_from_bytes(base64.b64decode(base64_private_key))
    public_key, pointer_of_public_key = _malloc_ubytes_from_bytes(base64.b64decode(base64_public_key))
    signature, pointer_of_signature = _malloc_ubytes(64)


    libed2559.ed25519_sign.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte), c_long, POINTER(c_ubyte), POINTER(c_ubyte)]
    libed2559.ed25519_sign(
        pointer_of_signature,
        pointer_of_message,
        len(message),
        pointer_of_private_key,
        pointer_of_public_key
    )
    return _encode(signature, length=64)

def verify(message, base64_signature, base64_public_key):
    message, pointer_of_message = _malloc_ubytes_from_bytes(message)
    public_key, pointer_of_public_key = _malloc_ubytes_from_bytes(base64.b64decode(base64_public_key))
    signature, pointer_of_signature = _malloc_ubytes_from_bytes(base64.b64decode(base64_signature))

    libed2559.ed25519_verify.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte), c_long, POINTER(c_ubyte)]
    return libed2559.ed25519_verify(
            pointer_of_signature,
            pointer_of_message,
        len(message),
        pointer_of_public_key
    )

def sha3_256(message):
    res, pointer_of_res = _malloc_ubytes(32)
    libed2559.ed25519_verify.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte), c_long]
    libed2559.sha256(
        pointer_of_res,
        _malloc_ubytes_from_bytes(message)[1],
        len(message)
    )
    return _unpack(res, 32)

def sha3_512(message):
    res, pointer_of_res = _malloc_ubytes(64)
    libed2559.ed25519_verify.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte), c_long]
    libed2559.sha512(
        pointer_of_res,
        _malloc_ubytes_from_bytes(message)[1],
        len(message)
    )
    return _unpack(res, 64)

