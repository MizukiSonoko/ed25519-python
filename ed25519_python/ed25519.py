#! /usr/bin/python
import os
from ctypes import *
import ctypes
import ctypes.util
import base64
import binascii

# ToDo change use `ctypes.util.find_library`
libed2559 = None
try:
    libed2559 = cdll.LoadLibrary('./libed25519.so')
except OSError:
    pass
try:
    libed2559 = cdll.LoadLibrary('./libed25519.dylib')
except OSError:
    pass
if not libed2559:
    print("Library loading failed")

def generate():
    public_key = POINTER(c_ubyte)((c_ubyte * 32)())
    private_key = POINTER(c_ubyte)((c_ubyte * 32)())
    libed2559.ed25519_create_keypair.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte)]
    libed2559.ed25519_create_keypair(private_key,public_key)

    publist = []
    for i in range(32):
        publist.append(public_key[i])
    publicKey64 = base64.b64encode(bytes(publist))

    prilist = []
    for i in range(32):
        prilist.append(private_key[i])
    privateKey64 = base64.b64encode(bytes(prilist))

    return (publicKey64, privateKey64)

def sign(message, public, private):
    signature = POINTER(c_ubyte)((c_ubyte * 64)())
    libed2559.ed25519_sign.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte), c_long, POINTER(c_ubyte), POINTER(c_ubyte)]
    libed2559.ed25519_sign(
        signature,
        POINTER(c_ubyte)((c_ubyte * len(message)).from_buffer_copy(message)),
        len(message),
        POINTER(c_ubyte)((c_ubyte * len(base64.b64decode(public))).from_buffer_copy(base64.b64decode(public))),
        POINTER(c_ubyte)((c_ubyte * len(base64.b64decode(private))).from_buffer_copy(base64.b64decode(private)))
    )
    siglist = []
    for i in range(64):
        siglist.append(signature[i])
    return base64.b64encode(bytes(siglist))

def verify(message, signature, public):
    libed2559.ed25519_verify.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte), c_long, POINTER(c_ubyte)]
    return libed2559.ed25519_verify(
        POINTER(c_ubyte)((c_ubyte * len(base64.b64decode(signature))).from_buffer_copy(base64.b64decode(signature))),
        POINTER(c_ubyte)((c_ubyte * len(message)).from_buffer_copy(message)),
        len(message),
        POINTER(c_ubyte)((c_ubyte * len(base64.b64decode(public))).from_buffer_copy(base64.b64decode(public))),
    )

def sha3_256(message):
    res = POINTER(c_ubyte)((c_ubyte * 32)())
    libed2559.ed25519_verify.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte), c_long]
    libed2559.sha256(
        res,
        POINTER(c_ubyte)((c_ubyte * len(message)).from_buffer_copy(message)),
        len(message)
    )
    siglist = []
    for i in range(32):
        siglist.append(res[i])
    return binascii.hexlify(bytes(siglist))

def sha3_512(message):
    res = POINTER(c_ubyte)((c_ubyte * 128)())
    libed2559.ed25519_verify.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte), c_long]
    libed2559.sha256(
        res,
        POINTER(c_ubyte)((c_ubyte * len(message)).from_buffer_copy(message)),
        len(message)
    )
    siglist = []
    for i in range(128):
        siglist.append(res[i])
    return binascii.hexlify(bytes(siglist))

if __name__ == "__main__":
    message = bytearray.fromhex("7d4e3eec80026719639ed4dba68916eb94c7a49a053e05c8f9578fe4e5a3d7ea")
    pub_ = '359f925e4eeecfdd6aa1abc0b79a6a121a5dd63bb612b603247ea4f8ad160156'
    sig_ = '62fb363de8785e5cee29c64222c7a558ce8b2ca6f7efac1bb2ac2feabfc240ff03e1538afc1a087856a8f7225c0b8ff2bc6471c77ea29290cc5040ee30d55c0c'

    print(1 == verify(
        message,
        base64.b64encode(bytearray.fromhex(sig_)).decode(),
        base64.b64encode(bytearray.fromhex(pub_)).decode()
    ))

    account_id = "admin@test"
    #pub, pri = generate()

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

