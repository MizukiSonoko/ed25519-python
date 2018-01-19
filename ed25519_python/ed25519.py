#! /usr/bin/python

from ctypes import *
import base64

# ToDo change find & load
libed2559 = cdll.LoadLibrary('lib/ed25519/libed25519.so')

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

if __name__ == "__main__":
    message = b"c0a5cca43b8aa79eb50e3464bc839dd6fd414fae0ddf928ca23dcebf8a8b8dd0"
    pub, pri = generate()
    signatureb = sign(message, pub, pri)
    print(1 == verify(
        message,
        signatureb,
        pub
    ))
