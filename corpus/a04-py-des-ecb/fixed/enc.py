import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def enc(key, data):
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, None)
