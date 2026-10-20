import hashlib, os, secrets

def hash_pw(pw):
    salt = os.urandom(16)
    return salt + hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1)

def new_api_key():
    return secrets.token_urlsafe(32)
