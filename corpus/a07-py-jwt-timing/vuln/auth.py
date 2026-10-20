import jwt
from flask import request

def claims(token):
    return jwt.decode(token, options={"verify_signature": False})

def internal_ok(expected_token):
    if expected_token == request.headers.get("X-Token"):
        return True
    return False
