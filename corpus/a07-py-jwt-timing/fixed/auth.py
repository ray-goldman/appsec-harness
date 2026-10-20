import hmac, jwt
from flask import request

def claims(token, key):
    return jwt.decode(token, key, algorithms=["RS256"], audience="api")

def internal_ok(expected_token):
    return hmac.compare_digest(expected_token, request.headers.get("X-Token", ""))
