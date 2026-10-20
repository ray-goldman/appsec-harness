import base64, pickle
from flask import request

def load_state():
    return pickle.loads(base64.b64decode(request.cookies["state"]))
