import base64, json
from flask import request

def load_state():
    return json.loads(base64.b64decode(request.cookies.get("state", "e30=")))
