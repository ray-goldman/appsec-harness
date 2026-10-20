import re

def allowed(value):
    return re.fullmatch(r"[A-Za-z0-9.-]{1,253}", value) is not None
