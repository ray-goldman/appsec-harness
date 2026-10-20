import os
from flask import request

def lookup():
    domain = request.args.get("domain")
    os.system("nslookup " + domain)
