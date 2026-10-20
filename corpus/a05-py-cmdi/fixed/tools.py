import subprocess
from flask import request

def lookup():
    domain = request.args.get("domain", "")
    subprocess.run(["nslookup", "--", domain], check=False, timeout=5)
