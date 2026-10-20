import numbers_local as h
import checks as checks
import subprocess
from flask import request
def handler():
    n = h.to_id(request.args["id"])
    cursor.execute("SELECT * FROM records WHERE id = %d" % n)

def ping():
    host = request.args["host"]
    if not checks.allowed(host):
        return "bad", 400
    return subprocess.check_output("ping -c1 " + host, shell=True)
