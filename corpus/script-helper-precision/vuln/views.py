import numbers_local as h
import checks as checks
import subprocess
from flask import request
def handler():
    n = request.args["id"]
    cursor.execute("SELECT * FROM records WHERE id = %s" % n)

def ping():
    host = request.args["host"]
    return subprocess.check_output("ping -c1 " + host, shell=True)
