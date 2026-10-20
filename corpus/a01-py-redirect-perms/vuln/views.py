import os
from flask import request, redirect

def after_login():
    return redirect(request.args.get("next"))

def save(path, data):
    open(path, "w").write(data)
    os.chmod(path, 0o777)
