import os
from flask import request, redirect
from django.utils.http import url_has_allowed_host_and_scheme

def after_login():
    nxt = request.args.get("next", "/")
    return redirect(nxt if url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.host}) else "/")

def save(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
    os.write(fd, data.encode())
