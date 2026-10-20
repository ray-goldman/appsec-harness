import os
from flask import Flask, request
app = Flask(__name__)
BASE = "/srv/reports"

@app.route("/report")
def report():
    name = request.args.get("name")
    with open(os.path.join(BASE, name)) as fh:
        return fh.read()
