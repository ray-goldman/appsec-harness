from flask import Flask, request, send_from_directory
app = Flask(__name__)
BASE = "/srv/reports"

@app.route("/report")
def report():
    return send_from_directory(BASE, request.args.get("name", ""))
