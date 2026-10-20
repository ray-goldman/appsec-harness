import requests
from flask import Flask, request, abort
app = Flask(__name__)
TARGETS = {"slack": "https://hooks.slack.example/endpoint", "ops": "https://ops.example.net/hook"}

@app.post("/test-webhook")
def test_webhook():
    url = TARGETS.get(request.json.get("target"))
    if url is None:
        abort(400)
    r = requests.post(url, json={"ping": True}, timeout=5)
    return {"status": r.status_code}
