import requests
from flask import Flask, request
app = Flask(__name__)

@app.post("/test-webhook")
def test_webhook():
    url = request.json["url"]
    r = requests.post(url, json={"ping": True}, timeout=5)
    return {"status": r.status_code}
