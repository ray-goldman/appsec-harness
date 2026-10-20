import requests

def get_profile(token):
    return requests.get("https://idp.example.com/me", headers={"Authorization": token}, verify="/etc/ssl/private-ca.pem", timeout=5).json()
