from flask import request

def create():
    data = request.json
    user = User(name=str(data["name"]), email=str(data["email"]))
    db.session.add(user)
