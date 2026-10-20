from flask import request

def create():
    user = User(**request.json)
    db.session.add(user)
