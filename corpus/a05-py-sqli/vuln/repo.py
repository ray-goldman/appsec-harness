from flask import request

def find_user(cur):
    username = request.args["u"]
    cur.execute(f"SELECT * FROM users WHERE username = '{username}'")
    return cur.fetchone()
