from flask import request

def find_user(cur):
    cur.execute("SELECT * FROM users WHERE username = %s", (request.args["u"],))
    return cur.fetchone()
