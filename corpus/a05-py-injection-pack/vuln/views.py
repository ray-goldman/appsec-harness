from flask import request
from markupsafe import Markup

def search(cur):
    sql = f"SELECT * FROM items WHERE name = '{request.args['n']}'"
    return sql

def badge(name):
    return Markup(f"<b>{name}</b>")

def echo():
    return f"<h1>{request.args.get('q')}</h1>"

def find(conn):
    return conn.search_s(BASE, 2, f"(uid={request.form['u']})")
