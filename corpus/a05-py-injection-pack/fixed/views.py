from flask import request, render_template
from markupsafe import Markup
from ldap3.utils.conv import escape_filter_chars

def search(cur):
    cur.execute("SELECT * FROM items WHERE name = %s", (request.args["n"],))
    return cur.fetchall()

def badge(name):
    return Markup("<b>{}</b>").format(name)

def echo():
    return render_template("q.html", q=request.args.get("q"))

def find(conn):
    return conn.search_s(BASE, 2, "(uid=%s)" % escape_filter_chars(request.form["u"]))
