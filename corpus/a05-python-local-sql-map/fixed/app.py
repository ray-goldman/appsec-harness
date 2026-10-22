from flask import Flask, request
app = Flask(__name__)

@app.route("/catalog")
def catalog():
    key = request.args.get("sort", "price")
    choices = {"price": "price ASC", "size": "size DESC"}
    order = choices.get(key, "price ASC")
    query = f"SELECT * FROM listings ORDER BY {order}"
    cursor.execute(query)
