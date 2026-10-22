from flask import Flask, request, render_template
app = Flask(__name__)

@app.route("/catalog")
def catalog():
    badge = ""
    if request.args.get("kind") == "gold":
        badge = "<b>Gold</b>"
    else:
        badge = "<b>Standard</b>"
    return render_template("catalog.html", badge=badge)
