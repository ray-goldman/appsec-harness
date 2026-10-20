from flask import request

def calc():
    return str(eval(request.args["expr"]))
