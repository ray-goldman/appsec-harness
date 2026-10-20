from flask import jsonify

def handler():
    try:
        return do_work()
    except Exception as e:
        return jsonify({"error": str(e)}), 500
