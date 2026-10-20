import logging, uuid
from flask import jsonify

def handler():
    try:
        return do_work()
    except Exception:
        ref = uuid.uuid4().hex
        logging.exception("handler failed ref=%s", ref)
        return jsonify({"error": "internal error", "ref": ref}), 500
