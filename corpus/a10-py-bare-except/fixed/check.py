import logging

def verify(sig, body):
    try:
        hmac_verify(sig, body)
    except InvalidSignature:
        logging.warning("bad signature")
        return False
    return True
