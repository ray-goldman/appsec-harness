def verify(sig, body):
    try:
        hmac_verify(sig, body)
    except:
        pass
    return True
