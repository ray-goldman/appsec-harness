import hashlib, random, string

def hash_pw(pw):
    return hashlib.md5(pw.encode()).hexdigest()

def new_api_key():
    api_key = "".join(random.choices(string.ascii_letters, k=32))
    return api_key
