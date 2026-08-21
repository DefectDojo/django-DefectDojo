import hashlib


def fingerprint(value):
    return hashlib.md5(value.encode()).hexdigest()
