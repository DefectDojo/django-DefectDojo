import hashlib
import random


def weak_hash(value):
    return hashlib.md5(value.encode()).hexdigest()


def weak_sha(value):
    return hashlib.sha1(value.encode()).hexdigest()


def weak_token():
    return random.random()
