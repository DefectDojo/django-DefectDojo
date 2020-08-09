from hashlib import md5
from json import dumps

def create_dedupe_key(check_id='', path='', start='', end=''):
    try:
        if not all([check_id, path, start, end]):
            return None

        raw_bytes = (check_id + path + start + end).encode('utf-8')
        return md5(raw_bytes).hexdigest()

    except Exception as err:
        return None


def format_code(code):
    try:
        return str(code)

    except Exception as err:
        return None


def format_linenums(linenums={}):
    try:
        if not isinstance(linenums, dict):
            return None

        return ' '.join([f"{k}: {linenums[k]}" for k in linenums])

    except Exception as err:
        return None


def format_message(message=()):
    try:
        if not isinstance(message, list):
            return None

        return ''.join(message)
    except Exception as err:
        return None


def format_metavars(metavars={}):
    try:
        if not isinstance(metavars, dict):
            return None
        
        return dumps(metavars)

    except Exception as err:
        return None

def format_references(references=()):
    if not isinstance(message, list):
        return None

    return ''.join(message)
