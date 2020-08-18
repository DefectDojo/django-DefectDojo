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
    return _format_by_type(input=code)


def format_linenums(linenums):
    return _format_by_type(input=linenums)


def format_message(message):
    return _format_by_type(input=message)


def format_metavars(metavars):
    try:
        if not isinstance(metavars, dict):
            return None
        
        return dumps(metavars)

    except Exception as err:
        return None

def format_references(references=()):
    return _format_by_type(input=references)


def _format_by_type(input='', separator=' '):
    try:
        if isinstance(input, str):
            return input

        if isinstance(input, list):
            return separator.join(input)

        if isinstance(input, dict):
            return separator.join([f"{k}: {input[k]}" for k in input])

    except Exception as err:
        return None
