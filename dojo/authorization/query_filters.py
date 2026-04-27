_AUTH_FILTER_REGISTRY = {}


def register_auth_filter(key, func):
    _AUTH_FILTER_REGISTRY[key] = func


def get_auth_filter(key):
    return _AUTH_FILTER_REGISTRY.get(key)
