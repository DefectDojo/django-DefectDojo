_AUTH_FILTER_REGISTRY = {}


def register_auth_filter(key, func, *, override=False):
    # Defaults register without override and never clobber an existing entry.
    # Plugins replacing a default (e.g. Pro's RBAC implementations) must pass
    # override=True. This makes the wiring order-independent: regardless of
    # which AppConfig.ready() runs first, the explicit-override side wins.
    if key in _AUTH_FILTER_REGISTRY and not override:
        return
    _AUTH_FILTER_REGISTRY[key] = func


def get_auth_filter(key):
    return _AUTH_FILTER_REGISTRY.get(key)
