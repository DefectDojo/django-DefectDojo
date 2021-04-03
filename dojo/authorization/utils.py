from functools import lru_cache, wraps
from datetime import datetime, timedelta
from django.conf import settings


# Implementation taken from https://realpython.com/lru-cache-python/
def ttl_lru_cache(ttl=settings.AUTHORIZATION_CACHE_TTL, maxsize=settings.AUTHORIZATION_CACHE_MAXSIZE):
    def wrapper_cache(func):
        func = lru_cache(maxsize=maxsize)(func)
        func.lifetime = timedelta(seconds=ttl)
        func.expiration = datetime.utcnow() + func.lifetime

        @wraps(func)
        def wrapped_func(*args, **kwargs):
            if datetime.utcnow() >= func.expiration:
                func.cache_clear()
                func.expiration = datetime.utcnow() + func.lifetime
            return func(*args, **kwargs)

        return wrapped_func

    return wrapper_cache
