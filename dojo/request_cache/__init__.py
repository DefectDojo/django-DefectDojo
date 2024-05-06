from crum import get_current_request

# Attribution: This code has been taken from https://github.com/anexia-it/django-request-cache, which has
# been published under the MIT License. Since this project hasn't been updated for more than a year,
# the code has been copied to DefectDojo, to be able to fix issues ourselves.


def get_request_cache():
    """
    Return the current requests cache
    :return:
    """
    return getattr(get_current_request(), "cache", None)


cache_args_kwargs_marker = object()  # marker for separating args from kwargs (needs to be global)


def cache_calculate_key(*args, **kwargs):
    """
    Calculate the cache key of a function call with args and kwargs
    Taken from lru_cache
    :param args:
    :param kwargs:
    :return: the calculated key for the function call
    :rtype: basestring
    """
    # combine args with kwargs, separated by the cache_args_kwargs_marker
    key = args + (cache_args_kwargs_marker,) + tuple(sorted(kwargs.items()))
    # return as a string
    return str(key)


def cache_for_request(fn):
    """
    Decorator that allows to cache a function call with parameters and its result only for the current request
    The result is stored in the memory of the current process
    As soon as the request is destroyed, the cache is destroyed
    :param fn:
    :return:
    """
    def wrapper(*args, **kwargs):
        cache = get_request_cache()

        if not cache:
            # no cache found -> directly execute function without caching
            return fn(*args, **kwargs)

        # cache found -> check if a result is already available for this function call
        key = cache_calculate_key(fn.__name__, *args, **kwargs)

        try:
            result = getattr(cache, key)
        except AttributeError:
            # no result available -> execute function
            result = fn(*args, **kwargs)
            setattr(cache, key, result)

        return result
    return wrapper
