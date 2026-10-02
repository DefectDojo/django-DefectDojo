import threading

from crum import get_current_request, get_current_user

# Attribution: This code has been taken from https://github.com/anexia-it/django-request-cache, which has
# been published under the MIT License. Since this project hasn't been updated for more than a year,
# the code has been copied to DefectDojo, to be able to fix issues ourselves.


def get_request_cache():  # noqa: RUF067
    """
    Return the current requests cache
    :return:
    """
    return getattr(get_current_request(), "cache", None)


class _TaskCache:  # noqa: RUF067

    """
    Attribute-bag cache with the same access pattern as ``RequestCache`` (values
    stored via ``setattr``/``getattr`` on the instance), used inside a Celery task
    when there is no request. A fresh instance is installed at each task boundary
    (see ``begin_task_cache``), so it can never outlive one task.
    """


# Per-thread task cache. Only populated between ``begin_task_cache`` and
# ``end_task_cache`` (called by DojoAsyncTask around each task). ``None`` outside a
# task, so management commands / shells that never hit a task boundary do NOT cache
# (a cache with no reset boundary would grow unbounded and serve stale data).
_task_cache_local = threading.local()  # noqa: RUF067


def get_task_cache():  # noqa: RUF067
    """Return the current task's cache, or ``None`` when not inside a task."""
    return getattr(_task_cache_local, "cache", None)


def begin_task_cache():  # noqa: RUF067
    """
    Install a fresh task cache. Called at the START of every task so a task never
    inherits a cache populated by a prior task on the same (reused) worker thread.
    """
    _task_cache_local.cache = _TaskCache()


def end_task_cache():  # noqa: RUF067
    """
    Drop the task cache. Called at the END of every task so nothing lingers on the
    thread after the task completes.
    """
    _task_cache_local.cache = None


cache_args_kwargs_marker = object()  # noqa: RUF067 marker for separating args from kwargs (needs to be global)


def cache_calculate_key(*args, **kwargs):  # noqa: RUF067
    """
    Calculate the cache key of a function call with args and kwargs
    Taken from lru_cache
    :param args:
    :param kwargs:
    :return: the calculated key for the function call
    :rtype: basestring
    """
    # combine args with kwargs, separated by the cache_args_kwargs_marker
    key = (*args, cache_args_kwargs_marker, *tuple(sorted(kwargs.items())))
    # return as a string
    return str(key)


def cache_for_request(fn):  # noqa: RUF067
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


def cache_for_request_or_task(fn):  # noqa: RUF067
    """
    Like ``cache_for_request``, but also caches inside a Celery task (which has no
    request). Resolves the store as: request cache if a request exists, else the
    task cache if inside a task, else no caching (executes directly).

    SECURITY: the cache key folds in the *effective* current user
    (``get_current_user().pk``) so that user-dependent results (e.g. authorized
    querysets that resolve ``user`` downstream and would otherwise key on
    ``user=None``) cannot leak between users. This matters in tasks: a worker
    thread is reused across tasks and ``DojoAsyncTask`` impersonates a different
    user per task, and a single task can impersonate multiple users (e.g. the
    rules engine under ``impersonate(rule.owner)``). The per-task reset
    (begin/end) bounds staleness (e.g. revoked permissions); the user-aware key
    guarantees isolation even within a task.
    """
    def wrapper(*args, **kwargs):
        cache = get_request_cache()
        if cache is None:
            cache = get_task_cache()          # populated only inside a DojoAsyncTask
        if cache is None:
            # neither a request nor a task -> execute without caching
            return fn(*args, **kwargs)

        user = get_current_user()
        user_pk = user.pk if user is not None else None
        key = cache_calculate_key(fn.__name__, user_pk, *args, **kwargs)

        try:
            result = getattr(cache, key)
        except AttributeError:
            result = fn(*args, **kwargs)
            setattr(cache, key, result)

        return result
    return wrapper
