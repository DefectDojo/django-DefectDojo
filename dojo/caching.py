"""
Two-tier read-through cache for global, low-cardinality singleton config.

One in-process **L1** tier sits on top of the shared **L2** tier
(``django.core.cache``, Redis in deployments). A getter is resolved L1 → L2 → DB:
the first tier with a value wins; a ``None`` anywhere means "not cached, compute
it" and is never stored. This is deliberately simple — it is only for global,
user-INDEPENDENT, signal-invalidated singletons (feature flags, system settings,
and the like), never per-user or per-object data.

Values are stored as plain dicts/scalars (see ``model_to_cache_dict`` /
``cache_dict_to_model``), never pickled model instances.

Two independent tiers, each turned off by setting its TTL to ``-1`` (both off makes
the decorator a pass-through). Configuration (Django settings, wired from env in
``settings.dist.py``):

* ``SETTINGS_CACHE_L1_TTL`` — per-thread in-process freshness budget in seconds
  (``-1`` disables L1). Keep it short — it bounds cross-process staleness. L1 is
  reset at each request/task boundary, so it is effectively request/task scoped.
* ``SETTINGS_CACHE_L2_TTL`` — L2 timeout in seconds (``-1`` disables L2).
"""

import threading
import time
from functools import wraps

from django.conf import settings
from django.core.cache import cache


class _L1Store:

    """
    Per-thread in-process store, TTL-stamped. ``get`` returns the value or ``None``
    (absent, expired, or L1 disabled via ``SETTINGS_CACHE_L1_TTL`` < 0).

    Per-thread (not shared across threads) so it needs no locking, and is reset at
    each request/task boundary (see ``reset``) — making it effectively request/task
    scoped on a reused worker/uwsgi thread.
    """

    def __init__(self):
        self._local = threading.local()

    def _bucket(self):
        bucket = getattr(self._local, "b", None)
        if bucket is None:
            bucket = self._local.b = {}
        return bucket

    def get(self, key):
        if getattr(settings, "SETTINGS_CACHE_L1_TTL", 30) < 0:
            return None
        entry = self._bucket().get(key)
        if entry is None:
            return None
        value, expiry = entry
        if time.monotonic() >= expiry:
            self._bucket().pop(key, None)
            return None
        return value

    def set(self, key, value):
        ttl = getattr(settings, "SETTINGS_CACHE_L1_TTL", 30)
        if ttl < 0:
            return
        self._bucket()[key] = (value, time.monotonic() + ttl)

    def invalidate(self, key):
        # Only this thread; other threads/processes self-heal within the L1 TTL
        # (and reset at their next request/task boundary).
        self._bucket().pop(key, None)

    def reset(self):
        # Clear THIS thread's L1 bucket. Called at request/task boundaries so a
        # reused worker/uwsgi thread never serves a value cached during a prior
        # request or task (e.g. a since-changed System_Settings).
        self._bucket().clear()

    def clear(self):
        # Test helper: drop this thread's entries.
        self._local = threading.local()


_L1_STORE = _L1Store()


def dojo_settings_cache(*, key: str):
    """
    Read-through L1+L2 cache for a fixed-key singleton getter.

    Resolves L1 → L2 → wrapped function. A ``None`` result is treated as "no
    value" and is not cached (so the next call retries). Becomes a pass-through
    when both tiers are disabled (``SETTINGS_CACHE_L1_TTL=-1`` and
    ``SETTINGS_CACHE_L2_TTL=-1``).
    """

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            l2_ttl = getattr(settings, "SETTINGS_CACHE_L2_TTL", 300)
            l2_on = l2_ttl >= 0                      # SETTINGS_CACHE_L2_TTL == -1 disables L2

            value = _L1_STORE.get(key)              # ---- L1 ----
            if value is not None:
                return value

            if l2_on:                               # ---- L2 ----
                value = cache.get(key)
                if value is not None:
                    _L1_STORE.set(key, value)
                    return value

            value = fn(*args, **kwargs)             # ---- miss: compute ----
            if value is not None:
                if l2_on:
                    cache.set(key, value, timeout=l2_ttl)
                _L1_STORE.set(key, value)
            return value

        return wrapper

    return decorator


def invalidate_dojo_settings_cache(key: str) -> None:
    """Drop a cached singleton from L2 (all processes) and L1 (this process)."""
    cache.delete(key)
    _L1_STORE.invalidate(key)


def reset_l1_cache() -> None:
    """
    Reset the current thread's L1 tier.

    Call at request/task boundaries (reused worker/uwsgi threads) so the
    in-process L1 is effectively request/task-scoped and never serves a value
    cached during a prior request or task.
    """
    _L1_STORE.reset()


def model_to_cache_dict(instance) -> dict:
    """
    Flatten a model instance to a plain dict of concrete field values.

    Keyed by ``attname`` (so a relation ``foo`` becomes ``foo_id``) and includes
    the primary key. M2M and reverse relations are skipped. Storing this instead
    of the model instance keeps the cache free of pickled model graphs; rebuild a
    live instance with ``cache_dict_to_model``.
    """
    return {f.attname: f.value_from_object(instance) for f in instance._meta.concrete_fields}


def cache_dict_to_model(model_cls, data: dict):
    """
    Rebuild an in-memory model instance from a ``model_to_cache_dict`` dict.

    For read-only use; callers that persist changes must fetch a fresh DB instance
    rather than saving a cache-derived one.
    """
    return model_cls(**data)
