"""
In-process read-through cache for global, low-cardinality singleton config.

A single per-thread **L1** tier resolves a getter L1 → DB: a hit wins; a ``None``
result means "not cached, compute it" and is never stored (unless the getter opts
in with ``cache_none=True``, for getters where ``None`` is a legitimate answer).
This is deliberately simple — it is only for global, user-INDEPENDENT,
signal-invalidated singletons (feature flags, system settings, and the like),
never per-user or per-object data.

There is intentionally **no shared/cross-process (L2) tier**: freshness is provided
by resetting L1 at every request and task boundary (middleware + the Celery task
base), so each request/task reads the singleton from the DB at most once and never
serves a value cached during a prior request/task (e.g. a since-changed
``System_Settings``). This keeps the design free of a Redis dependency, pickled
model graphs, and cross-process invalidation — at the cost of one DB read per
singleton per request/task. (The default ``django.core.cache`` backend may still be
Redis for other uses; this module no longer reads or writes it.)

Values are stored as plain dicts/scalars (see ``model_to_cache_dict`` /
``cache_dict_to_model``), never pickled model instances.

Configuration (Django setting, wired from env in ``settings.dist.py``):

* ``SETTINGS_CACHE_L1_TTL`` — per-thread in-process freshness budget in seconds
  (``-1`` disables the cache, making the decorator a pass-through). Keep it short.
  L1 is reset at each request/task boundary, so it is effectively request/task
  scoped.
"""

import threading
import time
from functools import wraps

from django.conf import settings


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

# Sentinel stored in L1 to represent a cached ``None`` result, so a legitimately
# ``None`` value (e.g. "no default configured") is distinguishable from "absent".
# Only used by getters that opt in via ``cache_none=True``.
_CACHED_NONE = object()


def dojo_settings_cache(*, key: str, cache_none: bool = False):
    """
    Read-through in-process (L1) cache for a fixed-key singleton getter.

    Resolves L1 → wrapped function. Becomes a pass-through when L1 is disabled
    (``SETTINGS_CACHE_L1_TTL=-1``). Freshness across processes comes from resetting
    L1 each request/task (see ``reset_l1_cache``), not a shared tier.

    By default a ``None`` result is treated as "no value" and is not cached (so the
    next call retries) — right for singletons that always exist and where ``None``
    means "not yet computed / transient error".

    Pass ``cache_none=True`` for getters where ``None`` is a legitimate steady-state
    answer (e.g. "no default row configured"). It caches the ``None`` too, so a
    missing row costs one DB read per request/task instead of one per call site.
    Safe only when the getter is signal-invalidated on the row's create/save (so the
    cached ``None`` is dropped the moment a value appears).
    """

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            value = _L1_STORE.get(key)              # ---- L1 ----
            if value is _CACHED_NONE:               # cached "no value" (cache_none=True)
                return None
            if value is not None:
                return value

            value = fn(*args, **kwargs)             # ---- miss: compute ----
            if value is not None:
                _L1_STORE.set(key, value)
            elif cache_none:
                _L1_STORE.set(key, _CACHED_NONE)
            return value

        return wrapper

    return decorator


def invalidate_dojo_settings_cache(key: str) -> None:
    """
    Drop a cached singleton from L1 (this thread).

    With no shared tier, other threads/processes self-heal at their next
    request/task boundary (L1 reset), so there is nothing cross-process to drop.
    """
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


# Attribute set on instances rebuilt for read-only cache use (``read_only=True``).
# A guarded model's ``save()`` checks it and refuses to persist a cache-derived
# snapshot (see ``System_Settings.save``). Instance-level, so it never leaks to a
# freshly-fetched (``no_cache=True``) instance, which is a distinct object.
READ_ONLY_CACHE_MARKER = "_dd_read_only_cache_snapshot"


class ReadOnlyCachedInstanceError(RuntimeError):

    """
    Raised when code tries to save a model instance rebuilt from the read-through
    cache. Such an instance is a point-in-time snapshot; persisting it can clobber
    concurrent changes with stale field values. Fetch a fresh DB instance
    (e.g. ``System_Settings.objects.get(no_cache=True)``) before saving.
    """


def cache_dict_to_model(model_cls, data: dict, *, read_only: bool = False):
    """
    Rebuild an in-memory model instance from a ``model_to_cache_dict`` dict.

    For read-only use; callers that persist changes must fetch a fresh DB instance
    rather than saving a cache-derived one. Pass ``read_only=True`` to tag the
    instance with ``READ_ONLY_CACHE_MARKER`` so a guarded model's ``save()`` fails
    loudly instead of silently writing a stale snapshot.
    """
    instance = model_cls(**data)
    if read_only:
        setattr(instance, READ_ONLY_CACHE_MARKER, True)
    return instance
