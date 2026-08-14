"""
Runtime resolution of the Locations feature flag (``V3_FEATURE_LOCATIONS``).

Locations is the V3 successor to Endpoints. Whether an import creates Location
records or Endpoint records -- and which the UI and API surface -- is decided by
this flag. Historically every consumer read ``settings.V3_FEATURE_LOCATIONS``
directly, a value fixed for the life of the process.

This module adds a single indirection so the value can be resolved at call time
from something other than the Django setting. Open source keeps reading the
setting live (see ``_default_resolver``), so ``override_settings`` in the test
suite keeps working unchanged and there is no behavioural change for an OSS-only
install. The Pro plugin registers a database-backed resolver at startup via
``register_locations_resolver(..., override=True)``, turning the flag into a
customer-togglable Feature Flag without forking the ~200 call-time read sites.

The register-with-override hook mirrors ``dojo.authorization.query_filters``: a
default never clobbers an explicit override, so the wiring is order-independent
regardless of which ``AppConfig.ready()`` runs first.

Only *call-time* reads route through here. A handful of module-level sites decide
route wiring and permission tables at import and cannot follow a runtime toggle
without re-mounting URLConf; those deliberately stay on
``settings.V3_FEATURE_LOCATIONS`` and are annotated where they live
(``dojo/urls.py``, ``dojo/authorization/url_permissions.py``,
``dojo/authorization/api_permissions.py``, ``dojo/endpoint/api/urls.py``),
together with the ``Endpoint.__init__`` guard in ``dojo/endpoint/models.py``.
See ``pro/features/relabel.py`` for the same split applied to the
Organization/Asset relabel flag.
"""

import logging

logger = logging.getLogger(__name__)

# Single-slot registry, mutated in place so no `global` rebinding is needed
# (mirrors dojo.authorization.query_filters._AUTH_FILTER_REGISTRY). The stored
# callable resolves the flag; None means "fall back to the Django setting".
_RESOLVER: dict[str, object] = {"fn": None}


def register_locations_resolver(func, *, override=False):
    """
    Register the callable that resolves the Locations flag at call time.

    Defaults register without ``override`` and never clobber an existing entry;
    a plugin replacing the default (Pro's database-backed resolver) passes
    ``override=True``. This makes the wiring order-independent: whichever
    ``AppConfig.ready()`` runs first, the explicit-override side wins.
    """
    if _RESOLVER["fn"] is not None and not override:
        return
    _RESOLVER["fn"] = func


def _default_resolver() -> bool:
    from django.conf import settings  # noqa: PLC0415

    return bool(getattr(settings, "V3_FEATURE_LOCATIONS", False))


def locations_enabled() -> bool:
    """
    Return whether the Locations feature is currently enabled.

    With no resolver registered (plain open source) this reads
    ``settings.V3_FEATURE_LOCATIONS`` live, so the value follows
    ``override_settings`` in tests and the process environment in production.
    When Pro has registered a database-backed resolver, that value is returned
    instead; any failure inside the resolver falls back to the setting so that
    import-time and boot-time consumers always resolve a value and never raise.
    """
    resolver = _RESOLVER["fn"]
    if resolver is None:
        return _default_resolver()
    try:
        return bool(resolver())
    except Exception as exc:
        logger.debug(
            "locations_enabled: resolver failed (%s); using setting fallback.",
            type(exc).__name__,
        )
        return _default_resolver()
