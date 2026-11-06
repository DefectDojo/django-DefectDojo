"""
The single place DefectDojo resolves its own absolute base URL.

Absolute links (emails, notifications, Jira issues, API payloads, exports) are built
from the instance's public address. Historically each caller read
``settings.SITE_URL`` directly. ``site_url()`` puts one indirection in front of that
read so the value is resolved at call time, and ``absolute_url()`` builds a full link
from a path. Both are the sanctioned way to build an absolute URL; new code should use
them rather than reading the setting.

With nothing registered, ``site_url()`` returns exactly what ``dojo.utils.get_site_url``
always returned: ``settings.SITE_URL`` read live (so ``override_settings`` keeps
working), or the literal placeholder ``"settings.SITE_URL"`` with a warning when the
setting is empty. A plugin can replace the resolution with
``register_site_url_resolver(func, override=True)``. The register-with-override hook
mirrors ``dojo.location.feature`` and ``dojo.authorization.query_filters``: a default
never clobbers an explicit override, so the wiring does not depend on which
``AppConfig.ready()`` runs first.

Unlike ``dojo.location.feature``, a registered resolver that raises is not swallowed.
Falling back to the setting would quietly build a link to a different address than the
one the resolver chose, so the error propagates to the caller instead.
"""

import logging
from collections.abc import Callable

# The empty-setting warning keeps the logger it was always emitted under
# (dojo.utils.get_site_url), so log filters and alerts on that name keep matching.
logger = logging.getLogger("dojo.utils")

# Single-slot registry, mutated in place so no `global` rebinding is needed. The stored
# callable returns the base URL; None means "use default_site_url()".
_RESOLVER: dict[str, Callable[[], str] | None] = {"fn": None}


def register_site_url_resolver(func: Callable[[], str], *, override: bool = False) -> None:
    """
    Register the callable that resolves the instance's base URL.

    Without ``override`` an existing registration is kept; a plugin replacing the
    default passes ``override=True``.
    """
    if _RESOLVER["fn"] is not None and not override:
        return
    _RESOLVER["fn"] = func


def default_site_url() -> str:
    """Return ``settings.SITE_URL``, read live; the behavior with nothing registered."""
    from django.conf import settings  # noqa: PLC0415

    if settings.SITE_URL:
        return settings.SITE_URL
    logger.warning("SITE URL undefined in settings, full_url cannot be created")
    return "settings.SITE_URL"


def site_url() -> str:
    """Return the base URL absolute links are built from."""
    resolver = _RESOLVER["fn"]
    if resolver is None:
        return default_site_url()
    return resolver()


def absolute_url(path: str) -> str:
    """Return ``path`` (as produced by ``reverse()`` or ``get_absolute_url()``) as an absolute URL."""
    return f"{site_url()}{path}"
