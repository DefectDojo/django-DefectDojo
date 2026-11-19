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

A link built while serving a request (an API page's ``next``, for one) uses
``request_absolute_url()`` instead of ``request.build_absolute_uri()``. With nothing
registered the two are the same call. A plugin that serves the instance under an address
the request does not carry (behind a reverse proxy that forwards ``Host`` without the
public port) replaces it with ``register_request_url_resolver(func, override=True)``.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from django.http import HttpRequest

# The empty-setting warning keeps the logger it was always emitted under
# (dojo.utils.get_site_url), so log filters and alerts on that name keep matching.
logger = logging.getLogger("dojo.utils")

# Single-slot registry, mutated in place so no `global` rebinding is needed. The stored
# callable returns the base URL; None means "use default_site_url()".
_RESOLVER: dict[str, Callable[[], str] | None] = {"fn": None}
# Same shape for request-relative links: the callable takes the request and an absolute path
# and returns the absolute URL; None means "use request.build_absolute_uri()".
_REQUEST_RESOLVER: dict[str, Callable[[HttpRequest, str], str] | None] = {"fn": None}


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


def register_request_url_resolver(func: Callable[[HttpRequest, str], str], *, override: bool = False) -> None:
    """
    Register the callable that builds an absolute URL for a path within a request.

    It is called as ``func(request, path)`` with an absolute path (query string included).
    Without ``override`` an existing registration is kept.
    """
    if _REQUEST_RESOLVER["fn"] is not None and not override:
        return
    _REQUEST_RESOLVER["fn"] = func


def request_absolute_url(request: HttpRequest, path: str | None = None) -> str:
    """
    Return ``path`` (default: the request's own full path) as an absolute URL for ``request``.

    With nothing registered this is exactly ``request.build_absolute_uri(path)``.
    """
    resolver = _REQUEST_RESOLVER["fn"]
    if resolver is None:
        return request.build_absolute_uri(path)
    return resolver(request, request.get_full_path() if path is None else path)
