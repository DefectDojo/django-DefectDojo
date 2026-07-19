"""
NinjaAPI instance and mount assembly for API v3 (alpha) (D1, D2 / §4.1).

Builds the single ``NinjaAPI`` instance for v3 and assembles the OS routers via their factories
(I5). Imported (and thus built) only when ``V3_FEATURE_LOCATIONS`` is on -- ``dojo/urls.py`` mounts
it conditionally, so with the flag off ``/api/v3-alpha/`` does not exist at all and v3 carries no
legacy-endpoint code path (D5).

Auth is the pluggable ordered list ``[TokenAuth(), django_auth]`` (I7 / §4.2). CSRF for the
session (cookie) auth is enforced by ``django_auth`` itself (ninja's ``SessionAuth`` defaults
``csrf=True`` and checks it on unsafe methods); token (header) auth needs no CSRF. See §12 for why
``NinjaAPI(csrf=...)`` is not passed (the parameter no longer exists in django-ninja 1.6.x).
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.conf import settings
from ninja import NinjaAPI
from ninja.security import django_auth

from dojo.api_v3.auth import TokenAuth
from dojo.api_v3.errors import register_exception_handlers

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponse


class V3NinjaAPI(NinjaAPI):

    """NinjaAPI that stamps ``X-API-Status`` on every response it creates (§4.1)."""

    def create_response(self, request: HttpRequest, data: Any, *args: Any, **kwargs: Any) -> HttpResponse:
        response = super().create_response(request, data, *args, **kwargs)
        response["X-API-Status"] = settings.API_V3_STATUS
        return response


def build_api() -> NinjaAPI:
    """Construct the v3 NinjaAPI instance and mount the OS1 routers via their factories."""
    api = V3NinjaAPI(
        title="DefectDojo API v3",
        version=settings.API_V3_VERSION,
        description=(
            "DefectDojo API v3 (alpha). The alpha contract may change at any time; do not build "
            "production dependencies on this URL. At beta the API moves to /api/v3/ and stays there."
        ),
        auth=[TokenAuth(), django_auth],
        urls_namespace="api_v3",
        docs_url="/docs",
        openapi_url="/openapi.json",
    )
    register_exception_handlers(api)

    # Routers are factories (I5); the mount calls them with OS defaults. Imported here (not at
    # module top) so the kernel submodules never depend on route modules -- dependency direction
    # stays "resources import kernel", never the reverse.
    from dojo.api_v3.import_routes import build_import_router  # noqa: PLC0415
    from dojo.finding.api_v3.routes import build_findings_router  # noqa: PLC0415

    api.add_router("", build_findings_router())
    api.add_router("", build_import_router())
    return api


api_v3 = build_api()
