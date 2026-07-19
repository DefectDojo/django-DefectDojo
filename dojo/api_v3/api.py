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
    from dojo.engagement.api_v3.routes import build_engagements_router  # noqa: PLC0415
    from dojo.finding.api_v3.routes import build_findings_router  # noqa: PLC0415
    from dojo.location.api_v3.routes import (  # noqa: PLC0415
        build_finding_locations_router,
        build_locations_router,
        build_product_locations_router,
    )
    from dojo.product.api_v3.routes import build_products_router  # noqa: PLC0415
    from dojo.product_type.api_v3.routes import build_product_types_router  # noqa: PLC0415
    from dojo.test.api_v3.routes import build_tests_router  # noqa: PLC0415
    from dojo.user.api_v3.routes import build_users_router  # noqa: PLC0415

    api.add_router("", build_findings_router())
    api.add_router("", build_product_types_router())
    api.add_router("", build_products_router())
    api.add_router("", build_engagements_router())
    api.add_router("", build_tests_router())
    api.add_router("", build_users_router())
    api.add_router("", build_locations_router())
    api.add_router("", build_finding_locations_router())
    api.add_router("", build_product_locations_router())
    api.add_router("", build_import_router())

    _mount_subresources(api)
    return api


def _mount_subresources(api: NinjaAPI) -> None:
    """
    Mount the generic notes / tags / files sub-resources (§4.12, OS5) on the resources whose
    *models* actually store them (storage support matrix, see .claude/os5-report.md / §12):

    - notes + files: finding, engagement, test (each has a ``Notes``/``FileUpload`` M2M).
    - tags:          finding, engagement, test, product (each has a ``TagField`` and a writable v3
                     resource). product_type/user have no such fields; location has a ``TagField``
                     but is a read-only, superuser-only resource with no v2 tag-mutation endpoint
                     and already surfaces ``tags[]`` on its read shape -- so no tag sub-resource is
                     attached to it (§12).

    Deferred here (not at module top) so the kernel ``subresources.py`` stays resource-agnostic;
    this mount is the composition root, alongside the router-factory imports above.
    """
    from dojo.api_v3.subresources import (  # noqa: PLC0415
        build_files_router,
        build_notes_router,
        build_tags_router,
    )
    from dojo.authorization.roles_permissions import Permissions  # noqa: PLC0415
    from dojo.engagement.queries import get_authorized_engagements  # noqa: PLC0415
    from dojo.engagement.services import process_note_added as engagement_process_note_added  # noqa: PLC0415
    from dojo.finding.queries import get_authorized_findings  # noqa: PLC0415
    from dojo.finding.services import process_note_added as finding_process_note_added  # noqa: PLC0415
    from dojo.product.queries import get_authorized_products  # noqa: PLC0415
    from dojo.test.queries import get_authorized_tests  # noqa: PLC0415
    from dojo.test.services import process_note_added as test_process_note_added  # noqa: PLC0415

    # Parent authorized-view queryset resolvers. finding/product take an explicit user; engagement/
    # test read the current user from crum (their signatures take no user kwarg) -- matching how the
    # v2 viewsets and the OS3 route factories call them.
    def findings_qs(request):
        return get_authorized_findings(Permissions.Finding_View, user=request.user)

    def engagements_qs(request):
        return get_authorized_engagements(Permissions.Engagement_View)

    def tests_qs(request):
        return get_authorized_tests(Permissions.Test_View)

    def products_qs(request):
        return get_authorized_products(Permissions.Product_View, user=request.user)

    file_view = Permissions.Product_Tracking_Files_View
    file_add = Permissions.Product_Tracking_Files_Add

    # Note-created side-effect callbacks per resource (v2 parity): the finding service fires JIRA
    # comment sync + last_reviewed stamping + @mention notifications; engagement/test fire @mention
    # notifications only (their v2 @actions have no JIRA/last_reviewed) -- see §12. The kernel notes
    # factory imports none of this machinery; it only invokes the callback wired here (I5/I6).
    note_callbacks = {
        "findings": finding_process_note_added,
        "engagements": engagement_process_note_added,
        "tests": test_process_note_added,
    }
    notes_and_files = (
        ("findings", "Finding", findings_qs),
        ("engagements", "Engagement", engagements_qs),
        ("tests", "Test", tests_qs),
    )
    for resource, label, qs in notes_and_files:
        api.add_router("", build_notes_router(
            resource=resource, parent_label=label, get_parent_queryset=qs,
            on_note_created=note_callbacks[resource],
        ))
        api.add_router("", build_files_router(
            resource=resource, parent_label=label, get_parent_queryset=qs,
            view_permission=file_view, add_permission=file_add,
        ))

    tagged = (
        *notes_and_files,
        ("products", "Product", products_qs),
    )
    for resource, label, qs in tagged:
        api.add_router("", build_tags_router(resource=resource, parent_label=label, get_parent_queryset=qs))


api_v3 = build_api()
