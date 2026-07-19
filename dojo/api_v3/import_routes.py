"""
Consolidated import endpoint for API v3 (§4.13).

``POST /import`` (multipart/form-data) with ``mode`` ``auto`` | ``import`` | ``reimport`` (default
``auto``). The route parses the form, checks permission mirroring the v2
``UserHasImportPermission`` / ``UserHasReimportPermission`` semantics, then delegates **entirely**
to ``dojo/importers/services.py`` (I6). Destructive flags are never implied by mode -- when
omitted, importer defaults apply and the response echoes the effective values.

Per D11 the auto-create form fields speak the new domain language on the wire: ``asset_name`` and
``organization_name`` (mapped internally to the ``AutoCreateContextManager``'s ``product_name`` /
``product_type_name`` context keys, and to the ``dojo/importers/services.py`` facade's kwargs of the
same internal names -- those are not part of the v3 wire surface). See §12.

Background processing is reserved (grammar only): ``background=true`` returns 400 in alpha.
"""
from __future__ import annotations

from datetime import date  # noqa: TC003 -- runtime import: ninja resolves the Form schema field types
from typing import TYPE_CHECKING

from django.core.exceptions import PermissionDenied
from ninja import File, Form, Router, Schema
from ninja.constants import NOT_SET
from ninja.files import UploadedFile  # noqa: TC002 -- runtime import: ninja resolves the File() param type

from dojo.api_v3.errors import ProblemDetail, json_response, not_found_problem, validation_problem
from dojo.api_v3.refs import to_ref
from dojo.authorization.api_permissions import check_auto_create_permission
from dojo.authorization.authorization import user_has_permission
from dojo.importers.auto_create_context import AutoCreateContextManager
from dojo.importers.services import auto_import_scan, import_scan, reimport_scan
from dojo.models import Engagement, Test
from dojo.utils import get_object_or_none

if TYPE_CHECKING:
    from django.http import HttpRequest


class ImportForm(Schema):

    """Form payload for ``POST /import`` (§4.13)."""

    scan_type: str
    mode: str = "auto"
    engagement: int | None = None
    test: int | None = None
    asset_name: str | None = None
    engagement_name: str | None = None
    organization_name: str | None = None
    test_title: str | None = None
    auto_create_context: bool = False
    close_old_findings: bool | None = None
    do_not_reactivate: bool = False
    minimum_severity: str = "Info"
    active: bool | None = None
    verified: bool | None = None
    scan_date: date | None = None
    service: str | None = None
    version: str | None = None
    environment: str = "Development"
    tags: str | None = None
    background: bool = False


def _split_tags(tags: str | None) -> list[str] | None:
    if not tags:
        return None
    return [t.strip() for t in tags.split(",") if t.strip()]


def _require_permission(*, allowed: bool) -> None:
    if not allowed:
        raise PermissionDenied


def _resolve_engagement_for_import(request: HttpRequest, payload: ImportForm) -> Engagement:
    """Resolve (or auto-create) the target engagement + check import permission (import mode)."""
    if payload.engagement is not None:
        engagement = get_object_or_none(Engagement, pk=payload.engagement)
        if engagement is None:
            msg = f'Engagement "{payload.engagement}" does not exist'
            raise not_found_problem(msg)
        _require_permission(allowed=user_has_permission(request.user, engagement, "import"))
        return engagement
    if not payload.auto_create_context:
        raise validation_problem(
            {"engagement": ["Need engagement or asset_name + engagement_name to perform import"]},
        )
    _require_permission(
        allowed=check_auto_create_permission(
            request.user, None, payload.asset_name, None, payload.engagement_name, None,
            payload.organization_name,
            "Need engagement or asset_name + engagement_name to perform import",
        ),
    )
    auto = AutoCreateContextManager()
    context = {
        "product_name": payload.asset_name,
        "engagement_name": payload.engagement_name,
        "product_type_name": payload.organization_name,
        "auto_create_context": payload.auto_create_context,
    }
    auto.process_import_meta_data_from_dict(context)
    return auto.get_or_create_engagement(**context)


def _resolve_test_for_reimport(request: HttpRequest, test_id: int) -> Test:
    test = get_object_or_none(Test, pk=test_id)
    if test is None:
        msg = f'Test "{test_id}" does not exist'
        raise not_found_problem(msg)
    _require_permission(allowed=user_has_permission(request.user, test, "import"))
    return test


def _check_auto_permission(request: HttpRequest, payload: ImportForm) -> None:
    """Mirror UserHasReimportPermission: resolve target and check, else check auto-create."""
    auto = AutoCreateContextManager()
    context = {
        "scan_type": payload.scan_type,
        "product_name": payload.asset_name,
        "engagement_name": payload.engagement_name,
        "product_type_name": payload.organization_name,
        "test_title": payload.test_title,
        "auto_create_context": payload.auto_create_context,
    }
    auto.process_import_meta_data_from_dict(context)
    context["product"] = auto.get_target_product_if_exists(**context)
    context["engagement"] = auto.get_target_engagement_if_exists(**context)
    target_test = auto.get_target_test_if_exists(**context)
    if target_test is not None:
        _require_permission(allowed=user_has_permission(request.user, target_test, "import"))
        return
    if not payload.auto_create_context:
        raise validation_problem(
            {"test": ["Need test or asset_name + engagement_name + scan_type to perform reimport"]},
        )
    _require_permission(
        allowed=check_auto_create_permission(
            request.user, context.get("product"), payload.asset_name, context.get("engagement"),
            payload.engagement_name, None, payload.organization_name,
            "Need test or asset_name + engagement_name + scan_type to perform reimport",
        ),
    )


def build_import_router(*, auth=NOT_SET) -> Router:
    """Build the consolidated import router (I5)."""
    router = Router(tags=["import"], auth=auth)

    @router.post("/import", url_name="import")
    def import_endpoint(
        request: HttpRequest,
        payload: ImportForm = Form(...),  # noqa: B008 -- ninja's declarative param default
        file: UploadedFile | None = File(None),  # noqa: B008 -- ninja's declarative param default
    ):
        if payload.background:
            raise ProblemDetail(
                status=400, error_type="import", title="Background import not available",
                detail="background processing is not yet available",
            )
        if payload.mode not in {"auto", "import", "reimport"}:
            raise validation_problem({"mode": ["must be one of auto, import, reimport"]})

        common = {
            "user": request.user,
            "scan_file": file,
            "scan_type": payload.scan_type,
            "minimum_severity": payload.minimum_severity,
            "active": payload.active,
            "verified": payload.verified,
            "tags": _split_tags(payload.tags),
            "scan_date": payload.scan_date,
            "service": payload.service,
            "version": payload.version,
            "test_title": payload.test_title,
            "environment": payload.environment,
            "auto_create_context": payload.auto_create_context,
            "do_not_reactivate": payload.do_not_reactivate,
        }

        try:
            if payload.mode == "import":
                target_engagement = _resolve_engagement_for_import(request, payload)
                result = import_scan(
                    engagement=target_engagement,
                    close_old_findings=False if payload.close_old_findings is None else payload.close_old_findings,
                    **common,
                )
            elif payload.mode == "reimport" and payload.test is not None:
                target_test = _resolve_test_for_reimport(request, payload.test)
                result = reimport_scan(
                    test=target_test,
                    close_old_findings=True if payload.close_old_findings is None else payload.close_old_findings,
                    **common,
                )
            else:
                # mode == "auto", or reimport without an explicit test id -> resolve/auto-create.
                _check_auto_permission(request, payload)
                result = auto_import_scan(
                    engagement=get_object_or_none(Engagement, pk=payload.engagement) if payload.engagement else None,
                    product_name=payload.asset_name,
                    engagement_name=payload.engagement_name,
                    product_type_name=payload.organization_name,
                    close_old_findings=payload.close_old_findings,
                    **common,
                )
        except PermissionDenied:
            raise
        except ProblemDetail:
            raise
        except (ValueError, TypeError) as exc:
            msg = str(exc)
            raise validation_problem({"non_field_errors": [msg]}) from exc

        return json_response({
            "mode_resolved": result.mode_resolved,
            "test": to_ref(result.test),
            "statistics": {
                "new": result.new,
                "reactivated": result.reactivated,
                "closed": result.closed,
                "untouched": result.untouched,
            },
            "close_old_findings": result.close_old_findings,
        })

    return router
