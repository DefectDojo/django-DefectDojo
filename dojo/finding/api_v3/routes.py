"""
Findings read + write routes for API v3 (§4.5, §4.6, §4.8, OS1 read / OS3b write).

``build_findings_router()`` is a router *factory* (I5): the OS mount calls it with defaults; a
downstream distribution can call it with a subclassed schema / extra filters / a queryset hook and
mount the result under its own prefix -- no fork. Routes are thin (I6): authorize -> parse ->
service -> serialize; all RBAC flows through ``get_authorized_findings`` (reads) and the v2
``UserHasFindingPermission`` semantics (writes, I8), and **all** write side-effects/orchestration
live in ``dojo/finding/services.py`` (D7), never in the route:

- create (POST):   ``add`` permission on the target ``test`` referenced in the payload (404 if it
                   doesn't exist, 403 if unauthorized -- mirrors
                   ``check_post_permission(request, Test, "test", "add")``).
- update (PATCH):  object ``edit`` permission (404 for unknown-or-unauthorized, 403 if visible but
                   not editable). Mirrors ``perform_update``: ``push_to_jira`` is OR-ed with the
                   JIRA project's ``push_all_issues`` when JIRA is enabled.
- delete (DELETE): object ``delete`` permission; delegates to the service, whose ``Finding.delete()``
                   runs the same dedup/grading hooks as the v2 ``FindingViewSet.destroy`` (§12).
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.db.models import Count
from django.http import HttpResponse
from ninja import Router, Schema
from ninja.constants import NOT_SET

from dojo.api_v3.errors import json_response, not_found_problem
from dojo.api_v3.expand import allowed_field_names, apply_fields, parse_fields, plan, plan_queryset, serialize
from dojo.api_v3.filtering import (
    FilterSpec,
    apply_filters,
    filter_field,
    register_filter_spec,
    severity_rank_order,
)
from dojo.api_v3.include import apply_includes
from dojo.api_v3.pagination import paginate
from dojo.authorization.authorization import user_has_permission
from dojo.authorization.roles_permissions import Permissions
from dojo.finding.api_v3.schemas import FindingDetail, FindingSlim, FindingUpdate, FindingWrite
from dojo.finding.queries import get_authorized_findings
from dojo.finding.services import create_finding, delete_finding, update_finding
from dojo.jira import services as jira_services
from dojo.models import Finding, Test
from dojo.utils import get_object_or_none, get_system_setting

if TYPE_CHECKING:
    from collections.abc import Callable

    from django.db.models import QuerySet
    from django.http import HttpRequest

# --- Findings filter vocabulary (§4.9) --------------------------------------------------------

FINDING_FILTER_SPEC = register_filter_spec("finding", FilterSpec(
    model=Finding,
    filters={
        "id__in": filter_field("id", "in", "number"),
        "title__icontains": filter_field("title", "icontains", "char"),
        "severity": filter_field("severity", "exact", "char"),
        "severity__in": filter_field("severity", "in", "char"),
        "active": filter_field("active", "exact", "bool"),
        "verified": filter_field("verified", "exact", "bool"),
        "duplicate": filter_field("duplicate", "exact", "bool"),
        "false_p": filter_field("false_p", "exact", "bool"),
        "risk_accepted": filter_field("risk_accepted", "exact", "bool"),
        "out_of_scope": filter_field("out_of_scope", "exact", "bool"),
        "is_mitigated": filter_field("is_mitigated", "exact", "bool"),
        "date__gte": filter_field("date", "gte", "date"),
        "date__lte": filter_field("date", "lte", "date"),
        "cwe": filter_field("cwe", "exact", "number"),
        "cwe__in": filter_field("cwe", "in", "number"),
        "product": filter_field("test__engagement__product", "exact", "number"),
        "product__in": filter_field("test__engagement__product", "in", "number"),
        "product_type": filter_field("test__engagement__product__prod_type", "exact", "number"),
        "engagement": filter_field("test__engagement", "exact", "number"),
        "test": filter_field("test", "exact", "number"),
        "reporter": filter_field("reporter", "exact", "number"),
        "tags__in": filter_field("tags__name", "in", "char", distinct=True),
        "created__gte": filter_field("created", "gte", "datetime"),
        "created__lte": filter_field("created", "lte", "datetime"),
        "updated__gte": filter_field("updated", "gte", "datetime"),
        "updated__lte": filter_field("updated", "lte", "datetime"),
    },
    orderings={
        "id": "id",
        "date": "date",
        "title": "title",
        "created": "created",
        "updated": "updated",
    },
    # `o=severity` sorts by rank (Critical first), not alphabetically (§4.9).
    order_expressions={"severity": severity_rank_order},
    search_fields=["title", "description"],
))

_ALLOWED_INCLUDES = {"counts"}


class FindingListResponse(Schema):

    """
    OpenAPI documentation of the list envelope (I1). Runtime serialization is manual so
    ``?expand=``/``?fields=`` can reshape ``results`` dynamically; this schema documents the base
    slim shape for client codegen.
    """

    count: int
    next: str | None
    previous: str | None
    results: list[FindingSlim]
    meta: dict | None = None


def _base_queryset(request: HttpRequest, queryset_hook: Callable | None) -> QuerySet:
    qs = get_authorized_findings(Permissions.Finding_View, user=request.user)
    if queryset_hook is not None:
        qs = queryset_hook(qs, request)
    return qs


def _detail_object(request: HttpRequest, queryset_hook: Callable | None, detail_schema: type, finding_id: int):
    """
    Fetch a finding through the authorized queryset with the detail schema's relations +
    ``locations_count`` annotation loaded, so the write responses serialize identically to GET.
    """
    qs = (
        _base_queryset(request, queryset_hook)
        .select_related(*detail_schema.SELECT_RELATED)
        .prefetch_related(*detail_schema.PREFETCH_RELATED)
        .annotate(locations_count=Count("locations", distinct=True))
    )
    return qs.filter(pk=finding_id).first()


def build_findings_router(
    *,
    schema: type = FindingSlim,
    detail_schema: type = FindingDetail,
    filter_spec: FilterSpec = FINDING_FILTER_SPEC,
    queryset_hook: Callable | None = None,
    auth=NOT_SET,
) -> Router:
    """Build the findings router (I5)."""
    router = Router(tags=["findings"], auth=auth)

    @router.get("/findings", response=FindingListResponse, url_name="findings_list")
    def list_findings(request: HttpRequest):
        filtered = apply_filters(request, _base_queryset(request, queryset_hook), filter_spec)

        expand_tree, select_related, prefetch = plan(schema, request.GET.get("expand"))
        page_qs = (
            filtered.select_related(*schema.SELECT_RELATED)
            .prefetch_related(*schema.PREFETCH_RELATED)
            .annotate(locations_count=Count("locations", distinct=True))
        )
        page_qs = plan_queryset(page_qs, select_related, prefetch)

        allowed_fields = allowed_field_names(schema)
        fields = parse_fields(request.GET.get("fields"), allowed_fields)

        def serialize_row(obj: object) -> dict:
            return apply_fields(serialize(obj, schema, expand_tree), fields)

        envelope = paginate(request, count_qs=filtered, page_qs=page_qs, serialize=serialize_row)

        include_meta = apply_includes(request, filtered, allowed=_ALLOWED_INCLUDES)
        if include_meta:
            envelope.setdefault("meta", {}).update(include_meta)

        return json_response(envelope)

    @router.get("/findings/{int:finding_id}", response=detail_schema, url_name="findings_detail")
    def get_finding(request: HttpRequest, finding_id: int):
        expand_tree, select_related, prefetch = plan(detail_schema, request.GET.get("expand"))
        qs = (
            _base_queryset(request, queryset_hook)
            .select_related(*detail_schema.SELECT_RELATED)
            .prefetch_related(*detail_schema.PREFETCH_RELATED)
            .annotate(locations_count=Count("locations", distinct=True))
        )
        qs = plan_queryset(qs, select_related, prefetch)
        obj = qs.filter(pk=finding_id).first()
        if obj is None:
            # 404 for unknown *or unauthorized* -- never leak existence (§4.10).
            msg = f"Finding {finding_id} not found"
            raise not_found_problem(msg)

        allowed_fields = allowed_field_names(detail_schema)
        fields = parse_fields(request.GET.get("fields"), allowed_fields)
        data = apply_fields(serialize(obj, detail_schema, expand_tree), fields)
        return json_response(data)

    @router.post("/findings", response=detail_schema, url_name="findings_create")
    def create_finding_route(request: HttpRequest, payload: FindingWrite):
        data = payload.dict()
        test_id = data.pop("test")
        push_to_jira = data.pop("push_to_jira")
        vulnerability_ids = data.pop("vulnerability_ids")
        # Mirror UserHasFindingPermission -> check_post_permission(request, Test, "test", "add"):
        # 404 if the test doesn't exist, 403 if the user can't add findings to it.
        test = get_object_or_none(Test, pk=test_id)
        if test is None:
            msg = f"Test {test_id} not found"
            raise not_found_problem(msg)
        if not user_has_permission(request.user, test, Permissions.Finding_Add):
            raise PermissionDenied
        finding = create_finding(
            test=test, data=data, user=request.user,
            push_to_jira=push_to_jira, vulnerability_ids=vulnerability_ids,
        )
        obj = _detail_object(request, queryset_hook, detail_schema, finding.pk) or finding
        return json_response(serialize(obj, detail_schema, {}), status=201)

    @router.patch("/findings/{int:finding_id}", response=detail_schema, url_name="findings_update")
    def update_finding_route(request: HttpRequest, finding_id: int, payload: FindingUpdate):
        finding = _base_queryset(request, queryset_hook).filter(pk=finding_id).first()
        if finding is None:
            msg = f"Finding {finding_id} not found"
            raise not_found_problem(msg)  # 404: unknown or unauthorized-to-view
        if not user_has_permission(request.user, finding, Permissions.Finding_Edit):
            raise PermissionDenied  # 403: visible but not editable

        changes = payload.dict(exclude_unset=True)
        push_to_jira = changes.pop("push_to_jira", False)
        vulnerability_ids = changes.pop("vulnerability_ids", None)
        # Mirror FindingViewSet.perform_update: OR push_to_jira with the project's push_all_issues.
        jira_project = jira_services.get_project(finding)
        if get_system_setting("enable_jira") and jira_project:
            push_to_jira = push_to_jira or jira_project.push_all_issues

        update_finding(
            finding, changes=changes, user=request.user,
            push_to_jira=push_to_jira, vulnerability_ids=vulnerability_ids,
        )
        obj = _detail_object(request, queryset_hook, detail_schema, finding_id) or finding
        return json_response(serialize(obj, detail_schema, {}))

    @router.delete("/findings/{int:finding_id}", url_name="findings_delete")
    def delete_finding_route(request: HttpRequest, finding_id: int):
        finding = _base_queryset(request, queryset_hook).filter(pk=finding_id).first()
        if finding is None:
            msg = f"Finding {finding_id} not found"
            raise not_found_problem(msg)
        if not user_has_permission(request.user, finding, Permissions.Finding_Delete):
            raise PermissionDenied
        delete_finding(finding, user=request.user)
        response = HttpResponse(status=204)
        response["X-API-Status"] = settings.API_V3_STATUS
        return response

    return router
