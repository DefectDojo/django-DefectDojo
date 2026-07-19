"""
Findings read routes for API v3 (§4.5, §4.6, §4.8, OS1).

``build_findings_router()`` is a router *factory* (I5): the OS mount calls it with defaults; a
downstream distribution can call it with a subclassed schema / extra filters / a queryset hook and
mount the result under its own prefix -- no fork. Routes are thin (I6): authorize -> filter ->
plan queryset -> serialize -> shape; all RBAC flows through ``get_authorized_findings`` (I8).
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from django.db.models import Count
from ninja import Router, Schema
from ninja.constants import NOT_SET

from dojo.api_v3.errors import json_response, not_found_problem
from dojo.api_v3.expand import apply_fields, parse_fields, plan, plan_queryset, serialize
from dojo.api_v3.filtering import FilterSpec, apply_filters, filter_field
from dojo.api_v3.include import apply_includes
from dojo.api_v3.pagination import paginate
from dojo.authorization.roles_permissions import Permissions
from dojo.finding.api_v3.schemas import FindingDetail, FindingSlim
from dojo.finding.queries import get_authorized_findings
from dojo.models import Finding

if TYPE_CHECKING:
    from collections.abc import Callable

    from django.db.models import QuerySet
    from django.http import HttpRequest

# --- Findings filter vocabulary (§4.9) --------------------------------------------------------

FINDING_FILTER_SPEC = FilterSpec(
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
        "severity": "severity",
        "title": "title",
        "created": "created",
        "updated": "updated",
    },
    search_fields=["title", "description"],
)

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

        allowed_fields = set(schema.model_fields)
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

        allowed_fields = set(detail_schema.model_fields)
        fields = parse_fields(request.GET.get("fields"), allowed_fields)
        data = apply_fields(serialize(obj, detail_schema, expand_tree), fields)
        return json_response(data)

    return router
