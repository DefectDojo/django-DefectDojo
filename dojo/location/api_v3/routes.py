"""
Location read routes + finding/product location sub-resources for API v3 (§4.14, OS4).

Three router factories (I5), all **read-only** (location lifecycle is import-driven, §4.14):

- ``build_locations_router()``          -> ``GET /locations`` + ``GET /locations/{id}``
- ``build_finding_locations_router()``  -> ``GET /findings/{id}/locations`` (edge rows)
- ``build_product_locations_router()``  -> ``GET /products/{id}/locations`` (edge rows)

Routes are thin (I6): authorize -> filter/plan -> serialize -> shape. RBAC:

- ``/locations`` mirrors the v2 ``LocationViewSet`` access model **exactly** -- that viewset stacks
  ``permission_classes = (IsSuperUser, DjangoModelPermissions)``, i.e. **superuser-only** (verified,
  see §12). v3 gates the whole resource behind ``request.user.is_superuser`` (403 otherwise) and
  draws rows from ``get_authorized_locations`` (I8, forward-compatible: a downstream distribution can
  scope the queryset without a route change).
- the sub-resources use **parent-inherited authorization**: the parent finding/product is resolved
  through ``get_authorized_findings``/``get_authorized_products`` (I8); an unknown *or unauthorized*
  parent is a 404 (never leak existence, §4.10). The edge rows are then drawn from the parent's own
  reverse manager, so a caller who can see the parent sees its edges.

These live in the location module (not the finding/product route factories) so all location code
stays together and the finding/product factories are untouched (§12).
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from django.core.exceptions import PermissionDenied
from ninja import Router
from ninja.constants import NOT_SET

from dojo.api_v3.errors import json_response, not_found_problem
from dojo.api_v3.expand import allowed_field_names, apply_fields, parse_fields, plan, plan_queryset, serialize
from dojo.api_v3.filtering import FilterSpec, apply_filters, filter_field, register_filter_spec
from dojo.api_v3.pagination import paginate
from dojo.authorization.roles_permissions import Permissions
from dojo.finding.queries import get_authorized_findings
from dojo.location.api_v3.schemas import (
    FindingLocationListResponse,
    LocationDetail,
    LocationListResponse,
    LocationSlim,
    ProductLocationListResponse,
    finding_location_edge,
    product_location_edge,
)
from dojo.location.models import Location, LocationFindingReference, LocationProductReference
from dojo.location.queries import get_authorized_locations
from dojo.product.queries import get_authorized_products

if TYPE_CHECKING:
    from collections.abc import Callable

    from django.db.models import QuerySet
    from django.http import HttpRequest

# --- Location filter vocabulary (§4.14) -------------------------------------------------------

LOCATION_FILTER_SPEC = register_filter_spec("location", FilterSpec(
    model=Location,
    filters={
        "type": filter_field("location_type", "exact", "char"),
        "name__icontains": filter_field("location_value", "icontains", "char"),
        # A location relates to a product via LocationProductReference (mirrors the v2 LocationFilter
        # `product` filter, field_name="products__product"). Distinct: the join can duplicate rows.
        "product": filter_field("products__product", "exact", "number", distinct=True),
    },
    orderings={
        "id": "id",
        "name": "location_value",
    },
    search_fields=["location_value"],
))


def build_locations_router(
    *,
    schema: type = LocationSlim,
    detail_schema: type = LocationDetail,
    filter_spec: FilterSpec = LOCATION_FILTER_SPEC,
    queryset_hook: Callable | None = None,
    auth=NOT_SET,
) -> Router:
    """Build the read-only locations router (I5)."""
    router = Router(tags=["locations"], auth=auth)

    def _base_queryset(request: HttpRequest) -> QuerySet:
        # Mirror v2 LocationViewSet: superuser-only (IsSuperUser). Everyone else -> 403 (§12).
        if not request.user.is_superuser:
            raise PermissionDenied
        qs = get_authorized_locations("view", user=request.user)
        if queryset_hook is not None:
            qs = queryset_hook(qs, request)
        return qs

    @router.get("/locations", response=LocationListResponse, url_name="locations_list")
    def list_locations(request: HttpRequest):
        filtered = apply_filters(request, _base_queryset(request), filter_spec)

        expand_tree, select_related, prefetch = plan(schema, request.GET.get("expand"))
        page_qs = filtered.select_related(*schema.SELECT_RELATED).prefetch_related(*schema.PREFETCH_RELATED)
        page_qs = plan_queryset(page_qs, select_related, prefetch)

        fields = parse_fields(request.GET.get("fields"), allowed_field_names(schema))

        def serialize_row(obj: object) -> dict:
            return apply_fields(serialize(obj, schema, expand_tree), fields)

        envelope = paginate(request, count_qs=filtered, page_qs=page_qs, serialize=serialize_row)
        return json_response(envelope)

    @router.get("/locations/{int:location_id}", response=detail_schema, url_name="locations_detail")
    def get_location(request: HttpRequest, location_id: int):
        expand_tree, select_related, prefetch = plan(detail_schema, request.GET.get("expand"))
        qs = _base_queryset(request).select_related(*detail_schema.SELECT_RELATED).prefetch_related(*detail_schema.PREFETCH_RELATED)
        qs = plan_queryset(qs, select_related, prefetch)
        obj = qs.filter(pk=location_id).first()
        if obj is None:
            msg = f"Location {location_id} not found"
            raise not_found_problem(msg)
        fields = parse_fields(request.GET.get("fields"), allowed_field_names(detail_schema))
        return json_response(apply_fields(serialize(obj, detail_schema, expand_tree), fields))

    return router


def build_finding_locations_router(*, queryset_hook: Callable | None = None, auth=NOT_SET) -> Router:
    """
    Build the ``GET /findings/{id}/locations`` sub-resource router (I5). Edge rows carry the location
    ref + edge ``status``/``audit_time``/``auditor`` (§4.14). ``select_related("location", "auditor")``
    keeps the query count constant regardless of the number of edges.
    """
    router = Router(tags=["findings"], auth=auth)

    @router.get(
        "/findings/{int:finding_id}/locations",
        response=FindingLocationListResponse,
        url_name="finding_locations_list",
    )
    def list_finding_locations(request: HttpRequest, finding_id: int):
        findings = get_authorized_findings(Permissions.Finding_View, user=request.user)
        if queryset_hook is not None:
            findings = queryset_hook(findings, request)
        finding = findings.filter(pk=finding_id).first()
        if finding is None:
            # 404 for unknown *or unauthorized* parent -- parent-inherited authorization (§4.10).
            msg = f"Finding {finding_id} not found"
            raise not_found_problem(msg)

        edges = LocationFindingReference.objects.filter(finding=finding).order_by("id")
        page_qs = edges.select_related("location", "auditor")
        envelope = paginate(request, count_qs=edges, page_qs=page_qs, serialize=finding_location_edge)
        return json_response(envelope)

    return router


def build_product_locations_router(*, queryset_hook: Callable | None = None, auth=NOT_SET) -> Router:
    """
    Build the ``GET /products/{id}/locations`` sub-resource router (I5). Edge rows carry the location
    ref + edge ``status`` only -- ``LocationProductReference`` has no audit columns (§12).
    ``select_related("location")`` keeps the query count constant.
    """
    router = Router(tags=["products"], auth=auth)

    @router.get(
        "/products/{int:product_id}/locations",
        response=ProductLocationListResponse,
        url_name="product_locations_list",
    )
    def list_product_locations(request: HttpRequest, product_id: int):
        products = get_authorized_products(Permissions.Product_View, user=request.user)
        if queryset_hook is not None:
            products = queryset_hook(products, request)
        product = products.filter(pk=product_id).first()
        if product is None:
            msg = f"Product {product_id} not found"
            raise not_found_problem(msg)

        edges = LocationProductReference.objects.filter(product=product).order_by("id")
        page_qs = edges.select_related("location")
        envelope = paginate(request, count_qs=edges, page_qs=page_qs, serialize=product_location_edge)
        return json_response(envelope)

    return router
