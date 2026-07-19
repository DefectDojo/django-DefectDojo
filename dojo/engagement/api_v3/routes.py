"""
Engagement CRUD routes for API v3 (§4.5, §4.9, §4.11, OS3b).

``build_engagements_router()`` is a router factory (I5), same shape as ``build_products_router``.
Routes are thin (I6): authorize -> filter -> plan queryset -> serialize -> shape. RBAC flows only
through ``get_authorized_engagements`` for reads (I8) and the v2 ``user_has_permission`` semantics
for writes, mirroring the v2 ``UserHasEngagementPermission`` permission class exactly:

- create (POST):   ``add`` permission on the target ``product`` referenced in the payload
                   (404 if the product doesn't exist, 403 if unauthorized -- mirrors
                   ``check_post_permission(request, Product, "product", "add")``)
- update (PATCH):  object ``edit`` permission, plus ``add`` on a *reassigned* ``product``
                   (mirrors ``check_update_permission(request, obj, "add", "product")``)
- delete (DELETE): object ``delete`` permission (staff-only for non-staff members, legacy model)
- read:            object ``view`` via the authorized queryset (404 for unknown-or-unauthorized)

Deletion mirrors the v2 ``EngagementViewSet.destroy`` exactly: async delete when
``ASYNC_OBJECT_DELETE`` is set, else a plain synchronous ``instance.delete()`` -- note there is **no**
``Endpoint.allow_endpoint_init()`` wrapper here (unlike product/product_type destroy), mirroring v2
(§12). Relations are referenced by integer id (§4.11).
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.core.exceptions import ValidationError as DjangoValidationError
from django.http import HttpResponse
from ninja import Router, Schema
from ninja.constants import NOT_SET

from dojo.api_v3.errors import json_response, not_found_problem, validation_problem
from dojo.api_v3.expand import allowed_field_names, apply_fields, parse_fields, plan, plan_queryset, serialize
from dojo.api_v3.filtering import (
    FilterSpec,
    apply_filters,
    filter_field,
    register_filter_spec,
)
from dojo.api_v3.include import apply_includes
from dojo.api_v3.pagination import paginate
from dojo.authorization.authorization import user_has_permission
from dojo.authorization.roles_permissions import Permissions
from dojo.engagement.api_v3.schemas import (
    EngagementDetail,
    EngagementSlim,
    EngagementUpdate,
    EngagementWrite,
)
from dojo.engagement.queries import get_authorized_engagements
from dojo.models import Dojo_User, Engagement, Product
from dojo.utils import async_delete, get_object_or_none, get_setting

if TYPE_CHECKING:
    from collections.abc import Callable

    from django.db.models import QuerySet
    from django.http import HttpRequest

# --- Engagement filter vocabulary (§4.9, minimal set) -----------------------------------------

ENGAGEMENT_FILTER_SPEC = register_filter_spec("engagement", FilterSpec(
    model=Engagement,
    filters={
        "id__in": filter_field("id", "in", "number"),
        "name__icontains": filter_field("name", "icontains", "char"),
        "product": filter_field("product", "exact", "number"),
        "product__in": filter_field("product", "in", "number"),
        "product_type": filter_field("product__prod_type", "exact", "number"),
        "lead": filter_field("lead", "exact", "number"),
        "status": filter_field("status", "exact", "char"),
        "engagement_type": filter_field("engagement_type", "exact", "char"),
        "target_start__gte": filter_field("target_start", "gte", "date"),
        "target_start__lte": filter_field("target_start", "lte", "date"),
        "target_end__gte": filter_field("target_end", "gte", "date"),
        "target_end__lte": filter_field("target_end", "lte", "date"),
        "created__gte": filter_field("created", "gte", "datetime"),
        "created__lte": filter_field("created", "lte", "datetime"),
        "updated__gte": filter_field("updated", "gte", "datetime"),
        "updated__lte": filter_field("updated", "lte", "datetime"),
    },
    orderings={
        "id": "id",
        "name": "name",
        "target_start": "target_start",
        "created": "created",
        "updated": "updated",
    },
    search_fields=["name", "description"],
))

# Sentinel distinguishing "tags omitted" from "tags set to null/empty" on PATCH.
_UNSET = object()


class EngagementListResponse(Schema):

    """OpenAPI documentation of the list envelope (I1); runtime serialization is manual."""

    count: int
    next: str | None
    previous: str | None
    results: list[EngagementSlim]
    meta: dict | None = None


def _base_queryset(request: HttpRequest, queryset_hook: Callable | None) -> QuerySet:
    # Reads flow only through the authorized queryset (I8). The OS helper resolves the current user
    # from crum (its signature takes no user kwarg), exactly as the v2 viewset relies on.
    qs = get_authorized_engagements(Permissions.Engagement_View)
    if queryset_hook is not None:
        qs = queryset_hook(qs, request)
    return qs


def _validation_from_django(exc: DjangoValidationError) -> Exception:
    if hasattr(exc, "message_dict"):
        return validation_problem({k: list(v) for k, v in exc.message_dict.items()})
    return validation_problem({"non_field_errors": list(exc.messages)})


def _resolve_lead(pk: int | None) -> Dojo_User | None:
    if pk is None:
        return None
    lead = get_object_or_none(Dojo_User, pk=pk)
    if lead is None:
        raise validation_problem({"lead": [f"user {pk} does not exist"]})
    return lead


def _validate_dates(target_start, target_end) -> None:
    # Mirror EngagementSerializer.validate (POST): target start must not exceed target end.
    if target_start is not None and target_end is not None and target_start > target_end:
        raise validation_problem(
            {"target_start": ["Your target start date exceeds your target end date"]},
        )


def _destroy(instance: Engagement) -> None:
    """Mirror v2 ``EngagementViewSet.destroy`` exactly (no Endpoint context wrapper -- §12)."""
    if get_setting("ASYNC_OBJECT_DELETE"):
        async_delete().delete(instance)
    else:
        instance.delete()


def _apply_scalars(instance: Engagement, data: dict) -> None:
    if "lead" in data:
        instance.lead = _resolve_lead(data.pop("lead"))
    for key, value in data.items():
        setattr(instance, key, value)


def build_engagements_router(
    *,
    schema: type = EngagementSlim,
    detail_schema: type = EngagementDetail,
    filter_spec: FilterSpec = ENGAGEMENT_FILTER_SPEC,
    queryset_hook: Callable | None = None,
    auth=NOT_SET,
) -> Router:
    """Build the engagements router (I5)."""
    router = Router(tags=["engagements"], auth=auth)

    @router.get("/engagements", response=EngagementListResponse, url_name="engagements_list")
    def list_engagements(request: HttpRequest):
        filtered = apply_filters(request, _base_queryset(request, queryset_hook), filter_spec)

        expand_tree, select_related, prefetch = plan(schema, request.GET.get("expand"))
        page_qs = filtered.select_related(*schema.SELECT_RELATED).prefetch_related(*schema.PREFETCH_RELATED)
        page_qs = plan_queryset(page_qs, select_related, prefetch)

        fields = parse_fields(request.GET.get("fields"), allowed_field_names(schema))

        def serialize_row(obj: object) -> dict:
            return apply_fields(serialize(obj, schema, expand_tree), fields)

        envelope = paginate(request, count_qs=filtered, page_qs=page_qs, serialize=serialize_row)
        include_meta = apply_includes(request, filtered, allowed=set())
        if include_meta:
            envelope.setdefault("meta", {}).update(include_meta)
        return json_response(envelope)

    @router.get("/engagements/{int:engagement_id}", response=detail_schema, url_name="engagements_detail")
    def get_engagement(request: HttpRequest, engagement_id: int):
        expand_tree, select_related, prefetch = plan(detail_schema, request.GET.get("expand"))
        qs = _base_queryset(request, queryset_hook).select_related(*detail_schema.SELECT_RELATED).prefetch_related(*detail_schema.PREFETCH_RELATED)
        qs = plan_queryset(qs, select_related, prefetch)
        obj = qs.filter(pk=engagement_id).first()
        if obj is None:
            msg = f"Engagement {engagement_id} not found"
            raise not_found_problem(msg)
        fields = parse_fields(request.GET.get("fields"), allowed_field_names(detail_schema))
        return json_response(apply_fields(serialize(obj, detail_schema, expand_tree), fields))

    @router.post("/engagements", response=detail_schema, url_name="engagements_create")
    def create_engagement(request: HttpRequest, payload: EngagementWrite):
        data = payload.dict()
        tags = data.pop("tags")
        product_id = data.pop("product")
        # Mirror check_post_permission(request, Product, "product", "add"): 404 if the target
        # product doesn't exist, 403 if the user can't add engagements to it.
        product = get_object_or_none(Product, pk=product_id)
        if product is None:
            msg = f"Product {product_id} not found"
            raise not_found_problem(msg)
        if not user_has_permission(request.user, product, Permissions.Engagement_Add):
            raise PermissionDenied
        _validate_dates(data.get("target_start"), data.get("target_end"))

        instance = Engagement(product=product)
        _apply_scalars(instance, {k: v for k, v in data.items() if v is not None})
        try:
            instance.save()
        except DjangoValidationError as exc:
            raise _validation_from_django(exc) from exc
        if tags is not None:
            instance.tags = tags
            instance.save()
        return json_response(serialize(instance, detail_schema, {}), status=201)

    @router.patch("/engagements/{int:engagement_id}", response=detail_schema, url_name="engagements_update")
    def update_engagement(request: HttpRequest, engagement_id: int, payload: EngagementUpdate):
        instance = _base_queryset(request, queryset_hook).filter(pk=engagement_id).first()
        if instance is None:
            msg = f"Engagement {engagement_id} not found"
            raise not_found_problem(msg)  # 404: unknown or unauthorized-to-view
        if not user_has_permission(request.user, instance, Permissions.Engagement_Edit):
            raise PermissionDenied  # 403: visible but not editable

        data = payload.dict(exclude_unset=True)
        tags = data.pop("tags", _UNSET)
        if "product" in data:
            new_product_id = data.pop("product")
            # Mirror check_update_permission: only re-check `add` when the FK actually changes.
            if new_product_id is not None and new_product_id != instance.product_id:
                new_product = get_object_or_none(Product, pk=new_product_id)
                if new_product is None:
                    msg = f"Product {new_product_id} not found"
                    raise not_found_problem(msg)
                if not user_has_permission(request.user, new_product, Permissions.Engagement_Add):
                    raise PermissionDenied
                instance.product = new_product

        target_start = data.get("target_start", instance.target_start)
        target_end = data.get("target_end", instance.target_end)
        _validate_dates(target_start, target_end)

        _apply_scalars(instance, data)
        if tags is not _UNSET:
            instance.tags = tags if tags is not None else []
        try:
            instance.save()
        except DjangoValidationError as exc:
            raise _validation_from_django(exc) from exc
        return json_response(serialize(instance, detail_schema, {}))

    @router.delete("/engagements/{int:engagement_id}", url_name="engagements_delete")
    def delete_engagement(request: HttpRequest, engagement_id: int):
        instance = _base_queryset(request, queryset_hook).filter(pk=engagement_id).first()
        if instance is None:
            msg = f"Engagement {engagement_id} not found"
            raise not_found_problem(msg)
        if not user_has_permission(request.user, instance, Permissions.Engagement_Delete):
            raise PermissionDenied
        _destroy(instance)
        response = HttpResponse(status=204)
        response["X-API-Status"] = settings.API_V3_STATUS
        return response

    return router
