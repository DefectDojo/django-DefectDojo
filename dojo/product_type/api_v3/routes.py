"""
Product_Type CRUD routes for API v3 (§4.5, §4.9, §4.11, OS3a).

``build_product_types_router()`` is a router factory (I5), same signature style as
``build_findings_router``. Routes are thin (I6): authorize -> filter -> plan queryset -> serialize
-> shape. RBAC flows only through ``get_authorized_product_types`` for reads (I8) and the v2
``user_has_permission``/``user_has_global_permission`` semantics for writes, mirroring the v2
``UserHasProductTypePermission`` permission class exactly:

- create (POST):   global ``add`` permission (``user_has_global_permission(user, "add")``)
- update (PATCH):  object ``edit`` permission
- delete (DELETE): object ``delete`` permission (staff-only for non-staff members, per the legacy model)
- read:            object ``view`` via the authorized queryset (404 for unknown-or-unauthorized)

Deletion mirrors the v2 ``ProductTypeViewSet.destroy`` exactly: async delete when
``ASYNC_OBJECT_DELETE`` is set, else a synchronous delete inside ``Endpoint.allow_endpoint_init()``
(required while ``V3_FEATURE_LOCATIONS`` is on -- see §12).
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
from dojo.authorization.authorization import user_has_global_permission, user_has_permission
from dojo.authorization.roles_permissions import Permissions
from dojo.models import Endpoint, Product_Type
from dojo.product_type.api_v3.schemas import (
    ProductTypeDetail,
    ProductTypeSlim,
    ProductTypeUpdate,
    ProductTypeWrite,
)
from dojo.product_type.queries import get_authorized_product_types
from dojo.utils import async_delete, get_setting

if TYPE_CHECKING:
    from collections.abc import Callable

    from django.db.models import QuerySet
    from django.http import HttpRequest

# --- Product_Type filter vocabulary (§4.9, minimal set) ---------------------------------------

PRODUCT_TYPE_FILTER_SPEC = register_filter_spec("product_type", FilterSpec(
    model=Product_Type,
    filters={
        "id__in": filter_field("id", "in", "number"),
        "name__icontains": filter_field("name", "icontains", "char"),
        "created__gte": filter_field("created", "gte", "datetime"),
        "created__lte": filter_field("created", "lte", "datetime"),
        "updated__gte": filter_field("updated", "gte", "datetime"),
        "updated__lte": filter_field("updated", "lte", "datetime"),
    },
    orderings={
        "id": "id",
        "name": "name",
        "created": "created",
        "updated": "updated",
    },
    search_fields=["name", "description"],
))


class ProductTypeListResponse(Schema):

    """OpenAPI documentation of the list envelope (I1); runtime serialization is manual."""

    count: int
    next: str | None
    previous: str | None
    results: list[ProductTypeSlim]
    meta: dict | None = None


def _base_queryset(request: HttpRequest, queryset_hook: Callable | None) -> QuerySet:
    # Reads flow only through the authorized queryset (I8). The OS helper resolves the current user
    # from crum (its signature takes no user kwarg), exactly as the v2 viewset relies on.
    qs = get_authorized_product_types(Permissions.Product_Type_View)
    if queryset_hook is not None:
        qs = queryset_hook(qs, request)
    return qs


def _validation_from_django(exc: DjangoValidationError) -> Exception:
    """Map a model ``full_clean`` failure onto the field-keyed problem+json contract (§4.10)."""
    if hasattr(exc, "message_dict"):
        return validation_problem({k: list(v) for k, v in exc.message_dict.items()})
    return validation_problem({"non_field_errors": list(exc.messages)})


def _destroy(instance: Product_Type) -> None:
    """Mirror v2 ``ProductTypeViewSet.destroy`` exactly (§12)."""
    if get_setting("ASYNC_OBJECT_DELETE"):
        async_delete().delete(instance)
    else:
        with Endpoint.allow_endpoint_init():  # TODO: remove after full move to Locations (mirrors v2)
            instance.delete()


def build_product_types_router(
    *,
    schema: type = ProductTypeSlim,
    detail_schema: type = ProductTypeDetail,
    filter_spec: FilterSpec = PRODUCT_TYPE_FILTER_SPEC,
    queryset_hook: Callable | None = None,
    auth=NOT_SET,
) -> Router:
    """Build the product_types router (I5)."""
    router = Router(tags=["product_types"], auth=auth)

    @router.get("/product_types", response=ProductTypeListResponse, url_name="product_types_list")
    def list_product_types(request: HttpRequest):
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

    @router.get("/product_types/{int:product_type_id}", response=detail_schema, url_name="product_types_detail")
    def get_product_type(request: HttpRequest, product_type_id: int):
        expand_tree, select_related, prefetch = plan(detail_schema, request.GET.get("expand"))
        qs = _base_queryset(request, queryset_hook).select_related(*detail_schema.SELECT_RELATED).prefetch_related(*detail_schema.PREFETCH_RELATED)
        qs = plan_queryset(qs, select_related, prefetch)
        obj = qs.filter(pk=product_type_id).first()
        if obj is None:
            msg = f"Product_Type {product_type_id} not found"
            raise not_found_problem(msg)
        fields = parse_fields(request.GET.get("fields"), allowed_field_names(detail_schema))
        return json_response(apply_fields(serialize(obj, detail_schema, expand_tree), fields))

    @router.post("/product_types", response=detail_schema, url_name="product_types_create")
    def create_product_type(request: HttpRequest, payload: ProductTypeWrite):
        # Mirror UserHasProductTypePermission: POST requires global "add".
        if not user_has_global_permission(request.user, "add"):
            raise PermissionDenied
        instance = Product_Type(**payload.dict())
        try:
            instance.save()
        except DjangoValidationError as exc:
            raise _validation_from_django(exc) from exc
        return json_response(serialize(instance, detail_schema, {}), status=201)

    @router.patch("/product_types/{int:product_type_id}", response=detail_schema, url_name="product_types_update")
    def update_product_type(request: HttpRequest, product_type_id: int, payload: ProductTypeUpdate):
        instance = _base_queryset(request, queryset_hook).filter(pk=product_type_id).first()
        if instance is None:
            msg = f"Product_Type {product_type_id} not found"
            raise not_found_problem(msg)  # 404: unknown or unauthorized-to-view
        if not user_has_permission(request.user, instance, Permissions.Product_Type_Edit):
            raise PermissionDenied  # 403: visible but not editable
        for key, value in payload.dict(exclude_unset=True).items():
            setattr(instance, key, value)
        try:
            instance.save()
        except DjangoValidationError as exc:
            raise _validation_from_django(exc) from exc
        return json_response(serialize(instance, detail_schema, {}))

    @router.delete("/product_types/{int:product_type_id}", url_name="product_types_delete")
    def delete_product_type(request: HttpRequest, product_type_id: int):
        instance = _base_queryset(request, queryset_hook).filter(pk=product_type_id).first()
        if instance is None:
            msg = f"Product_Type {product_type_id} not found"
            raise not_found_problem(msg)
        if not user_has_permission(request.user, instance, Permissions.Product_Type_Delete):
            raise PermissionDenied
        _destroy(instance)
        # 204 No Content: an empty body (not "null"); still carry the alpha status header (§4.1).
        response = HttpResponse(status=204)
        response["X-API-Status"] = settings.API_V3_STATUS
        return response

    return router
