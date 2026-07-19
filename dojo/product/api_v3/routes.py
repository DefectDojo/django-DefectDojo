"""
Product CRUD routes for API v3 (§4.5, §4.9, §4.11, OS3a).

``build_products_router()`` is a router factory (I5), same signature style as
``build_findings_router``. Routes are thin (I6): authorize -> filter -> plan queryset -> serialize
-> shape. RBAC flows only through ``get_authorized_products`` for reads (I8) and the v2
``user_has_permission`` semantics for writes, mirroring the v2 ``UserHasProductPermission`` class:

- create (POST):   ``add`` permission on the target ``prod_type`` referenced in the payload
- update (PATCH):  object ``edit`` permission, plus ``add`` on a *reassigned* ``prod_type``
                   (mirrors ``check_update_permission(request, obj, "add", "prod_type")``)
- delete (DELETE): object ``delete`` permission (staff-only for non-staff members, legacy model)
- read:            object ``view`` via the authorized queryset (404 for unknown-or-unauthorized)

Deletion mirrors the v2 ``ProductViewSet.destroy`` exactly: async delete when
``ASYNC_OBJECT_DELETE`` is set, else a synchronous delete inside ``Endpoint.allow_endpoint_init()``
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
from dojo.models import Dojo_User, Endpoint, Product, Product_Type, SLA_Configuration
from dojo.product.api_v3.schemas import (
    ProductDetail,
    ProductSlim,
    ProductUpdate,
    ProductWrite,
)
from dojo.product.queries import get_authorized_products
from dojo.utils import async_delete, get_object_or_none, get_setting

if TYPE_CHECKING:
    from collections.abc import Callable

    from django.db.models import QuerySet
    from django.http import HttpRequest

# --- Product filter vocabulary (§4.9, minimal set) --------------------------------------------

PRODUCT_FILTER_SPEC = register_filter_spec("product", FilterSpec(
    model=Product,
    filters={
        "id__in": filter_field("id", "in", "number"),
        "name__icontains": filter_field("name", "icontains", "char"),
        "product_type": filter_field("prod_type", "exact", "number"),
        "product_type__in": filter_field("prod_type", "in", "number"),
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

_USER_FK_FIELDS = ("product_manager", "technical_contact", "team_manager")

# Sentinel distinguishing "tags omitted" from "tags set to null/empty" on PATCH.
_UNSET = object()


class ProductListResponse(Schema):

    """OpenAPI documentation of the list envelope (I1); runtime serialization is manual."""

    count: int
    next: str | None
    previous: str | None
    results: list[ProductSlim]
    meta: dict | None = None


def _base_queryset(request: HttpRequest, queryset_hook: Callable | None) -> QuerySet:
    qs = get_authorized_products(Permissions.Product_View, user=request.user)
    if queryset_hook is not None:
        qs = queryset_hook(qs, request)
    return qs


def _validation_from_django(exc: DjangoValidationError) -> Exception:
    if hasattr(exc, "message_dict"):
        return validation_problem({k: list(v) for k, v in exc.message_dict.items()})
    return validation_problem({"non_field_errors": list(exc.messages)})


def _resolve_user_fk(field: str, pk: int) -> Dojo_User:
    user = get_object_or_none(Dojo_User, pk=pk)
    if user is None:
        raise validation_problem({field: [f"user {pk} does not exist"]})
    return user


def _destroy(instance: Product) -> None:
    """Mirror v2 ``ProductViewSet.destroy`` exactly (§12)."""
    if get_setting("ASYNC_OBJECT_DELETE"):
        async_delete().delete(instance)
    else:
        with Endpoint.allow_endpoint_init():  # TODO: remove after full move to Locations (mirrors v2)
            instance.delete()


def _apply_optional_relations_and_scalars(instance: Product, data: dict) -> None:
    """Apply the user-FK, SLA and scalar fields present in ``data`` (create + update share this)."""
    for field in _USER_FK_FIELDS:
        if field in data:
            pk = data.pop(field)
            setattr(instance, field, _resolve_user_fk(field, pk) if pk is not None else None)
    if "sla_configuration" in data:
        pk = data.pop("sla_configuration")
        if pk is not None:
            sla = get_object_or_none(SLA_Configuration, pk=pk)
            if sla is None:
                raise validation_problem({"sla_configuration": [f"SLA configuration {pk} does not exist"]})
            instance.sla_configuration = sla
    for key, value in data.items():
        setattr(instance, key, value)


def build_products_router(
    *,
    schema: type = ProductSlim,
    detail_schema: type = ProductDetail,
    filter_spec: FilterSpec = PRODUCT_FILTER_SPEC,
    queryset_hook: Callable | None = None,
    auth=NOT_SET,
) -> Router:
    """Build the products router (I5)."""
    router = Router(tags=["products"], auth=auth)

    @router.get("/products", response=ProductListResponse, url_name="products_list")
    def list_products(request: HttpRequest):
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

    @router.get("/products/{int:product_id}", response=detail_schema, url_name="products_detail")
    def get_product(request: HttpRequest, product_id: int):
        expand_tree, select_related, prefetch = plan(detail_schema, request.GET.get("expand"))
        qs = _base_queryset(request, queryset_hook).select_related(*detail_schema.SELECT_RELATED).prefetch_related(*detail_schema.PREFETCH_RELATED)
        qs = plan_queryset(qs, select_related, prefetch)
        obj = qs.filter(pk=product_id).first()
        if obj is None:
            msg = f"Product {product_id} not found"
            raise not_found_problem(msg)
        fields = parse_fields(request.GET.get("fields"), allowed_field_names(detail_schema))
        return json_response(apply_fields(serialize(obj, detail_schema, expand_tree), fields))

    @router.post("/products", response=detail_schema, url_name="products_create")
    def create_product(request: HttpRequest, payload: ProductWrite):
        data = payload.dict()
        tags = data.pop("tags")
        prod_type_id = data.pop("prod_type")
        # Mirror check_post_permission(request, Product_Type, "prod_type", "add"): 404 if the
        # target product type doesn't exist, 403 if the user can't add products to it.
        prod_type = get_object_or_none(Product_Type, pk=prod_type_id)
        if prod_type is None:
            msg = f"Product_Type {prod_type_id} not found"
            raise not_found_problem(msg)
        if not user_has_permission(request.user, prod_type, Permissions.Product_Type_Add_Product):
            raise PermissionDenied
        instance = Product(prod_type=prod_type)
        # Drop unset (None) scalars so the model field defaults apply on create.
        _apply_optional_relations_and_scalars(instance, {k: v for k, v in data.items() if v is not None})
        if tags is not None:
            instance.tags = tags
        try:
            instance.save()
        except DjangoValidationError as exc:
            raise _validation_from_django(exc) from exc
        return json_response(serialize(instance, detail_schema, {}), status=201)

    @router.patch("/products/{int:product_id}", response=detail_schema, url_name="products_update")
    def update_product(request: HttpRequest, product_id: int, payload: ProductUpdate):
        instance = _base_queryset(request, queryset_hook).filter(pk=product_id).first()
        if instance is None:
            msg = f"Product {product_id} not found"
            raise not_found_problem(msg)  # 404: unknown or unauthorized-to-view
        if not user_has_permission(request.user, instance, Permissions.Product_Edit):
            raise PermissionDenied  # 403: visible but not editable

        data = payload.dict(exclude_unset=True)
        tags = data.pop("tags", _UNSET)
        if "prod_type" in data:
            new_pt_id = data.pop("prod_type")
            # Mirror check_update_permission: only re-check when the FK actually changes.
            if new_pt_id is not None and new_pt_id != instance.prod_type_id:
                new_pt = get_object_or_none(Product_Type, pk=new_pt_id)
                if new_pt is None:
                    msg = f"Product_Type {new_pt_id} not found"
                    raise not_found_problem(msg)
                if not user_has_permission(request.user, new_pt, Permissions.Product_Type_Add_Product):
                    raise PermissionDenied
                instance.prod_type = new_pt

        _apply_optional_relations_and_scalars(instance, data)
        if tags is not _UNSET:
            instance.tags = tags if tags is not None else []
        try:
            instance.save()
        except DjangoValidationError as exc:
            raise _validation_from_django(exc) from exc
        return json_response(serialize(instance, detail_schema, {}))

    @router.delete("/products/{int:product_id}", url_name="products_delete")
    def delete_product(request: HttpRequest, product_id: int):
        instance = _base_queryset(request, queryset_hook).filter(pk=product_id).first()
        if instance is None:
            msg = f"Product {product_id} not found"
            raise not_found_problem(msg)
        if not user_has_permission(request.user, instance, Permissions.Product_Delete):
            raise PermissionDenied
        _destroy(instance)
        response = HttpResponse(status=204)
        response["X-API-Status"] = settings.API_V3_STATUS
        return response

    return router
