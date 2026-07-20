"""
Asset CRUD routes for API v3 (§4.5, §4.9, §4.11, OS3a; renamed per D11).

**D11 wire rename:** the ``Product`` model is exposed on the wire as ``asset`` and its parent
``Product_Type`` FK as ``organization`` -- paths (``/assets``), the OpenAPI tag, the filter registry
name, the schema classes and the write FK field (``organization`` -> model ``prod_type``) all use the
new domain language. The Django model / DB table / ``dojo/product/`` module path are **not** renamed
(see §12); ORM field paths, ``get_authorized_products`` and the ``Product_*`` permission enums keep
their names (they point at the real model). The wire field ``asset_manager`` maps to the model's
``product_manager`` FK (relabel term "Asset Manager"); ``technical_contact``/``team_manager`` are
unchanged (no product token). See §12.

``build_assets_router()`` is a router factory (I5), same signature style as ``build_findings_router``.
Routes are thin (I6): authorize -> filter -> plan queryset -> serialize -> shape. RBAC flows only
through ``get_authorized_products`` for reads (I8) and the v2 ``user_has_permission`` semantics for
writes, mirroring the v2 ``UserHasProductPermission`` class:

- create (POST):   ``add`` permission on the target organization (``prod_type``) in the payload
- update (PATCH):  object ``edit`` permission, plus ``add`` on a *reassigned* organization
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
from dojo.api_v3.expand import (
    allowed_field_names,
    apply_fields,
    parse_fields,
    plan,
    plan_list_fields,
    plan_queryset,
    serialize,
    serialize_list_row,
)
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
    AssetDetail,
    AssetReplace,
    AssetSlim,
    AssetUpdate,
    AssetWrite,
)
from dojo.product.queries import get_authorized_products
from dojo.utils import async_delete, get_object_or_none, get_setting

if TYPE_CHECKING:
    from collections.abc import Callable

    from django.db.models import QuerySet
    from django.http import HttpRequest

# --- Asset filter vocabulary (§4.9, minimal set) ----------------------------------------------

ASSET_FILTER_SPEC = register_filter_spec("asset", FilterSpec(
    model=Product,
    filters={
        "id__in": filter_field("id", "in", "number"),
        "name__icontains": filter_field("name", "icontains", "char"),
        "organization": filter_field("prod_type", "exact", "number"),
        "organization__in": filter_field("prod_type", "in", "number"),
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

# Wire write-field -> model attribute for the user-role FKs. ``asset_manager`` is the D11 wire name
# for the model's ``product_manager`` FK; the other two are unchanged (no product token).
_USER_FK_FIELDS = {
    "asset_manager": "product_manager",
    "technical_contact": "technical_contact",
    "team_manager": "team_manager",
}

# Sentinel distinguishing "tags omitted" from "tags set to null/empty" on PATCH.
_UNSET = object()


class AssetListResponse(Schema):

    """OpenAPI documentation of the list envelope (I1); runtime serialization is manual."""

    count: int
    next: str | None
    previous: str | None
    results: list[AssetSlim]
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
    for wire_field, model_attr in _USER_FK_FIELDS.items():
        if wire_field in data:
            pk = data.pop(wire_field)
            setattr(instance, model_attr, _resolve_user_fk(wire_field, pk) if pk is not None else None)
    if "sla_configuration" in data:
        pk = data.pop("sla_configuration")
        if pk is not None:
            sla = get_object_or_none(SLA_Configuration, pk=pk)
            if sla is None:
                raise validation_problem({"sla_configuration": [f"SLA configuration {pk} does not exist"]})
            instance.sla_configuration = sla
    for key, value in data.items():
        setattr(instance, key, value)


def build_assets_router(
    *,
    schema: type = AssetSlim,
    detail_schema: type = AssetDetail,
    filter_spec: FilterSpec = ASSET_FILTER_SPEC,
    queryset_hook: Callable | None = None,
    auth=NOT_SET,
) -> Router:
    """Build the assets router (I5)."""
    router = Router(tags=["assets"], auth=auth)

    @router.get("/assets", response=AssetListResponse, url_name="assets_list")
    def list_assets(request: HttpRequest):
        filtered = apply_filters(request, _base_queryset(request, queryset_hook), filter_spec)

        expand_tree, select_related, prefetch = plan(schema, request.GET.get("expand"))
        # ?fields= may opt up into the detail field set (§4.7 Part A); defer the heavy detail
        # columns not requested (Part B).
        fields = parse_fields(request.GET.get("fields"), allowed_field_names(detail_schema))
        fplan = plan_list_fields(schema, detail_schema, fields)
        page_qs = filtered.select_related(*schema.SELECT_RELATED, *fplan.select_related).prefetch_related(*schema.PREFETCH_RELATED)
        page_qs = plan_queryset(page_qs, select_related, prefetch)
        if fplan.defer:
            page_qs = page_qs.defer(*fplan.defer)

        def serialize_row(obj: object) -> dict:
            return serialize_list_row(obj, fplan, expand_tree)

        envelope = paginate(request, count_qs=filtered, page_qs=page_qs, serialize=serialize_row)
        include_meta = apply_includes(request, filtered, allowed=set())
        if include_meta:
            envelope.setdefault("meta", {}).update(include_meta)
        return json_response(envelope)

    @router.get("/assets/{int:asset_id}", response=detail_schema, url_name="assets_detail")
    def get_asset(request: HttpRequest, asset_id: int):
        expand_tree, select_related, prefetch = plan(detail_schema, request.GET.get("expand"))
        qs = _base_queryset(request, queryset_hook).select_related(*detail_schema.SELECT_RELATED).prefetch_related(*detail_schema.PREFETCH_RELATED)
        qs = plan_queryset(qs, select_related, prefetch)
        obj = qs.filter(pk=asset_id).first()
        if obj is None:
            msg = f"Asset {asset_id} not found"
            raise not_found_problem(msg)
        fields = parse_fields(request.GET.get("fields"), allowed_field_names(detail_schema))
        return json_response(apply_fields(serialize(obj, detail_schema, expand_tree), fields))

    @router.post("/assets", response=detail_schema, url_name="assets_create")
    def create_asset(request: HttpRequest, payload: AssetWrite):
        data = payload.dict()
        tags = data.pop("tags")
        organization_id = data.pop("organization")
        # Mirror check_post_permission(request, Product_Type, "prod_type", "add"): 404 if the target
        # organization doesn't exist, 403 if the user can't add assets to it.
        prod_type = get_object_or_none(Product_Type, pk=organization_id)
        if prod_type is None:
            msg = f"Organization {organization_id} not found"
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

    @router.patch("/assets/{int:asset_id}", response=detail_schema, url_name="assets_update")
    def update_asset(request: HttpRequest, asset_id: int, payload: AssetUpdate):
        instance = _base_queryset(request, queryset_hook).filter(pk=asset_id).first()
        if instance is None:
            msg = f"Asset {asset_id} not found"
            raise not_found_problem(msg)  # 404: unknown or unauthorized-to-view
        if not user_has_permission(request.user, instance, Permissions.Product_Edit):
            raise PermissionDenied  # 403: visible but not editable

        data = payload.dict(exclude_unset=True)
        tags = data.pop("tags", _UNSET)
        if "organization" in data:
            new_org_id = data.pop("organization")
            # Mirror check_update_permission: only re-check when the FK actually changes.
            if new_org_id is not None and new_org_id != instance.prod_type_id:
                new_pt = get_object_or_none(Product_Type, pk=new_org_id)
                if new_pt is None:
                    msg = f"Organization {new_org_id} not found"
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

    @router.put("/assets/{int:asset_id}", response=detail_schema, url_name="assets_replace")
    def replace_asset(request: HttpRequest, asset_id: int, payload: AssetReplace):
        # Full replace (PUT). Validates against the create-shaped AssetReplace (required
        # name/description/organization, extra="forbid") and applies payload.dict() WITHOUT
        # exclude_unset, so omitted optionals reset to their schema defaults (§4.11). Permission
        # ladder identical to PATCH: authorized-view resolve (404) then object Edit (403); the
        # required organization is re-authorized only when it actually changes (mirrors PATCH).
        instance = _base_queryset(request, queryset_hook).filter(pk=asset_id).first()
        if instance is None:
            msg = f"Asset {asset_id} not found"
            raise not_found_problem(msg)  # 404: unknown or unauthorized-to-view
        if not user_has_permission(request.user, instance, Permissions.Product_Edit):
            raise PermissionDenied  # 403: visible but not editable

        data = payload.dict()
        tags = data.pop("tags")
        new_org_id = data.pop("organization")
        if new_org_id != instance.prod_type_id:
            new_pt = get_object_or_none(Product_Type, pk=new_org_id)
            if new_pt is None:
                msg = f"Organization {new_org_id} not found"
                raise not_found_problem(msg)
            if not user_has_permission(request.user, new_pt, Permissions.Product_Type_Add_Product):
                raise PermissionDenied
            instance.prod_type = new_pt

        _apply_optional_relations_and_scalars(instance, data)
        instance.tags = tags if tags is not None else []
        try:
            instance.save()
        except DjangoValidationError as exc:
            raise _validation_from_django(exc) from exc
        return json_response(serialize(instance, detail_schema, {}))

    @router.delete("/assets/{int:asset_id}", url_name="assets_delete")
    def delete_asset(request: HttpRequest, asset_id: int):
        instance = _base_queryset(request, queryset_hook).filter(pk=asset_id).first()
        if instance is None:
            msg = f"Asset {asset_id} not found"
            raise not_found_problem(msg)
        if not user_has_permission(request.user, instance, Permissions.Product_Delete):
            raise PermissionDenied
        _destroy(instance)
        response = HttpResponse(status=204)
        response["X-API-Status"] = settings.API_V3_STATUS
        return response

    return router
