"""
Test CRUD routes for API v3 (§4.5, §4.9, §4.11, OS3b).

``build_tests_router()`` is a router factory (I5), same shape as ``build_assets_router``. Routes
are thin (I6): authorize -> filter -> plan queryset -> serialize -> shape. RBAC flows only through
``get_authorized_tests`` for reads (I8) and the v2 ``user_has_permission`` semantics for writes,
mirroring the v2 ``UserHasTestPermission`` permission class exactly:

- create (POST):   ``add`` permission on the target ``engagement`` referenced in the payload
                   (404 if it doesn't exist, 403 if unauthorized -- mirrors
                   ``check_post_permission(request, Engagement, "engagement", "add")``), plus
                   ``view`` on ``api_scan_configuration`` when present (mirrors the ``required=False``
                   sibling check).
- update (PATCH):  object ``edit`` permission, plus ``view`` on a *reassigned*
                   ``api_scan_configuration`` (mirrors
                   ``check_update_permission(request, obj, "view", "api_scan_configuration")``).
                   ``engagement`` is not writable on update (``editable=False``, mirrors v2).
- delete (DELETE): object ``delete`` permission (staff-only for non-staff members, legacy model)
- read:            object ``view`` via the authorized queryset (404 for unknown-or-unauthorized)

Deletion mirrors the v2 ``TestsViewSet.destroy`` exactly: async delete when ``ASYNC_OBJECT_DELETE``
is set, else a plain synchronous ``instance.delete()`` (no ``Endpoint`` context wrapper -- §12).
Relations are referenced by integer id (§4.11).
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
from dojo.models import (
    Development_Environment,
    Dojo_User,
    Engagement,
    Product_API_Scan_Configuration,
    Test,
    Test_Type,
)
from dojo.test.api_v3.schemas import (
    TestDetail,
    TestSlim,
    TestUpdate,
    TestWrite,
)
from dojo.test.queries import get_authorized_tests
from dojo.utils import async_delete, get_object_or_none, get_setting

if TYPE_CHECKING:
    from collections.abc import Callable

    from django.db.models import QuerySet
    from django.http import HttpRequest

# --- Test filter vocabulary (§4.9, minimal set) -----------------------------------------------

TEST_FILTER_SPEC = register_filter_spec("test", FilterSpec(
    model=Test,
    filters={
        "id__in": filter_field("id", "in", "number"),
        "title__icontains": filter_field("title", "icontains", "char"),
        "engagement": filter_field("engagement", "exact", "number"),
        "engagement__in": filter_field("engagement", "in", "number"),
        "asset": filter_field("engagement__product", "exact", "number"),
        "asset__in": filter_field("engagement__product", "in", "number"),
        "organization": filter_field("engagement__product__prod_type", "exact", "number"),
        "test_type": filter_field("test_type", "exact", "number"),
        "environment": filter_field("environment", "exact", "number"),
        "lead": filter_field("lead", "exact", "number"),
        "target_start__gte": filter_field("target_start", "gte", "datetime"),
        "target_start__lte": filter_field("target_start", "lte", "datetime"),
        "target_end__gte": filter_field("target_end", "gte", "datetime"),
        "target_end__lte": filter_field("target_end", "lte", "datetime"),
        "created__gte": filter_field("created", "gte", "datetime"),
        "created__lte": filter_field("created", "lte", "datetime"),
        "updated__gte": filter_field("updated", "gte", "datetime"),
        "updated__lte": filter_field("updated", "lte", "datetime"),
    },
    orderings={
        "id": "id",
        "title": "title",
        "target_start": "target_start",
        "created": "created",
        "updated": "updated",
    },
    search_fields=["title", "description"],
))

# Sentinel distinguishing "tags omitted" from "tags set to null/empty" on PATCH.
_UNSET = object()

# Optional relation fields resolved by integer id (with existence validation -> 400).
_SIMPLE_FK = {
    "test_type": Test_Type,
    "environment": Development_Environment,
    "lead": Dojo_User,
}


class TestListResponse(Schema):

    """OpenAPI documentation of the list envelope (I1); runtime serialization is manual."""

    count: int
    next: str | None
    previous: str | None
    results: list[TestSlim]
    meta: dict | None = None


def _base_queryset(request: HttpRequest, queryset_hook: Callable | None) -> QuerySet:
    qs = get_authorized_tests(Permissions.Test_View)
    if queryset_hook is not None:
        qs = queryset_hook(qs, request)
    return qs


def _validation_from_django(exc: DjangoValidationError) -> Exception:
    if hasattr(exc, "message_dict"):
        return validation_problem({k: list(v) for k, v in exc.message_dict.items()})
    return validation_problem({"non_field_errors": list(exc.messages)})


def _resolve_simple_fk(field: str, pk: int):
    """Resolve a body-referenced FK by id (400 if it doesn't exist -- mirrors DRF PK validation)."""
    obj = get_object_or_none(_SIMPLE_FK[field], pk=pk)
    if obj is None:
        raise validation_problem({field: [f"{_SIMPLE_FK[field].__name__} {pk} does not exist"]})
    return obj


def _authorize_api_scan_configuration(request: HttpRequest, pk: int) -> Product_API_Scan_Configuration:
    """Mirror check_post_permission(..., 'view'): 404 if it doesn't exist, 403 if no view perm."""
    config = get_object_or_none(Product_API_Scan_Configuration, pk=pk)
    if config is None:
        msg = f"Product_API_Scan_Configuration {pk} not found"
        raise not_found_problem(msg)
    if not user_has_permission(request.user, config, Permissions.Product_API_Scan_Configuration_View):
        raise PermissionDenied
    return config


def _destroy(instance: Test) -> None:
    """Mirror v2 ``TestsViewSet.destroy`` exactly (no Endpoint context wrapper -- §12)."""
    if get_setting("ASYNC_OBJECT_DELETE"):
        async_delete().delete(instance)
    else:
        instance.delete()


def _apply_relations_and_scalars(request: HttpRequest, instance: Test, data: dict) -> None:
    for field in _SIMPLE_FK:
        if field in data:
            pk = data.pop(field)
            setattr(instance, field, _resolve_simple_fk(field, pk) if pk is not None else None)
    if "api_scan_configuration" in data:
        pk = data.pop("api_scan_configuration")
        instance.api_scan_configuration = _authorize_api_scan_configuration(request, pk) if pk is not None else None
    for key, value in data.items():
        setattr(instance, key, value)


def build_tests_router(
    *,
    schema: type = TestSlim,
    detail_schema: type = TestDetail,
    filter_spec: FilterSpec = TEST_FILTER_SPEC,
    queryset_hook: Callable | None = None,
    auth=NOT_SET,
) -> Router:
    """Build the tests router (I5)."""
    router = Router(tags=["tests"], auth=auth)

    @router.get("/tests", response=TestListResponse, url_name="tests_list")
    def list_tests(request: HttpRequest):
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

    @router.get("/tests/{int:test_id}", response=detail_schema, url_name="tests_detail")
    def get_test(request: HttpRequest, test_id: int):
        expand_tree, select_related, prefetch = plan(detail_schema, request.GET.get("expand"))
        qs = _base_queryset(request, queryset_hook).select_related(*detail_schema.SELECT_RELATED).prefetch_related(*detail_schema.PREFETCH_RELATED)
        qs = plan_queryset(qs, select_related, prefetch)
        obj = qs.filter(pk=test_id).first()
        if obj is None:
            msg = f"Test {test_id} not found"
            raise not_found_problem(msg)
        fields = parse_fields(request.GET.get("fields"), allowed_field_names(detail_schema))
        return json_response(apply_fields(serialize(obj, detail_schema, expand_tree), fields))

    @router.post("/tests", response=detail_schema, url_name="tests_create")
    def create_test(request: HttpRequest, payload: TestWrite):
        data = payload.dict()
        tags = data.pop("tags")
        engagement_id = data.pop("engagement")
        # Mirror check_post_permission(request, Engagement, "engagement", "add"): 404 if the target
        # engagement doesn't exist, 403 if the user can't add tests to it.
        engagement = get_object_or_none(Engagement, pk=engagement_id)
        if engagement is None:
            msg = f"Engagement {engagement_id} not found"
            raise not_found_problem(msg)
        if not user_has_permission(request.user, engagement, Permissions.Test_Add):
            raise PermissionDenied

        instance = Test(engagement=engagement)
        _apply_relations_and_scalars(request, instance, {k: v for k, v in data.items() if v is not None})
        try:
            instance.save()
        except DjangoValidationError as exc:
            raise _validation_from_django(exc) from exc
        if tags is not None:
            instance.tags = tags
            instance.save()
        return json_response(serialize(instance, detail_schema, {}), status=201)

    @router.patch("/tests/{int:test_id}", response=detail_schema, url_name="tests_update")
    def update_test(request: HttpRequest, test_id: int, payload: TestUpdate):
        instance = _base_queryset(request, queryset_hook).filter(pk=test_id).first()
        if instance is None:
            msg = f"Test {test_id} not found"
            raise not_found_problem(msg)  # 404: unknown or unauthorized-to-view
        if not user_has_permission(request.user, instance, Permissions.Test_Edit):
            raise PermissionDenied  # 403: visible but not editable

        data = payload.dict(exclude_unset=True)
        tags = data.pop("tags", _UNSET)
        _apply_relations_and_scalars(request, instance, data)
        if tags is not _UNSET:
            instance.tags = tags if tags is not None else []
        try:
            instance.save()
        except DjangoValidationError as exc:
            raise _validation_from_django(exc) from exc
        return json_response(serialize(instance, detail_schema, {}))

    @router.delete("/tests/{int:test_id}", url_name="tests_delete")
    def delete_test(request: HttpRequest, test_id: int):
        instance = _base_queryset(request, queryset_hook).filter(pk=test_id).first()
        if instance is None:
            msg = f"Test {test_id} not found"
            raise not_found_problem(msg)
        if not user_has_permission(request.user, instance, Permissions.Test_Delete):
            raise PermissionDenied
        _destroy(instance)
        response = HttpResponse(status=204)
        response["X-API-Status"] = settings.API_V3_STATUS
        return response

    return router
