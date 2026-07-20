"""
User (Dojo_User) CRUD routes for API v3 (§4.5, §4.9, §4.11, OS3a).

``build_users_router()`` is a router factory (I5), same signature style as ``build_findings_router``.
Routes are thin (I6): authorize -> filter -> plan queryset -> serialize -> shape.

RBAC (mirroring the v2 ``UsersViewSet``, read first):
- reads:  every authenticated user gets the collaborator-scoped view via ``get_authorized_users``
          (I8). This is the OS user-visibility model (superusers/staff see all; others see users
          sharing their authorized products/product-types, plus superusers). See §12 for why reads
          are opened to authenticated users rather than gated behind the ``view_user`` config perm.
- writes: admin/superuser-only, mirroring ``UserHasConfigurationPermissionSuperuser`` (the Django
          ``add_user``/``change_user``/``delete_user`` configuration permissions -- superusers pass
          automatically). The ``UserSerializer.validate()`` rules are ported verbatim: only
          superusers may add/edit superusers or staff; password is write-only and cannot be changed
          via PATCH; a password is required on create when ``REQUIRE_PASSWORD_ON_USER`` is set; and
          a user may not delete themselves (v2 ``destroy``).
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from django.conf import settings
from django.contrib.auth.password_validation import validate_password
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
from dojo.authorization.authorization import user_has_configuration_permission
from dojo.models import Dojo_User
from dojo.user.api_v3.schemas import UserDetail, UserSlim, UserUpdate, UserWrite
from dojo.user.queries import get_authorized_users

if TYPE_CHECKING:
    from collections.abc import Callable

    from django.db.models import QuerySet
    from django.http import HttpRequest

# --- User filter vocabulary (§4.9, minimal set) -----------------------------------------------

USER_FILTER_SPEC = register_filter_spec("user", FilterSpec(
    model=Dojo_User,
    filters={
        "id__in": filter_field("id", "in", "number"),
        "username__icontains": filter_field("username", "icontains", "char"),
        "first_name__icontains": filter_field("first_name", "icontains", "char"),
        "last_name__icontains": filter_field("last_name", "icontains", "char"),
        "email__icontains": filter_field("email", "icontains", "char"),
        "is_active": filter_field("is_active", "exact", "bool"),
        "is_superuser": filter_field("is_superuser", "exact", "bool"),
        "date_joined__gte": filter_field("date_joined", "gte", "datetime"),
        "date_joined__lte": filter_field("date_joined", "lte", "datetime"),
        "last_login__gte": filter_field("last_login", "gte", "datetime"),
        "last_login__lte": filter_field("last_login", "lte", "datetime"),
    },
    orderings={
        "id": "id",
        "username": "username",
        "date_joined": "date_joined",
        "last_login": "last_login",
    },
    search_fields=["username", "first_name", "last_name", "email"],
))


class UserListResponse(Schema):

    """OpenAPI documentation of the list envelope (I1); runtime serialization is manual."""

    count: int
    next: str | None
    previous: str | None
    results: list[UserSlim]
    meta: dict | None = None


def _base_queryset(request: HttpRequest, queryset_hook: Callable | None) -> QuerySet:
    # Mirror the v2 UsersViewSet ``view_user`` gate (§6 OS3 "read + self"; conservative per §10.2):
    # - holders of the ``view_user`` configuration permission get the RBAC-scoped queryset
    #   (superusers/staff -> all; a non-staff holder -> the collaborator subset, which is <= v2's
    #   "return all users" exposure);
    # - everyone else sees only themselves, so a plain user lists exactly their own record and
    #   ``GET /users/{own id}`` always resolves (never a 404 on your own record).
    if user_has_configuration_permission(request.user, "auth.view_user"):
        qs = get_authorized_users("view", user=request.user)
    else:
        qs = Dojo_User.objects.filter(pk=request.user.pk)
    if queryset_hook is not None:
        qs = queryset_hook(qs, request)
    return qs


def _require_config_permission(request: HttpRequest, codename: str) -> None:
    if not user_has_configuration_permission(request.user, codename):
        raise PermissionDenied


def _enforce_superuser_staff_rules(request: HttpRequest, *, current: Dojo_User | None, data: dict) -> None:
    """Port ``UserSerializer.validate()`` superuser/staff gating (§12 / D7 reconciliation)."""
    acting_is_superuser = bool(getattr(request.user, "is_superuser", False))
    instance_is_superuser = bool(current.is_superuser) if current is not None else False
    data_is_superuser = data.get("is_superuser", instance_is_superuser)
    if not acting_is_superuser and (instance_is_superuser or data_is_superuser):
        raise validation_problem({"is_superuser": ["Only superusers are allowed to add or edit superusers."]})

    instance_is_staff = bool(current.is_staff) if current is not None else False
    data_is_staff = data.get("is_staff", instance_is_staff)
    if not acting_is_superuser and data_is_staff != instance_is_staff:
        raise validation_problem({"is_staff": ["Only superusers are allowed to add or edit staff users."]})


def _validate_password_or_400(password: str) -> None:
    try:
        validate_password(password)
    except DjangoValidationError as exc:
        raise validation_problem({"password": list(exc.messages)}) from exc


def build_users_router(
    *,
    schema: type = UserSlim,
    detail_schema: type = UserDetail,
    filter_spec: FilterSpec = USER_FILTER_SPEC,
    queryset_hook: Callable | None = None,
    auth=NOT_SET,
) -> Router:
    """Build the users router (I5)."""
    router = Router(tags=["users"], auth=auth)

    @router.get("/users", response=UserListResponse, url_name="users_list")
    def list_users(request: HttpRequest):
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

    @router.get("/users/{int:user_id}", response=detail_schema, url_name="users_detail")
    def get_user(request: HttpRequest, user_id: int):
        obj = _base_queryset(request, queryset_hook).filter(pk=user_id).first()
        if obj is None:
            msg = f"User {user_id} not found"
            raise not_found_problem(msg)
        fields = parse_fields(request.GET.get("fields"), allowed_field_names(detail_schema))
        return json_response(apply_fields(serialize(obj, detail_schema, {}), fields))

    @router.post("/users", response=detail_schema, url_name="users_create")
    def create_user(request: HttpRequest, payload: UserWrite):
        _require_config_permission(request, "auth.add_user")
        data = payload.dict()
        password = data.pop("password")
        _enforce_superuser_staff_rules(request, current=None, data=data)
        if password:
            _validate_password_or_400(password)
        elif settings.REQUIRE_PASSWORD_ON_USER:
            raise validation_problem({"password": ["Passwords must be supplied for new users"]})
        if Dojo_User.objects.filter(username=data["username"]).exists():
            raise validation_problem({"username": ["A user with that username already exists."]})

        instance = Dojo_User(**data)
        if password:
            instance.set_password(password)
        else:
            instance.set_unusable_password()
        instance.save()
        return json_response(serialize(instance, detail_schema, {}), status=201)

    @router.patch("/users/{int:user_id}", response=detail_schema, url_name="users_update")
    def update_user(request: HttpRequest, user_id: int, payload: UserUpdate):
        # Resolve against the authorized view queryset first (404 for unknown-or-unauthorized).
        instance = _base_queryset(request, queryset_hook).filter(pk=user_id).first()
        if instance is None:
            msg = f"User {user_id} not found"
            raise not_found_problem(msg)
        _require_config_permission(request, "auth.change_user")
        data = payload.dict(exclude_unset=True)
        if "password" in data:
            raise validation_problem({"password": ["Update of password though API is not allowed"]})
        _enforce_superuser_staff_rules(request, current=instance, data=data)
        for key, value in data.items():
            setattr(instance, key, value)
        instance.save()
        return json_response(serialize(instance, detail_schema, {}))

    @router.delete("/users/{int:user_id}", url_name="users_delete")
    def delete_user(request: HttpRequest, user_id: int):
        instance = _base_queryset(request, queryset_hook).filter(pk=user_id).first()
        if instance is None:
            msg = f"User {user_id} not found"
            raise not_found_problem(msg)
        _require_config_permission(request, "auth.delete_user")
        if request.user.pk == instance.pk:
            # Mirror v2 UsersViewSet.destroy: users may not delete themselves.
            raise validation_problem({"non_field_errors": ["Users may not delete themselves"]})
        instance.delete()
        response = HttpResponse(status=204)
        response["X-API-Status"] = settings.API_V3_STATUS
        return response

    return router
