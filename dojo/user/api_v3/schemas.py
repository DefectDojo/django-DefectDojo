"""
User (Dojo_User) response + write schemas for API v3 (§4.5, §4.11, OS3a).

``UserSlim`` is the canonical user slim (relocated here from ``dojo/finding/api_v3`` where OS1 first
defined it -- see §12; the finding module now re-exports this copy). Every field in §4.5's UserSlim
was verified against the model. ``UserDetail`` adds ``is_staff`` and ``date_joined`` so the
superuser/staff write rules operate over documented read fields.

Write schemas mirror the v2 ``UserSerializer``: ``username``/``email`` required on create,
``password`` write-only. The superuser/staff/self-delete/password-on-PATCH rules are enforced in
the route (ported from ``UserSerializer.validate()``). Server-managed fields (``id``,
``date_joined``, ``last_login``) are never writable; unknown fields are rejected (``extra="forbid"``).
``configuration_permissions`` is intentionally out of the alpha write surface (see §12).
"""
from __future__ import annotations

from datetime import datetime  # noqa: TC003 -- runtime import: pydantic resolves the schema field types
from typing import TYPE_CHECKING, ClassVar

from ninja import Schema

from dojo.models import Dojo_User

if TYPE_CHECKING:
    from dojo.api_v3.expand import ExpandRel


class UserSlim(Schema):
    django_model: ClassVar = Dojo_User
    SELECT_RELATED: ClassVar[tuple] = ()
    PREFETCH_RELATED: ClassVar[tuple] = ()
    EXPANDABLE: ClassVar[dict[str, ExpandRel]] = {}

    id: int
    username: str
    first_name: str
    last_name: str
    email: str
    is_active: bool
    is_superuser: bool
    last_login: datetime | None


class UserDetail(UserSlim):

    """Slim + documented heavier read fields (§4.5)."""

    is_staff: bool
    date_joined: datetime | None


class UserWrite(Schema):

    """Create payload (POST). ``username``/``email`` required, mirroring the v2 serializer (§6 OS3)."""

    model_config = {"extra": "forbid"}

    username: str
    email: str
    first_name: str = ""
    last_name: str = ""
    is_active: bool = True
    is_staff: bool = False
    is_superuser: bool = False
    password: str | None = None


class UserUpdate(Schema):

    """Partial update payload (PATCH). Every field optional; ``password`` is rejected here (§12)."""

    model_config = {"extra": "forbid"}

    username: str | None = None
    email: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    is_active: bool | None = None
    is_staff: bool | None = None
    is_superuser: bool | None = None
    password: str | None = None
