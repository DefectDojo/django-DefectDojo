"""
Organization response + write schemas for API v3 (§4.5, §4.11, OS3a; renamed per D11).

**D11 wire rename:** v3 speaks the new domain language -- the ``Product_Type`` model is exposed on
the wire as ``organization``. The schema classes are ``Organization*`` and the Django model
(``Product_Type``) / DB table / module path are deliberately **not** renamed (the DTO layer is what
decouples wire names from models). See §12.

``OrganizationSlim`` is the canonical parent slim (relocated here from ``dojo/finding/api_v3`` where
OS1 first defined it -- see §12; the finding module now re-exports this copy so there is one class,
not two, keeping expand targets and this resource in lock-step). Every schema is a named,
importable, subclassable ninja ``Schema`` (I4) and declares the ``ClassVar`` machinery the expand
planner reads (``django_model``/``SELECT_RELATED``/``PREFETCH_RELATED``/``EXPANDABLE``).

Write schemas (``OrganizationWrite`` create, ``OrganizationUpdate`` PATCH) are the editable subset of
the detail fields; required-vs-optional mirrors the v2 ``ProductTypeSerializer`` (a ``ModelSerializer``
over the model -- ``name`` required, the rest defaulted). Server-managed fields (``id``/``created``/
``updated``) are never writable, and unknown fields are rejected (``extra="forbid"``) so write
validation is consistent with the kernel's strict query contract (§12). ``critical_product``/
``key_product`` keep their model-column names (D11 excludes DB columns; the UI relabel itself retains
them, e.g. ``org.critical_product_label`` -- see §12).
"""
from __future__ import annotations

from datetime import datetime  # noqa: TC003 -- runtime import: pydantic resolves the schema field types
from typing import TYPE_CHECKING, ClassVar

from ninja import Schema

from dojo.models import Product_Type

if TYPE_CHECKING:
    from dojo.api_v3.expand import ExpandRel


class OrganizationSlim(Schema):
    django_model: ClassVar = Product_Type
    SELECT_RELATED: ClassVar[tuple] = ()
    PREFETCH_RELATED: ClassVar[tuple] = ()
    EXPANDABLE: ClassVar[dict[str, ExpandRel]] = {}

    id: int
    name: str
    description: str | None
    critical_product: bool | None
    key_product: bool | None
    created: datetime | None
    updated: datetime | None


class OrganizationDetail(OrganizationSlim):

    """Detail (retrieve) shape. Organization has no heavier read fields today, so it equals slim."""


class OrganizationWrite(Schema):

    """Create payload (POST). ``name`` is required; the rest mirror the model defaults (§6 OS3)."""

    model_config = {"extra": "forbid"}

    name: str
    description: str | None = None
    critical_product: bool = False
    key_product: bool = False


class OrganizationUpdate(Schema):

    """Partial update payload (PATCH). Every field optional; only provided keys are applied."""

    model_config = {"extra": "forbid"}

    name: str | None = None
    description: str | None = None
    critical_product: bool | None = None
    key_product: bool | None = None
