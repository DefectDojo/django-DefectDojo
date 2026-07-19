"""
Product response + write schemas for API v3 (§4.5, §4.11, OS3a).

``ProductSlim`` is the canonical parent slim (relocated here from ``dojo/finding/api_v3`` where OS1
first defined it -- see §12; the finding module now re-exports this copy). ``ProductDetail`` adds the
documented heavier read fields (§4.5). ``product_type`` is an expandable relation (§4.6).

Write schemas mirror the v2 ``ProductSerializer`` required/optional split: the model requires
``name``, ``description`` and ``prod_type``; everything else is optional (``sla_configuration``
defaults to the model default when omitted). Relations are referenced by integer id (§4.11);
server-managed fields are never writable; unknown fields are rejected (``extra="forbid"``).
"""
from __future__ import annotations

from datetime import datetime  # noqa: TC003 -- runtime import: pydantic resolves the schema field types
from typing import ClassVar

from ninja import Schema

from dojo.api_v3.expand import ExpandRel
from dojo.api_v3.refs import Ref, to_ref
from dojo.models import Product
from dojo.product_type.api_v3.schemas import ProductTypeSlim


class ProductSlim(Schema):
    django_model: ClassVar = Product
    SELECT_RELATED: ClassVar[tuple] = ("prod_type",)
    PREFETCH_RELATED: ClassVar[tuple] = ("tags",)
    EXPANDABLE: ClassVar[dict[str, ExpandRel]] = {}

    id: int
    name: str
    description: str | None
    product_type: Ref
    lifecycle: str | None
    tags: list[str]
    created: datetime | None
    updated: datetime | None

    @staticmethod
    def resolve_product_type(obj) -> dict | None:
        return to_ref(obj.prod_type)

    @staticmethod
    def resolve_tags(obj) -> list[str]:
        return [t.name for t in obj.tags.all()]


ProductSlim.EXPANDABLE = {
    "product_type": ExpandRel(attr="prod_type", path="prod_type", schema=ProductTypeSlim),
}


class ProductDetail(ProductSlim):

    """Slim + the documented heavier read fields (§4.5). Retrieve returns detail; list returns slim."""

    # Detail fetch pulls the extra parent FKs so the ref resolvers below issue no extra queries.
    SELECT_RELATED: ClassVar[tuple] = ("prod_type", "product_manager", "technical_contact", "team_manager")

    business_criticality: str | None
    platform: str | None
    origin: str | None
    external_audience: bool | None
    internet_accessible: bool | None
    product_manager: Ref | None
    technical_contact: Ref | None
    team_manager: Ref | None

    @staticmethod
    def resolve_product_manager(obj) -> dict | None:
        return to_ref(obj.product_manager)

    @staticmethod
    def resolve_technical_contact(obj) -> dict | None:
        return to_ref(obj.technical_contact)

    @staticmethod
    def resolve_team_manager(obj) -> dict | None:
        return to_ref(obj.team_manager)


class ProductWrite(Schema):

    """Create payload (POST). ``name``/``description``/``prod_type`` required (§6 OS3, mirrors v2)."""

    model_config = {"extra": "forbid"}

    name: str
    description: str
    prod_type: int
    business_criticality: str | None = None
    platform: str | None = None
    lifecycle: str | None = None
    origin: str | None = None
    product_manager: int | None = None
    technical_contact: int | None = None
    team_manager: int | None = None
    sla_configuration: int | None = None
    external_audience: bool | None = None
    internet_accessible: bool | None = None
    tags: list[str] | None = None


class ProductUpdate(Schema):

    """Partial update payload (PATCH). Every field optional; only provided keys are applied."""

    model_config = {"extra": "forbid"}

    name: str | None = None
    description: str | None = None
    prod_type: int | None = None
    business_criticality: str | None = None
    platform: str | None = None
    lifecycle: str | None = None
    origin: str | None = None
    product_manager: int | None = None
    technical_contact: int | None = None
    team_manager: int | None = None
    sla_configuration: int | None = None
    external_audience: bool | None = None
    internet_accessible: bool | None = None
    tags: list[str] | None = None
