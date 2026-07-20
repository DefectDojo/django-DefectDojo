"""
Asset response + write schemas for API v3 (§4.5, §4.11, OS3a; renamed per D11).

**D11 wire rename:** v3 speaks the new domain language -- the ``Product`` model is exposed on the
wire as ``asset`` and its parent ``Product_Type`` FK as ``organization``. The schema classes are
``Asset*``; the Django model (``Product``) / DB table / module path are deliberately **not** renamed
(the DTO layer is what decouples wire names from models). See §12.

``AssetSlim`` is the canonical parent slim (relocated here from ``dojo/finding/api_v3`` where OS1
first defined it -- see §12; the finding module now re-exports this copy). ``AssetDetail`` adds the
documented heavier read fields (§4.5). ``organization`` is an expandable relation (§4.6).

Write schemas mirror the v2 ``ProductSerializer`` required/optional split: the model requires
``name``, ``description`` and ``prod_type`` (exposed on the wire as ``organization``); everything
else is optional (``sla_configuration`` defaults to the model default when omitted). Relations are
referenced by integer id (§4.11); server-managed fields are never writable; unknown fields are
rejected (``extra="forbid"``). The user-role ref ``asset_manager`` is the wire name for the model's
``product_manager`` FK (the UI relabel's canonical term is "Asset Manager"); ``critical_product`` /
``key_product`` (on ``organization``) keep their model-column names because the relabel itself
retains them (``org.critical_product_label``). See §12.
"""
from __future__ import annotations

from datetime import datetime  # noqa: TC003 -- runtime import: pydantic resolves the schema field types
from typing import ClassVar

from ninja import Schema

from dojo.api_v3.expand import ExpandRel
from dojo.api_v3.refs import Ref, to_ref
from dojo.models import Product
from dojo.product_type.api_v3.schemas import OrganizationSlim


class AssetSlim(Schema):
    django_model: ClassVar = Product
    SELECT_RELATED: ClassVar[tuple] = ("prod_type",)
    PREFETCH_RELATED: ClassVar[tuple] = ("tags",)
    EXPANDABLE: ClassVar[dict[str, ExpandRel]] = {}

    id: int
    name: str
    description: str | None
    organization: Ref
    lifecycle: str | None
    tags: list[str]
    created: datetime | None
    updated: datetime | None

    @staticmethod
    def resolve_organization(obj) -> dict | None:
        return to_ref(obj.prod_type)

    @staticmethod
    def resolve_tags(obj) -> list[str]:
        return [t.name for t in obj.tags.all()]


AssetSlim.EXPANDABLE = {
    "organization": ExpandRel(attr="prod_type", path="prod_type", schema=OrganizationSlim),
}


class AssetDetail(AssetSlim):

    """Slim + the documented heavier read fields (§4.5). Retrieve returns detail; list returns slim."""

    # Detail fetch pulls the extra parent FKs so the ref resolvers below issue no extra queries.
    SELECT_RELATED: ClassVar[tuple] = ("prod_type", "product_manager", "technical_contact", "team_manager")
    # Fixed joins for the user-role refs when a LIST ``?fields=`` opts up into them (§4.7 Part A). The
    # wire field ``asset_manager`` maps to the model FK ``product_manager`` (D11), so the join path is
    # declared here rather than derived from the wire name; added by the kernel only when requested.
    DETAIL_SELECT_RELATED: ClassVar[dict[str, tuple[str, ...]]] = {
        "asset_manager": ("product_manager",),
        "technical_contact": ("technical_contact",),
        "team_manager": ("team_manager",),
    }

    business_criticality: str | None
    platform: str | None
    origin: str | None
    external_audience: bool | None
    internet_accessible: bool | None
    asset_manager: Ref | None
    technical_contact: Ref | None
    team_manager: Ref | None

    @staticmethod
    def resolve_asset_manager(obj) -> dict | None:
        return to_ref(obj.product_manager)

    @staticmethod
    def resolve_technical_contact(obj) -> dict | None:
        return to_ref(obj.technical_contact)

    @staticmethod
    def resolve_team_manager(obj) -> dict | None:
        return to_ref(obj.team_manager)


class AssetWrite(Schema):

    """Create payload (POST). ``name``/``description``/``organization`` required (§6 OS3, mirrors v2)."""

    model_config = {"extra": "forbid"}

    name: str
    description: str
    organization: int
    business_criticality: str | None = None
    platform: str | None = None
    lifecycle: str | None = None
    origin: str | None = None
    asset_manager: int | None = None
    technical_contact: int | None = None
    team_manager: int | None = None
    sla_configuration: int | None = None
    external_audience: bool | None = None
    internet_accessible: bool | None = None
    tags: list[str] | None = None


class AssetUpdate(Schema):

    """Partial update payload (PATCH). Every field optional; only provided keys are applied."""

    model_config = {"extra": "forbid"}

    name: str | None = None
    description: str | None = None
    organization: int | None = None
    business_criticality: str | None = None
    platform: str | None = None
    lifecycle: str | None = None
    origin: str | None = None
    asset_manager: int | None = None
    technical_contact: int | None = None
    team_manager: int | None = None
    sla_configuration: int | None = None
    external_audience: bool | None = None
    internet_accessible: bool | None = None
    tags: list[str] | None = None
