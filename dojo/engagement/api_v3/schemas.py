"""
Engagement response + write schemas for API v3 (§4.5, §4.11, OS3b).

``EngagementSlim`` is the canonical Engagement slim -- relocated here from ``dojo/finding/api_v3``
(where OS1 first defined it so finding ``?expand=`` had a target); the finding module now re-exports
this copy so there is exactly one class per model (verified is-identity in the tests, mirroring the
OS3a relocation pattern -- see §12). ``EngagementDetail`` adds the documented heavier read fields
(§4.5). ``product``/``product_type``/``lead`` are expandable relations (§4.6).

Write schemas mirror the v2 ``EngagementSerializer`` (a ``ModelSerializer`` excluding
``inherited_tags``): the model requires ``target_start``, ``target_end`` and ``product``; everything
else is optional. Relations are referenced by integer id (§4.11); ``editable=False`` /
server-managed fields (``active``, ``notes``, ``files``, ``progress``, ``risk_acceptance``,
``done_testing``, ``id``, ``created``, ``updated``) are never writable; unknown fields are rejected
(``extra="forbid"``).
"""
from __future__ import annotations

from datetime import date, datetime  # noqa: TC003 -- runtime import: pydantic resolves the schema field types
from typing import ClassVar

from ninja import Schema

from dojo.api_v3.expand import ExpandRel
from dojo.api_v3.refs import Ref, to_ref
from dojo.models import Engagement
from dojo.product.api_v3.schemas import ProductSlim
from dojo.product_type.api_v3.schemas import ProductTypeSlim
from dojo.user.api_v3.schemas import UserSlim


class EngagementSlim(Schema):
    django_model: ClassVar = Engagement
    SELECT_RELATED: ClassVar[tuple] = ("product__prod_type", "lead")
    PREFETCH_RELATED: ClassVar[tuple] = ("tags",)
    EXPANDABLE: ClassVar[dict[str, ExpandRel]] = {}

    id: int
    name: str | None
    product: Ref
    product_type: Ref
    lead: Ref | None
    status: str | None
    engagement_type: str | None
    target_start: date | None
    target_end: date | None
    active: bool | None
    tags: list[str]
    created: datetime | None
    updated: datetime | None

    @staticmethod
    def resolve_product(obj) -> dict | None:
        return to_ref(obj.product)

    @staticmethod
    def resolve_product_type(obj) -> dict | None:
        return to_ref(obj.product.prod_type)

    @staticmethod
    def resolve_lead(obj) -> dict | None:
        return to_ref(obj.lead)

    @staticmethod
    def resolve_tags(obj) -> list[str]:
        return [t.name for t in obj.tags.all()]


EngagementSlim.EXPANDABLE = {
    "product": ExpandRel(attr="product", path="product", schema=ProductSlim),
    "product_type": ExpandRel(attr="product.prod_type", path="product__prod_type", schema=ProductTypeSlim),
    "lead": ExpandRel(attr="lead", path="lead", schema=UserSlim),
}


class EngagementDetail(EngagementSlim):

    """Slim + the documented heavier read fields (§4.5). Retrieve returns detail; list returns slim."""

    description: str | None
    version: str | None
    first_contacted: date | None
    reason: str | None
    tracker: str | None
    test_strategy: str | None
    threat_model: bool | None
    api_test: bool | None
    pen_test: bool | None
    check_list: bool | None
    build_id: str | None
    commit_hash: str | None
    branch_tag: str | None
    source_code_management_uri: str | None
    deduplication_on_engagement: bool | None


class EngagementWrite(Schema):

    """Create payload (POST). ``product``/``target_start``/``target_end`` required (mirrors v2)."""

    model_config = {"extra": "forbid"}

    product: int
    target_start: date
    target_end: date
    name: str | None = None
    description: str | None = None
    version: str | None = None
    first_contacted: date | None = None
    lead: int | None = None
    reason: str | None = None
    tracker: str | None = None
    test_strategy: str | None = None
    threat_model: bool | None = None
    api_test: bool | None = None
    pen_test: bool | None = None
    check_list: bool | None = None
    status: str | None = None
    engagement_type: str | None = None
    build_id: str | None = None
    commit_hash: str | None = None
    branch_tag: str | None = None
    source_code_management_uri: str | None = None
    deduplication_on_engagement: bool | None = None
    tags: list[str] | None = None


class EngagementUpdate(Schema):

    """Partial update payload (PATCH). Every field optional; only provided keys are applied."""

    model_config = {"extra": "forbid"}

    product: int | None = None
    target_start: date | None = None
    target_end: date | None = None
    name: str | None = None
    description: str | None = None
    version: str | None = None
    first_contacted: date | None = None
    lead: int | None = None
    reason: str | None = None
    tracker: str | None = None
    test_strategy: str | None = None
    threat_model: bool | None = None
    api_test: bool | None = None
    pen_test: bool | None = None
    check_list: bool | None = None
    status: str | None = None
    engagement_type: str | None = None
    build_id: str | None = None
    commit_hash: str | None = None
    branch_tag: str | None = None
    source_code_management_uri: str | None = None
    deduplication_on_engagement: bool | None = None
    tags: list[str] | None = None
