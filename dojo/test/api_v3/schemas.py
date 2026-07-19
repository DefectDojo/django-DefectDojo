"""
Test response + write schemas for API v3 (§4.5, §4.11, OS3b).

``TestSlim`` (plus ``TestTypeSlim`` / ``EnvironmentSlim``) is the canonical Test slim -- relocated
here from ``dojo/finding/api_v3`` (where OS1 first defined it for finding ``?expand=``); the finding
module now re-exports these copies so there is exactly one class per model (verified is-identity in
the tests -- see §12). ``TestDetail`` adds the documented heavier read fields (§4.5).
``test_type``/``engagement``/``product``/``product_type``/``environment``/``lead`` are expandable
relations (§4.6).

Write schemas mirror the v2 ``TestCreateSerializer`` (create) and ``TestSerializer`` (update): the
model requires ``engagement``, ``test_type``, ``target_start`` and ``target_end``. ``engagement`` is
``editable=False`` on the model, so it is writable **only on create** (mirrors v2 -- the update
serializer treats it as read-only). Relations are referenced by integer id (§4.11); server-managed /
``editable=False`` fields (``id``, ``created``, ``updated``, ``notes``, ``files``) are never
writable; unknown fields are rejected (``extra="forbid"``).
"""
from __future__ import annotations

from datetime import datetime  # noqa: TC003 -- runtime import: pydantic resolves the schema field types
from typing import ClassVar

from ninja import Schema

from dojo.api_v3.expand import ExpandRel
from dojo.api_v3.refs import Ref, to_ref
from dojo.engagement.api_v3.schemas import EngagementSlim
from dojo.models import Development_Environment, Test, Test_Type
from dojo.product.api_v3.schemas import ProductSlim
from dojo.product_type.api_v3.schemas import ProductTypeSlim
from dojo.user.api_v3.schemas import UserSlim


class TestTypeSlim(Schema):
    django_model: ClassVar = Test_Type
    SELECT_RELATED: ClassVar[tuple] = ()
    PREFETCH_RELATED: ClassVar[tuple] = ()
    EXPANDABLE: ClassVar[dict[str, ExpandRel]] = {}

    id: int
    name: str
    active: bool | None


class EnvironmentSlim(Schema):
    django_model: ClassVar = Development_Environment
    SELECT_RELATED: ClassVar[tuple] = ()
    PREFETCH_RELATED: ClassVar[tuple] = ()
    EXPANDABLE: ClassVar[dict[str, ExpandRel]] = {}

    id: int
    name: str


class TestSlim(Schema):
    django_model: ClassVar = Test
    SELECT_RELATED: ClassVar[tuple] = ("test_type", "engagement__product__prod_type", "environment", "lead")
    PREFETCH_RELATED: ClassVar[tuple] = ("tags",)
    EXPANDABLE: ClassVar[dict[str, ExpandRel]] = {}

    id: int
    name: str | None
    test_type: Ref
    engagement: Ref
    product: Ref
    product_type: Ref
    environment: Ref | None
    lead: Ref | None
    target_start: datetime | None
    target_end: datetime | None
    percent_complete: int | None
    tags: list[str]
    created: datetime | None
    updated: datetime | None

    @staticmethod
    def resolve_name(obj) -> str | None:
        return obj.title

    @staticmethod
    def resolve_test_type(obj) -> dict | None:
        return to_ref(obj.test_type)

    @staticmethod
    def resolve_engagement(obj) -> dict | None:
        return to_ref(obj.engagement)

    @staticmethod
    def resolve_product(obj) -> dict | None:
        return to_ref(obj.engagement.product)

    @staticmethod
    def resolve_product_type(obj) -> dict | None:
        return to_ref(obj.engagement.product.prod_type)

    @staticmethod
    def resolve_environment(obj) -> dict | None:
        return to_ref(obj.environment)

    @staticmethod
    def resolve_lead(obj) -> dict | None:
        return to_ref(obj.lead)

    @staticmethod
    def resolve_tags(obj) -> list[str]:
        return [t.name for t in obj.tags.all()]


TestSlim.EXPANDABLE = {
    "test_type": ExpandRel(attr="test_type", path="test_type", schema=TestTypeSlim),
    "engagement": ExpandRel(attr="engagement", path="engagement", schema=EngagementSlim),
    "product": ExpandRel(attr="engagement.product", path="engagement__product", schema=ProductSlim),
    "product_type": ExpandRel(attr="engagement.product.prod_type", path="engagement__product__prod_type", schema=ProductTypeSlim),
    "lead": ExpandRel(attr="lead", path="lead", schema=UserSlim),
    "environment": ExpandRel(attr="environment", path="environment", schema=EnvironmentSlim),
}


class TestDetail(TestSlim):

    """Slim + the documented heavier read fields (§4.5). Retrieve returns detail; list returns slim."""

    description: str | None
    scan_type: str | None
    version: str | None
    build_id: str | None
    commit_hash: str | None
    branch_tag: str | None


class TestWrite(Schema):

    """Create payload (POST). ``engagement``/``test_type``/``target_start``/``target_end`` required."""

    model_config = {"extra": "forbid"}

    engagement: int
    test_type: int
    target_start: datetime
    target_end: datetime
    title: str | None = None
    description: str | None = None
    scan_type: str | None = None
    lead: int | None = None
    percent_complete: int | None = None
    environment: int | None = None
    version: str | None = None
    build_id: str | None = None
    commit_hash: str | None = None
    branch_tag: str | None = None
    api_scan_configuration: int | None = None
    tags: list[str] | None = None


class TestUpdate(Schema):

    """Partial update payload (PATCH). ``engagement`` is not writable (editable=False, mirrors v2)."""

    model_config = {"extra": "forbid"}

    test_type: int | None = None
    target_start: datetime | None = None
    target_end: datetime | None = None
    title: str | None = None
    description: str | None = None
    scan_type: str | None = None
    lead: int | None = None
    percent_complete: int | None = None
    environment: int | None = None
    version: str | None = None
    build_id: str | None = None
    commit_hash: str | None = None
    branch_tag: str | None = None
    api_scan_configuration: int | None = None
    tags: list[str] | None = None
