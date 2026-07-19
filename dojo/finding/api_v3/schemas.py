"""
Finding response schemas for API v3 (§4.5).

``FindingSlim`` (list) and ``FindingDetail`` (retrieve) plus the parent slim schemas needed to
serve ``?expand=`` targets (§4.6). Every schema is a named, importable, subclassable ninja Schema
(I4) and declares (as ``ClassVar`` so pydantic does not treat them as fields):

- ``django_model``    -- the mapped model (used by the expand cycle guard),
- ``SELECT_RELATED`` / ``PREFETCH_RELATED`` -- the relation paths its resolvers read, so the
  expand planner can keep the query count constant,
- ``EXPANDABLE``      -- its expandable relations (§4.6).

Slim = identity + primary status fields + parent refs + timestamps, with no per-row computed
fields (``locations_count`` is a queryset annotation, which is allowed). The parent slims live
here for OS1 (findings-only); OS3 relocates the canonical copies to their resource modules.
"""
from __future__ import annotations

from datetime import date, datetime  # noqa: TC003 -- runtime import: pydantic resolves the schema field types
from typing import ClassVar

from ninja import Schema

from dojo.api_v3.expand import ExpandRel
from dojo.api_v3.refs import Ref, to_location_ref, to_ref
from dojo.models import (
    Development_Environment,
    Dojo_User,
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
)


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


class ProductTypeSlim(Schema):
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


class FindingSlim(Schema):
    django_model: ClassVar = Finding
    # Base relation paths the finding resolvers read; applied by the route regardless of expand.
    SELECT_RELATED: ClassVar[tuple] = ("test__test_type", "test__engagement__product__prod_type", "reporter")
    PREFETCH_RELATED: ClassVar[tuple] = ("tags",)
    EXPANDABLE: ClassVar[dict[str, ExpandRel]] = {}

    id: int
    title: str
    severity: str
    active: bool
    verified: bool
    false_p: bool
    duplicate: bool
    risk_accepted: bool
    out_of_scope: bool
    is_mitigated: bool
    date: date | None
    cwe: int | None
    test: Ref
    engagement: Ref
    product: Ref
    product_type: Ref
    reporter: Ref | None
    locations_count: int
    tags: list[str]
    created: datetime | None
    updated: datetime | None

    @staticmethod
    def resolve_test(obj) -> dict | None:
        return to_ref(obj.test)

    @staticmethod
    def resolve_engagement(obj) -> dict | None:
        return to_ref(obj.test.engagement)

    @staticmethod
    def resolve_product(obj) -> dict | None:
        return to_ref(obj.test.engagement.product)

    @staticmethod
    def resolve_product_type(obj) -> dict | None:
        return to_ref(obj.test.engagement.product.prod_type)

    @staticmethod
    def resolve_reporter(obj) -> dict | None:
        return to_ref(obj.reporter)

    @staticmethod
    def resolve_locations_count(obj) -> int:
        return getattr(obj, "locations_count", 0) or 0

    @staticmethod
    def resolve_tags(obj) -> list[str]:
        return [t.name for t in obj.tags.all()]


def _finding_location_edges(finding) -> list[dict]:
    """
    ``expand=locations`` special renderer (§4.6): swap the cheap ``locations_count`` for the edge
    rows ``[{location: {id, name, type}, status, audit_time}]``. ``finding.locations`` is the
    ``LocationFindingReference`` reverse manager (edge carries ``status``/``audit_time``); the
    ``locations__location`` prefetch declared on the ExpandRel keeps the query count constant.
    """
    return [
        {
            "location": to_location_ref(ref.location),
            "status": ref.status,
            "audit_time": ref.audit_time,
        }
        for ref in finding.locations.all()
    ]


FindingSlim.EXPANDABLE = {
    "test": ExpandRel(attr="test", path="test", schema=TestSlim),
    "reporter": ExpandRel(attr="reporter", path="reporter", schema=UserSlim),
    "engagement": ExpandRel(attr="test.engagement", path="test__engagement", schema=EngagementSlim),
    "product": ExpandRel(attr="test.engagement.product", path="test__engagement__product", schema=ProductSlim),
    "product_type": ExpandRel(
        attr="test.engagement.product.prod_type",
        path="test__engagement__product__prod_type",
        schema=ProductTypeSlim,
    ),
    "locations": ExpandRel(
        attr="locations",
        path="locations",
        to_many=True,
        special=_finding_location_edges,
        prefetch_paths=("locations__location",),
        replaces="locations_count",
    ),
}


class FindingDetail(FindingSlim):

    """Slim + the documented heavier fields (§4.5). List returns slim; retrieve returns detail."""

    description: str | None
    mitigation: str | None
    impact: str | None
    steps_to_reproduce: str | None
    severity_justification: str | None
    references: str | None
    file_path: str | None
    line: int | None
    mitigated: datetime | None
    mitigated_by: Ref | None

    @staticmethod
    def resolve_mitigated_by(obj) -> dict | None:
        return to_ref(obj.mitigated_by)
