"""
Finding response + write schemas for API v3 (§4.5, §4.11).

``FindingSlim`` (list) and ``FindingDetail`` (retrieve). Every schema is a named, importable,
subclassable ninja Schema (I4) and declares (as ``ClassVar`` so pydantic does not treat them as
fields):

- ``django_model``    -- the mapped model (used by the expand cycle guard),
- ``SELECT_RELATED`` / ``PREFETCH_RELATED`` -- the relation paths its resolvers read, so the
  expand planner can keep the query count constant,
- ``EXPANDABLE``      -- its expandable relations (§4.6).

The parent slims (``EngagementSlim``/``TestSlim``/``TestTypeSlim``/``EnvironmentSlim``/``ProductSlim``
/``ProductTypeSlim``/``UserSlim``) live in their own resource modules; this module **re-exports**
them (OS3a relocated product/product_type/user; OS3b relocated engagement/test) so there is exactly
one canonical class per model shared by the resource endpoints and the finding ``?expand=`` targets
(I4). See §12.

Write schemas (``FindingWrite`` create, ``FindingUpdate`` PATCH) are the editable subset of the
detail fields; required-vs-optional mirrors the v2 ``FindingCreateSerializer`` / ``FindingSerializer``.
Relations are referenced by integer id (§4.11); ``test`` is writable only on create
(``editable=False`` on the model, mirrors v2). Server-managed fields are never writable and unknown
fields are rejected (``extra="forbid"``). All side-effect / status-invariant validation lives in the
service (``dojo/finding/services.py``, D7); the schemas do field typing + strictness only.
"""
from __future__ import annotations

import datetime  # noqa: TC003 -- runtime import: pydantic resolves the schema field types
from typing import ClassVar

from ninja import Schema

from dojo.api_v3.expand import ExpandRel
from dojo.api_v3.refs import Ref, to_location_ref, to_ref

# Canonical parent slims live in their own resource modules; re-exported here so the finding
# expand targets (below) and the resource endpoints serialize through the same schema (I4, §12).
from dojo.engagement.api_v3.schemas import EngagementSlim
from dojo.models import Finding
from dojo.product.api_v3.schemas import ProductSlim
from dojo.product_type.api_v3.schemas import ProductTypeSlim
from dojo.test.api_v3.schemas import EnvironmentSlim, TestSlim, TestTypeSlim
from dojo.user.api_v3.schemas import UserSlim

__all__ = [
    "EngagementSlim",
    "EnvironmentSlim",
    "FindingDetail",
    "FindingSlim",
    "FindingUpdate",
    "FindingWrite",
    "ProductSlim",
    "ProductTypeSlim",
    "TestSlim",
    "TestTypeSlim",
    "UserSlim",
]


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
    date: datetime.date | None
    cwe: int | None
    test: Ref
    engagement: Ref
    product: Ref
    product_type: Ref
    reporter: Ref | None
    locations_count: int
    tags: list[str]
    created: datetime.datetime | None
    updated: datetime.datetime | None

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
    mitigated: datetime.datetime | None
    mitigated_by: Ref | None

    @staticmethod
    def resolve_mitigated_by(obj) -> dict | None:
        return to_ref(obj.mitigated_by)


# --- Write schemas (§4.11, §6 OS3 write-schema rule) ------------------------------------------

class FindingWrite(Schema):

    """
    Create payload (POST /findings). ``test``/``title``/``severity``/``description``/``active``/
    ``verified`` required (mirrors ``FindingCreateSerializer``: ``active``/``verified`` carry
    ``extra_kwargs required=True``). ``vulnerability_ids`` is a flat ``list[str]`` (§4.11); the
    service persists them and mirrors the first into the ``cve`` field. ``found_by`` references
    ``Test_Type`` ids; ``reporter``/``mitigated_by`` reference user ids.
    """

    model_config = {"extra": "forbid"}

    test: int
    title: str
    severity: str
    description: str
    active: bool
    verified: bool
    date: datetime.date | None = None
    cwe: int | None = None
    false_p: bool | None = None
    duplicate: bool | None = None
    out_of_scope: bool | None = None
    risk_accepted: bool | None = None
    is_mitigated: bool | None = None
    mitigation: str | None = None
    impact: str | None = None
    steps_to_reproduce: str | None = None
    severity_justification: str | None = None
    references: str | None = None
    file_path: str | None = None
    line: int | None = None
    mitigated: datetime.datetime | None = None
    mitigated_by: int | None = None
    reporter: int | None = None
    found_by: list[int] | None = None
    vulnerability_ids: list[str] | None = None
    tags: list[str] | None = None
    push_to_jira: bool = False


class FindingUpdate(Schema):

    """Partial update payload (PATCH). ``test`` is not writable (editable=False, mirrors v2)."""

    model_config = {"extra": "forbid"}

    title: str | None = None
    severity: str | None = None
    description: str | None = None
    active: bool | None = None
    verified: bool | None = None
    date: datetime.date | None = None
    cwe: int | None = None
    false_p: bool | None = None
    duplicate: bool | None = None
    out_of_scope: bool | None = None
    risk_accepted: bool | None = None
    is_mitigated: bool | None = None
    mitigation: str | None = None
    impact: str | None = None
    steps_to_reproduce: str | None = None
    severity_justification: str | None = None
    references: str | None = None
    file_path: str | None = None
    line: int | None = None
    mitigated: datetime.datetime | None = None
    mitigated_by: int | None = None
    reporter: int | None = None
    found_by: list[int] | None = None
    vulnerability_ids: list[str] | None = None
    tags: list[str] | None = None
    push_to_jira: bool = False
