"""
Location response schemas + the finding/product location edge schemas for API v3 (§4.5, §4.14, OS4).

``LocationSlim`` (list) and ``LocationDetail`` (retrieve). Every schema is a named, importable,
subclassable ninja Schema (I4) and declares (as ``ClassVar`` so pydantic does not treat them as
fields) ``django_model`` / ``SELECT_RELATED`` / ``PREFETCH_RELATED`` / ``EXPANDABLE`` -- the same
contract the kernel expand planner reads from every resource schema.

Locations are **read-only** in alpha (lifecycle is import-driven, §4.14). Only the ``URL`` location
subtype is persistable today (D5), so ``LocationDetail`` adds the URL-subtype fields
(``protocol/host/port/path/query/fragment``) pulled from the ``url`` reverse one-to-one; for a
non-URL location (none exist in alpha) those fields render ``null``.

``FindingLocationEdge`` / ``ProductLocationEdge`` document the edge-row shape of the
``/findings/{id}/locations`` and ``/products/{id}/locations`` sub-resources for OpenAPI (I1/I4);
their runtime serialization is manual dicts (like the list envelopes) so ``LocationRef`` is emitted
with its ``type`` field.
"""
from __future__ import annotations

import datetime  # noqa: TC003 -- runtime import: pydantic resolves the schema field types
from typing import TYPE_CHECKING, ClassVar

from django.core.exceptions import ObjectDoesNotExist
from ninja import Schema

# ``LocationRef``/``Ref`` are pydantic field types (runtime-resolved); ``to_location_ref``/``to_ref``
# back the edge-row serializers below (runtime) -- co-located with the edge schemas, mirroring the
# finding module's ``_finding_location_edges``.
from dojo.api_v3.refs import LocationRef, Ref, to_location_ref, to_ref
from dojo.location.models import Location

if TYPE_CHECKING:
    # Only referenced in a ClassVar annotation (never a pydantic field), so a typing-only import.
    from dojo.api_v3.expand import ExpandRel

__all__ = [
    "FindingLocationEdge",
    "FindingLocationListResponse",
    "LocationDetail",
    "LocationListResponse",
    "LocationSlim",
    "ProductLocationEdge",
    "ProductLocationListResponse",
    "finding_location_edge",
    "product_location_edge",
]


def _url_of(location: Location):
    """
    The location's ``URL`` subtype (reverse one-to-one), or ``None`` for a non-URL location. The
    reverse one-to-one accessor raises ``RelatedObjectDoesNotExist`` (an ``ObjectDoesNotExist``
    subtype) when absent; catch it so non-URL locations render null URL fields. Loaded via
    ``select_related("url")`` on the detail fetch so this issues no extra query.
    """
    try:
        return location.url
    except ObjectDoesNotExist:
        return None


class LocationSlim(Schema):
    django_model: ClassVar = Location
    SELECT_RELATED: ClassVar[tuple] = ()
    PREFETCH_RELATED: ClassVar[tuple] = ("tags",)
    EXPANDABLE: ClassVar[dict[str, ExpandRel]] = {}

    id: int
    name: str
    type: str
    tags: list[str]

    @staticmethod
    def resolve_name(obj) -> str:
        return obj.location_value

    @staticmethod
    def resolve_type(obj) -> str:
        return obj.location_type

    @staticmethod
    def resolve_tags(obj) -> list[str]:
        return [t.name for t in obj.tags.all()]


class LocationDetail(LocationSlim):

    """Slim + the URL-subtype detail fields (§4.5, §4.14). Retrieve/expand only; list is slim."""

    # The URL subtype is a reverse one-to-one; load it in the detail fetch so the resolvers below
    # issue no per-object query.
    SELECT_RELATED: ClassVar[tuple] = ("url",)

    protocol: str | None
    host: str | None
    port: int | None
    path: str | None
    query: str | None
    fragment: str | None

    @staticmethod
    def resolve_protocol(obj) -> str | None:
        url = _url_of(obj)
        return url.protocol if url is not None else None

    @staticmethod
    def resolve_host(obj) -> str | None:
        url = _url_of(obj)
        return url.host if url is not None else None

    @staticmethod
    def resolve_port(obj) -> int | None:
        url = _url_of(obj)
        return url.port if url is not None else None

    @staticmethod
    def resolve_path(obj) -> str | None:
        url = _url_of(obj)
        return url.path if url is not None else None

    @staticmethod
    def resolve_query(obj) -> str | None:
        url = _url_of(obj)
        return url.query if url is not None else None

    @staticmethod
    def resolve_fragment(obj) -> str | None:
        url = _url_of(obj)
        return url.fragment if url is not None else None


# --- Sub-resource edge schemas (OpenAPI documentation of the manual dict shapes) --------------

class FindingLocationEdge(Schema):

    """One row of ``GET /findings/{id}/locations`` (§4.14): location ref + edge status/audit."""

    location: LocationRef
    status: str
    audit_time: datetime.datetime | None
    auditor: Ref | None


class ProductLocationEdge(Schema):

    """
    One row of ``GET /products/{id}/locations`` (§4.14): location ref + edge status.
    ``LocationProductReference`` has no ``audit_time``/``auditor`` columns, so the product edge
    carries only ``status`` (§12).
    """

    location: LocationRef
    status: str


class LocationListResponse(Schema):

    """OpenAPI documentation of the ``/locations`` list envelope (I1); serialization is manual."""

    count: int
    next: str | None
    previous: str | None
    results: list[LocationSlim]
    meta: dict | None = None


class FindingLocationListResponse(Schema):

    """OpenAPI documentation of the ``/findings/{id}/locations`` envelope (I1)."""

    count: int
    next: str | None
    previous: str | None
    results: list[FindingLocationEdge]
    meta: dict | None = None


class ProductLocationListResponse(Schema):

    """OpenAPI documentation of the ``/products/{id}/locations`` envelope (I1)."""

    count: int
    next: str | None
    previous: str | None
    results: list[ProductLocationEdge]
    meta: dict | None = None


# --- Edge-row serializers (manual dict shape; co-located with the edge schemas) ---------------

def finding_location_edge(ref) -> dict:
    """Serialize a ``LocationFindingReference`` edge row (§4.14): location ref + status/audit/auditor."""
    return {
        "location": to_location_ref(ref.location),
        "status": ref.status,
        "audit_time": ref.audit_time,
        "auditor": to_ref(ref.auditor),
    }


def product_location_edge(ref) -> dict:
    """Serialize a ``LocationProductReference`` edge row (§4.14): location ref + status (no audit)."""
    return {
        "location": to_location_ref(ref.location),
        "status": ref.status,
    }
