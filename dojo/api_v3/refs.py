"""
Relation references for API v3 (D3 / §4.4).

Every relation renders by default as a slim ``{id, name}`` ref produced by a single shared
schema. The relation key conveys the type, so refs carry no ``type`` field -- the sole
exception being location refs, whose one key can hold heterogeneous location subtypes.

This module is the single source of truth for the ref *label registry* (which model attribute
supplies ``name`` for each model). Invariant I3: the ref shape is closed -- do not extend it.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from ninja import Schema

if TYPE_CHECKING:
    from collections.abc import Callable

    from django.db.models import Model


class Ref(Schema):

    """Closed ref shape (I3): identity + human label."""

    id: int
    name: str


class LocationRef(Ref):

    """Location refs additionally carry ``type`` because one key holds heterogeneous subtypes."""

    type: str


def _test_label(obj: Model) -> str:
    # Test: .title if set, else str(.test_type) (§4.4).
    return obj.title or str(obj.test_type)


# Label registry (§4.4): model class -> callable(obj) -> name. Registered lazily by import path
# name to avoid importing every model at kernel-import time (keeps the kernel resource-agnostic).
_LABELERS: dict[str, Callable[[Model], str]] = {
    "Product_Type": lambda o: o.name,
    "Product": lambda o: o.name,
    "Engagement": lambda o: o.name,
    "Test": _test_label,
    "Finding": lambda o: o.title,
    "Dojo_User": lambda o: o.username,
    "Location": lambda o: o.location_value,
    "Test_Type": lambda o: o.name,
    "Development_Environment": lambda o: o.name,
}


def ref_label(obj: Model) -> str:
    """Return the human label for ``obj`` per the registry, falling back to ``str(obj)``."""
    labeler = _LABELERS.get(type(obj).__name__)
    if labeler is None:
        return str(obj)
    return labeler(obj)


def to_ref(obj: Model | None) -> dict | None:
    """Render ``obj`` as a closed ``{id, name}`` ref, or ``None`` when ``obj`` is ``None``."""
    if obj is None:
        return None
    return {"id": obj.pk, "name": ref_label(obj)}


def to_location_ref(location: Model | None) -> dict | None:
    """Render a Location as ``{id, name, type}`` (the one ref subtype carrying ``type``)."""
    if location is None:
        return None
    return {"id": location.pk, "name": location.location_value, "type": location.location_type}
