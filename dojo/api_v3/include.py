"""
``?include=`` response add-ons for API v3 (D6 / §4.8).

Namespaced add-ons rendered into ``meta``, computed over the **filtered, authorized** queryset.
The mechanism is a generic registry (``include_name -> callable(filtered_qs) -> dict``) so later
includes (and downstream-defined ones) plug in without contract changes (I1: capabilities extend
``meta``/``include``, never the envelope). Alpha ships ``include=counts`` on findings lists.

The ``counts`` callable is field-name-driven (no resource import), keeping the kernel free of
per-resource dependencies (I5).
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from django.db.models import Count, Q

from dojo.api_v3.errors import ProblemDetail

if TYPE_CHECKING:
    from collections.abc import Callable

    from django.db.models import QuerySet
    from django.http import HttpRequest

_SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")

_INCLUDE_REGISTRY: dict[str, Callable[[QuerySet], dict]] = {}


def register_include(name: str, func: Callable[[QuerySet], dict]) -> None:
    _INCLUDE_REGISTRY[name] = func


def finding_counts(filtered_qs: QuerySet) -> dict:
    """Severity/status totals over the filtered, authorized findings queryset in one aggregate query."""
    severity_filters = {
        f"sev_{sev.lower()}": Count("id", filter=Q(severity=sev)) for sev in _SEVERITIES
    }
    agg = filtered_qs.aggregate(
        total=Count("id"),
        active=Count("id", filter=Q(active=True)),
        verified=Count("id", filter=Q(verified=True)),
        duplicate=Count("id", filter=Q(duplicate=True)),
        **severity_filters,
    )
    return {
        "total": agg["total"],
        "active": agg["active"],
        "verified": agg["verified"],
        "duplicate": agg["duplicate"],
        "severity": {sev: agg[f"sev_{sev.lower()}"] for sev in _SEVERITIES},
    }


register_include("counts", finding_counts)


def parse_include(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [name.strip() for name in raw.split(",") if name.strip()]


def apply_includes(request: HttpRequest, filtered_qs: QuerySet, *, allowed: set[str]) -> dict:
    """Return the ``meta`` fragment produced by the requested includes. Unknown/not-allowed -> 400."""
    meta: dict = {}
    for name in parse_include(request.GET.get("include")):
        if name not in allowed or name not in _INCLUDE_REGISTRY:
            raise ProblemDetail(
                status=400,
                error_type="include",
                title="Invalid include",
                detail=f"'{name}' is not an available include for this endpoint",
            )
        meta[name] = _INCLUDE_REGISTRY[name](filtered_qs)
    return meta
