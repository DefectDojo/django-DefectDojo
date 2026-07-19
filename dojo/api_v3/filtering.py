"""
Filter adapter for API v3 (D6 / §4.9).

One filter contract, many projections. The grammar is fixed (``field``, ``field__gte/__lte/__gt/
__lt/__in/__icontains/__isnull``, multi-sort ``o=``, free-text ``q=``); the per-object vocabulary
is a curated, declarative artifact (``FilterSpec``). This module is the framework-light adapter:
it reuses django-filter ``FilterSet`` (criterion 4) to apply the value filters, then applies
``o=`` and ``q=`` on top.

Invariant I2: the grammar never varies per endpoint. The vocabulary snapshot test lands in OS2;
OS1 wires the mechanism and the findings vocabulary.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import django_filters as df
from django.db.models import Q

from dojo.api_v3.errors import filter_problem

if TYPE_CHECKING:
    from django.db.models import QuerySet
    from django.http import HttpRequest

# Query params owned by the kernel; never treated as filter fields.
RESERVED_PARAMS = frozenset({"limit", "offset", "pagination", "expand", "fields", "include", "o", "q"})


# --- Filter field constructors (the fixed grammar) --------------------------------------------

class NumberInFilter(df.BaseInFilter, df.NumberFilter):

    """`__in` for numeric fields (comma-separated)."""


class CharInFilter(df.BaseInFilter, df.CharFilter):

    """`__in` for char fields (comma-separated)."""


_BASE = {
    "number": df.NumberFilter,
    "char": df.CharFilter,
    "bool": df.BooleanFilter,
    "date": df.DateFilter,
    "datetime": df.IsoDateTimeFilter,
}


def filter_field(field_path: str, lookup: str, kind: str, *, distinct: bool = False) -> df.Filter:
    """Build a single django-filter Filter for the fixed grammar."""
    if lookup == "in":
        cls = NumberInFilter if kind == "number" else CharInFilter
        return cls(field_name=field_path, lookup_expr="in", distinct=distinct)
    return _BASE[kind](field_name=field_path, lookup_expr=lookup, distinct=distinct)


@dataclass
class FilterSpec:

    """Declarative per-object filter vocabulary (a tested artifact in OS2)."""

    model: type
    filters: dict[str, df.Filter]
    # Ordering param name -> model field path. Only these orderings are permitted (§4.9).
    orderings: dict[str, str]
    # Fields scanned by free-text `q=`.
    search_fields: list[str] = field(default_factory=list)
    _filterset_class: type | None = None

    def filterset_class(self) -> type[df.FilterSet]:
        if self._filterset_class is None:
            meta = type("Meta", (), {"model": self.model, "fields": []})
            self._filterset_class = type(
                f"{self.model.__name__}V3FilterSet",
                (df.FilterSet,),
                {**self.filters, "Meta": meta},
            )
        return self._filterset_class


def _apply_ordering(request: HttpRequest, queryset: QuerySet, orderings: dict[str, str]) -> QuerySet:
    raw = request.GET.get("o")
    if not raw:
        return queryset
    order_by = []
    for raw_token in raw.split(","):
        token = raw_token.strip()
        if not token:
            continue
        desc = token.startswith("-")
        key = token[1:] if desc else token
        if key not in orderings:
            msg = f"'{key}' is not an orderable field"
            raise filter_problem(msg)
        path = orderings[key]
        order_by.append(f"-{path}" if desc else path)
    return queryset.order_by(*order_by) if order_by else queryset


def _apply_search(request: HttpRequest, queryset: QuerySet, search_fields: list[str]) -> QuerySet:
    term = request.GET.get("q")
    if not term or not search_fields:
        return queryset
    condition = Q()
    for f in search_fields:
        condition |= Q(**{f"{f}__icontains": term})
    return queryset.filter(condition)


def apply_filters(request: HttpRequest, queryset: QuerySet, spec: FilterSpec) -> QuerySet:
    """Apply value filters (django-filter), then ``o=`` and ``q=``. Bad input -> 400 problem+json."""
    filterset = spec.filterset_class()(request.GET, queryset=queryset)
    if not filterset.is_valid():
        # Reshape django-filter field errors into the flat filter problem detail.
        messages = "; ".join(
            f"{name}: {', '.join(str(e) for e in errs)}" for name, errs in filterset.errors.items()
        )
        raise filter_problem(messages or "invalid filter parameters")
    queryset = filterset.qs
    queryset = _apply_ordering(request, queryset, spec.orderings)
    return _apply_search(request, queryset, spec.search_fields)
