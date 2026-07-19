"""
Filter adapter for API v3 (D6 / §4.9).

One filter contract, many projections. The grammar is fixed (``field``, ``field__gte/__lte/__gt/
__lt/__in/__icontains/__isnull``, multi-sort ``o=``, free-text ``q=``); the per-object vocabulary
is a curated, declarative artifact (``FilterSpec``). This module is the framework-light adapter:
it reuses django-filter ``FilterSet`` (criterion 4) to apply the value filters, then applies
``o=`` and ``q=`` on top.

Invariant I2: the grammar never varies per endpoint. Each ``FilterSpec`` registers itself
(``register_filter_spec``) so the OS2 vocabulary snapshot test can render every object's contract
without importing route modules (keeps the kernel resource-agnostic, I5).

Two orderings kinds:
- plain field-path orderings (``orderings``: public key -> model field path), and
- computed orderings (``order_expressions``: public key -> a factory returning a Django ordering
  expression). Severity is computed so it sorts by *rank* (Critical > High > Medium > Low > Info),
  never alphabetically -- mirroring v2's ``numerical_severity`` ordering (S0=Critical ... S4=Info,
  the model's default ordering) but computed at query time so it never depends on that denormalised
  column being populated.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import django_filters as df
from django.db.models import Case, IntegerField, Q, Value, When

from dojo.api_v3.errors import filter_problem

if TYPE_CHECKING:
    from collections.abc import Callable

    from django.db.models import QuerySet
    from django.http import HttpRequest

# Query params owned by the kernel; never treated as filter fields.
RESERVED_PARAMS = frozenset({"limit", "offset", "pagination", "expand", "fields", "include", "o", "q"})

# Severity rank: Critical is the most severe (rank 0) ... Info the least (rank 4). Mirrors v2's
# numerical_severity (S0..S4) and Finding.Meta.ordering.
SEVERITY_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def severity_rank_order():
    """A Case/When that maps the ``severity`` string to its rank so ``o=severity`` sorts by rank."""
    return Case(
        *[When(severity=sev, then=Value(rank)) for sev, rank in SEVERITY_RANK.items()],
        default=Value(len(SEVERITY_RANK)),
        output_field=IntegerField(),
    )


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

    """Declarative per-object filter vocabulary (a tested artifact -- OS2 snapshot)."""

    model: type
    filters: dict[str, df.Filter]
    # Ordering param name -> model field path. Only these plain-field orderings are permitted.
    orderings: dict[str, str]
    # Ordering param name -> callable() returning a Django ordering expression (computed orderings).
    order_expressions: dict[str, Callable] = field(default_factory=dict)
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

    def ordering_keys(self) -> set[str]:
        """Every valid ``o=`` key (plain-field + computed)."""
        return set(self.orderings) | set(self.order_expressions)

    def vocabulary(self) -> dict:
        """The public filter contract of this object (params + orderings + search fields)."""
        return {
            "model": self.model.__name__,
            "params": sorted(self.filters),
            "orderings": sorted(self.ordering_keys()),
            "search_fields": sorted(self.search_fields),
        }


# --- FilterSpec registry (populated by resource modules; read by the snapshot test) -----------

_FILTER_SPEC_REGISTRY: dict[str, FilterSpec] = {}


def register_filter_spec(name: str, spec: FilterSpec) -> FilterSpec:
    """Register a resource's ``FilterSpec`` under a stable name and return it (for module-level use)."""
    _FILTER_SPEC_REGISTRY[name] = spec
    return spec


def iter_filter_specs() -> dict[str, FilterSpec]:
    """A copy of the registry ``{name: spec}`` (the snapshot test's source of truth)."""
    return dict(_FILTER_SPEC_REGISTRY)


# --- Application -------------------------------------------------------------------------------

def _reject_unknown_params(request: HttpRequest, spec: FilterSpec) -> None:
    """Reject query params that are neither reserved nor a declared filter (§4.9 strictness)."""
    allowed = RESERVED_PARAMS | set(spec.filters)
    unknown = [key for key in request.GET if key not in allowed]
    if unknown:
        msg = f"unknown filter parameter(s): {', '.join(sorted(unknown))}"
        raise filter_problem(msg)


def _apply_ordering(request: HttpRequest, queryset: QuerySet, spec: FilterSpec) -> QuerySet:
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
        if key in spec.order_expressions:
            expr = spec.order_expressions[key]()
            order_by.append(expr.desc() if desc else expr.asc())
        elif key in spec.orderings:
            path = spec.orderings[key]
            order_by.append(f"-{path}" if desc else path)
        else:
            msg = f"'{key}' is not an orderable field"
            raise filter_problem(msg)
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
    _reject_unknown_params(request, spec)
    filterset = spec.filterset_class()(request.GET, queryset=queryset)
    if not filterset.is_valid():
        # Reshape django-filter field errors into the flat filter problem detail.
        messages = "; ".join(
            f"{name}: {', '.join(str(e) for e in errs)}" for name, errs in filterset.errors.items()
        )
        raise filter_problem(messages or "invalid filter parameters")
    queryset = filterset.qs
    queryset = _apply_ordering(request, queryset, spec)
    return _apply_search(request, queryset, spec.search_fields)
