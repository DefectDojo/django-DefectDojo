"""
``?expand=`` parsing, validation, queryset planning and serialization for API v3 (D3 / §4.6).

Comma-separated dotted paths (``expand=test.engagement,reporter``). Each segment must be a
registered expandable relation of the current schema. Expanding swaps the ref for the target's
slim schema **inline** (no side blob) and drives the queryset: FK/O2O segments append
``select_related`` paths, M2M/reverse-FK segments append ``prefetch_related`` paths (this is the
real N+1 fix, replacing v2's post-serialization ``?prefetch=``).

Two guards, both 400 problem+json: a cycle guard (a segment whose target model already appears in
its ancestry) and a node budget (``API_V3_EXPAND_BUDGET``).

OS1 hard-scopes the registry to the finding relations reachable from ``FindingSlim``; OS2 keeps
the same mechanism but drives it from a fully generic registry. Each schema declares its own
``EXPANDABLE`` registry and a ``django_model`` attribute, so the walker below is already generic.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from django.conf import settings

from dojo.api_v3.errors import expand_problem, fields_problem

if TYPE_CHECKING:
    from collections.abc import Callable

    from django.db.models import QuerySet


@dataclass(frozen=True)
class ExpandRel:

    """One expandable relation entry in a schema's ``EXPANDABLE`` registry."""

    attr: str                       # python attribute path on the object (may be dotted)
    path: str                       # django ORM relation path segment(s) relative to the model
    schema: type | None = None      # target slim schema class (None for a special renderer)
    to_many: bool = False           # True -> prefetch_related; False -> select_related
    special: Callable | None = None  # optional custom renderer(obj) -> value (e.g. edge rows)
    # Prefetch paths a *special* renderer needs so serialising it never triggers per-row queries
    # (a special renderer bypasses the schema-driven select/prefetch planning below). Relative to
    # this rel's model; the walker prefixes them with the current django path.
    prefetch_paths: tuple[str, ...] = ()
    # Slim field this expansion replaces in the output (e.g. ``locations`` replaces
    # ``locations_count`` -- §4.6 "swaps locations_count for edge rows"). None -> pure add.
    replaces: str | None = None


def parse_expand(raw: str | None) -> list[list[str]]:
    """Split ``expand=`` into a list of segment lists. Empty/missing -> []."""
    if not raw:
        return []
    paths = []
    for raw_chunk in raw.split(","):
        chunk = raw_chunk.strip()
        if not chunk:
            continue
        segments = [s for s in chunk.split(".") if s]
        if segments:
            paths.append(segments)
    return paths


def _walk(
    segments: list[str],
    schema: type,
    tree: dict,
    ancestry: tuple[type, ...],
    select_related: set[str],
    prefetch: set[str],
    django_prefix: str,
    node_counter: list[int],
) -> None:
    registry: dict[str, ExpandRel] = getattr(schema, "EXPANDABLE", {})
    head, *rest = segments
    rel = registry.get(head)
    if rel is None:
        msg = f"'{head}' is not an expandable relation of {schema.__name__}"
        raise expand_problem(msg)

    node_counter[0] += 1
    if node_counter[0] > settings.API_V3_EXPAND_BUDGET:
        msg = f"expand budget exceeded (max {settings.API_V3_EXPAND_BUDGET} nodes)"
        raise expand_problem(msg)

    target_model = getattr(rel.schema, "django_model", None)
    if target_model is not None and target_model in ancestry:
        msg = f"expand cycle detected at '{head}' ({target_model.__name__})"
        raise expand_problem(msg)

    full_path = f"{django_prefix}__{rel.path}" if django_prefix else rel.path
    if rel.special is not None:
        # A special renderer produces the value itself; it declares its own prefetch paths so the
        # query count stays constant (e.g. locations edge rows via prefetch_related, §4.6).
        prefetch.update(f"{django_prefix}__{pf}" if django_prefix else pf for pf in rel.prefetch_paths)
    elif rel.to_many:
        prefetch.add(full_path)
    else:
        select_related.add(full_path)
        # Pull in the target schema's own ref/tag dependencies so serializing the expanded
        # object never triggers per-row queries -- this is what keeps the query count constant
        # under expand (the headline guarantee).
        select_related.update(f"{full_path}__{sr}" for sr in getattr(rel.schema, "SELECT_RELATED", ()))
        prefetch.update(f"{full_path}__{pf}" for pf in getattr(rel.schema, "PREFETCH_RELATED", ()))

    subtree = tree.setdefault(head, {})
    if rest:
        if rel.special is not None:
            msg = f"'{head}' cannot be expanded further"
            raise expand_problem(msg)
        next_ancestry = (*ancestry, target_model) if target_model is not None else ancestry
        _walk(rest, rel.schema, subtree, next_ancestry, select_related, prefetch, full_path, node_counter)


def plan(root_schema: type, raw_expand: str | None) -> tuple[dict, set[str], set[str]]:
    """
    Validate the expand paths against ``root_schema`` and return
    ``(expand_tree, select_related_paths, prefetch_related_paths)``.
    """
    tree: dict = {}
    select_related: set[str] = set()
    prefetch: set[str] = set()
    node_counter = [0]
    root_model = getattr(root_schema, "django_model", None)
    ancestry: tuple[type, ...] = (root_model,) if root_model is not None else ()
    for segments in parse_expand(raw_expand):
        _walk(segments, root_schema, tree, ancestry, select_related, prefetch, "", node_counter)
    return tree, select_related, prefetch


def plan_queryset(queryset: QuerySet, select_related: set[str], prefetch: set[str]) -> QuerySet:
    """Apply the planned ``select_related``/``prefetch_related`` paths to the queryset."""
    if select_related:
        queryset = queryset.select_related(*sorted(select_related))
    if prefetch:
        queryset = queryset.prefetch_related(*sorted(prefetch))
    return queryset


def _resolve_attr(obj: object, attr: str) -> object | None:
    value = obj
    for part in attr.split("."):
        value = getattr(value, part, None)
        if value is None:
            return None
    return value


def serialize(obj: object, schema: type, expand_tree: dict) -> dict:
    """
    Produce the object's dict: the schema-driven slim shape, then each expanded key swapped from a
    ref to the target's serialized shape (recursively). Schema-driven so a subclass that adds a
    field serializes it automatically (I4).
    """
    data = schema.model_validate(obj).model_dump(mode="python")
    registry: dict[str, ExpandRel] = getattr(schema, "EXPANDABLE", {})
    for key, subtree in expand_tree.items():
        rel = registry[key]
        if rel.replaces is not None:
            # e.g. expand=locations swaps the cheap `locations_count` for the edge rows (§4.6).
            data.pop(rel.replaces, None)
        if rel.special is not None:
            data[key] = rel.special(obj)
            continue
        related = _resolve_attr(obj, rel.attr)
        if related is None:
            data[key] = None
        elif rel.to_many:
            data[key] = [serialize(item, rel.schema, subtree) for item in related.all()]
        else:
            data[key] = serialize(related, rel.schema, subtree)
    return data


# --- ?fields= projection (§4.7) ----------------------------------------------------------------

def allowed_field_names(schema: type) -> set[str]:
    """
    The ``?fields=`` allowlist for a schema: its declared fields **plus** its registered expandable
    keys (§4.7 + the OS4 fields/expand interplay decision, §12). This lets ``?expand=locations&
    fields=id,title,locations`` name an expand key in ``fields=`` while a genuinely unknown name
    still 400s. Expand keys are not model fields (e.g. ``locations`` replaces ``locations_count``),
    so they must be added explicitly; without expand the key simply renders nothing (``apply_fields``
    only keeps keys actually present in the serialized dict).
    """
    return set(schema.model_fields) | set(getattr(schema, "EXPANDABLE", {}))


def parse_fields(raw: str | None, allowed: set[str]) -> set[str] | None:
    """Return the requested field allowlist (``id`` always included) or None. Unknown -> 400."""
    if not raw:
        return None
    requested = {f.strip() for f in raw.split(",") if f.strip()}
    unknown = requested - allowed
    if unknown:
        msg = f"unknown field(s): {', '.join(sorted(unknown))}"
        raise fields_problem(msg)
    requested.add("id")
    return requested


def apply_fields(data: dict, fields: set[str] | None) -> dict:
    if fields is None:
        return data
    return {k: v for k, v in data.items() if k in fields}


# --- LIST-endpoint slim/detail field planning + deferral (Part A opt-up / Part B defer) --------

@dataclass(frozen=True)
class ListFieldPlan:

    """
    The serialization + queryset plan for one LIST request's ``?fields=`` selection.

    ``?fields=`` on a list may opt **up** into the detail field set (Jira-style, §4.7): the allowlist
    is ``DetailSchema fields`` plus the ``EXPANDABLE`` keys, and when a requested field is beyond the slim set
    the row serializes with the detail shape. Independently, LIST querysets ``defer()`` the heavy
    own-model detail columns that were **not** requested, so a default list never fetches them from
    the DB (Part B). Both are resource-agnostic: the kernel derives everything from the two schemas
    and the model's ``concrete_fields``.
    """

    base_schema: type                        # slim schema; base serialization always runs through it
    detail_schema: type                      # detail schema; source of the spliced detail-only fields
    detail_extra: tuple[str, ...]            # requested detail-only fields to splice onto the slim row
    defer: tuple[str, ...]                   # own-model concrete columns to .defer() on the LIST queryset
    select_related: tuple[str, ...]          # fixed joins for requested detail-only relation refs
    requested: frozenset[str] | None         # the parsed ?fields= set (id included) or None

    @property
    def serialization_schema(self) -> type:
        # The schema whose declared field set shapes the row (the task's "serialization_schema"):
        # detail once the request opted up beyond slim, else slim. Serialization itself always runs
        # through ``base_schema`` so no deferred column is ever read (see ``serialize_list_row``).
        return self.detail_schema if self.detail_extra else self.base_schema


def _own_concrete_columns(model: type) -> set[str]:
    """
    Own-model concrete columns that are NOT relations. Relations (FK/O2O columns) are excluded so we
    never defer a column a ref renderer needs (§Part B: "never defer properties, annotations, or
    relations"); properties/annotations are not ``concrete_fields`` at all.
    """
    return {f.name for f in model._meta.concrete_fields if not f.is_relation}


def plan_list_fields(slim_schema: type, detail_schema: type, requested: set[str] | None) -> ListFieldPlan:
    """
    Given ``(slim_schema, detail_schema, requested_fields)`` return the LIST serialization/queryset
    plan (Part A opt-up + Part B defer). ``requested`` is the already-parsed/validated ``?fields=``
    set (``id`` included) or ``None`` for the default (no ``?fields=``) request.

    - ``defer`` = detail-only concrete own-model columns **minus** the requested fields **minus** the
      concrete columns a requested *computed* detail field reads (``DETAIL_FIELD_COLUMNS``). On a
      default list this defers every heavy detail column (they are never serialized by the slim
      shape); a ``?fields=impact`` request un-defers exactly ``impact``.
    - ``detail_extra`` = the requested detail-only fields (spliced onto the slim row).
    - ``select_related`` = the fixed joins the requested detail-only *relation* refs need, declared by
      the detail schema's ``DETAIL_SELECT_RELATED`` (so D11 wire↔model naming and reverse-O2O joins
      resolve correctly); applied only when such a field is requested and never per row.
    """
    slim_fields = set(slim_schema.model_fields)
    detail_only = set(detail_schema.model_fields) - slim_fields
    model = getattr(slim_schema, "django_model", None)
    concrete = _own_concrete_columns(model) if model is not None else set()
    defer_candidates = detail_only & concrete

    requested_set = set(requested) if requested is not None else set()
    detail_extra = tuple(sorted(requested_set & detail_only))

    # A requested *computed* (non-concrete) detail field's resolver may read concrete own-model
    # columns that would otherwise be deferred (e.g. ``Test.deduplication_algorithm`` reads the
    # deferred ``scan_type`` column). A schema declares those dependencies in ``DETAIL_FIELD_COLUMNS``
    # so requesting such a field un-defers exactly the columns its resolver needs -- keeping the LIST
    # query count constant (no per-row lazy column load). Analogous to ``DETAIL_SELECT_RELATED`` but
    # for own columns a resolver reads rather than relation joins.
    detail_field_columns: dict[str, tuple[str, ...]] = getattr(detail_schema, "DETAIL_FIELD_COLUMNS", {})
    undefer: set[str] = set()
    for name in detail_extra:
        undefer.update(detail_field_columns.get(name, ()))
    defer = tuple(sorted(defer_candidates - requested_set - undefer))

    detail_select_related: dict[str, tuple[str, ...]] = getattr(detail_schema, "DETAIL_SELECT_RELATED", {})
    select_related: set[str] = set()
    for name in detail_extra:
        select_related.update(detail_select_related.get(name, ()))

    return ListFieldPlan(
        base_schema=slim_schema,
        detail_schema=detail_schema,
        detail_extra=detail_extra,
        defer=defer,
        select_related=tuple(sorted(select_related)),
        requested=frozenset(requested) if requested is not None else None,
    )


def serialize_list_row(obj: object, plan: ListFieldPlan, expand_tree: dict) -> dict:
    """
    Serialize one LIST row honoring an opt-up ``?fields=`` projection (Part A) **without ever reading
    a deferred column** (Part B). The base slim serialization touches only always-loaded slim
    columns/refs/annotations; each requested detail-only field is then spliced on -- concrete columns
    via ``getattr`` (un-deferred because ``plan.defer`` excludes requested fields) and relation refs
    via the detail schema's resolver (loaded by ``plan.select_related``). The output is identical to
    ``apply_fields(serialize(obj, detail_schema, expand_tree), requested)`` but issues no per-row query.
    """
    data = serialize(obj, plan.base_schema, expand_tree)
    for name in plan.detail_extra:
        resolver = getattr(plan.detail_schema, f"resolve_{name}", None)
        data[name] = resolver(obj) if resolver else getattr(obj, name)
    return apply_fields(data, plan.requested)
