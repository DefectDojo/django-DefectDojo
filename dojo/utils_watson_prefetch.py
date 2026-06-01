"""
Query prefetch helper for the async watson search indexer.

Watson's `SearchAdapter._resolve_field` walks `__`-separated relation paths via
per-instance `getattr`, which triggers one query per FK hop per object during
indexing. For deep adapter `fields`/`store` paths (e.g.
`finding__test__engagement__product__name`) on a 1000-row batch this means
thousands of extra queries.

`build_prefetched_queryset` introspects the adapter paths against the model's
`_meta`, classifies each prefix as FK chain (`select_related`) or M2M / reverse
(`prefetch_related`), and applies them in a single query plan. On any failure
the caller is expected to fall back to the plain queryset — watson still works
correctly, just slower.

Toggle: ``settings.WATSON_INDEX_PREFETCH_ENABLED`` (default True).
"""

import logging

from django.core.exceptions import FieldDoesNotExist

logger = logging.getLogger(__name__)


def _classify_path(model, prefix):
    """
    Walk a `__`-separated relation prefix against `model._meta`.

    Returns
    -------
    "select" | "prefetch" | None
        - "select": pure FK / OneToOne chain (safe for select_related).
        - "prefetch": chain contains a many-to-many or reverse-many leg.
        - None: unresolvable (callable on adapter, GenericForeignKey, typo, etc.) —
          caller should drop this path.

    """
    is_multi = False
    current = model
    for part in prefix.split("__"):
        try:
            field = current._meta.get_field(part)
        except FieldDoesNotExist:
            return None
        if getattr(field, "many_to_many", False) or getattr(field, "one_to_many", False):
            is_multi = True
        related = getattr(field, "related_model", None)
        if related is None:
            # Reached a concrete field (e.g. CharField) — chain ends here. The
            # caller passes the prefix without the leaf, so this should be rare.
            return "prefetch" if is_multi else "select"
        current = related
    return "prefetch" if is_multi else "select"


def derive_relation_paths(model, adapter):
    """
    Inspect adapter `fields` + `store` and return ``(select_paths, prefetch_paths)``.

    Each entry is a relation prefix suitable for passing to
    `QuerySet.select_related` / `QuerySet.prefetch_related`. Paths that cannot
    be resolved against ``model._meta`` are dropped (watson will resolve them
    at indexing time the slow way).
    """
    select_paths = set()
    prefetch_paths = set()

    raw_paths = tuple(getattr(adapter, "fields", ()) or ()) + tuple(getattr(adapter, "store", ()) or ())
    for path in raw_paths:
        if "__" not in path:
            continue
        prefix = path.rsplit("__", 1)[0]
        classification = _classify_path(model, prefix)
        if classification == "select":
            select_paths.add(prefix)
        elif classification == "prefetch":
            prefetch_paths.add(prefix)
        # None: drop silently — adapter property/GFK, watson handles at runtime.

    return select_paths, prefetch_paths


def build_indexing_queryset(model, pk_list, adapter):
    """
    Build the queryset used by the async watson indexer.

    Applies `select_related` / `prefetch_related` derived from the adapter when
    ``settings.WATSON_INDEX_PREFETCH_ENABLED`` is True (default). On any error
    we log loudly and return the plain queryset so indexing still succeeds.
    """
    from django.conf import settings  # noqa: PLC0415 -- settings access at call time

    base_qs = model.objects.filter(pk__in=pk_list)

    if not getattr(settings, "WATSON_INDEX_PREFETCH_ENABLED", True):
        logger.debug(
            "WATSON_INDEX_PREFETCH_ENABLED=False, indexing %s with plain queryset",
            model.__name__,
        )
        return base_qs

    try:
        select_paths, prefetch_paths = derive_relation_paths(model, adapter)
    except Exception:
        logger.exception(
            "Watson prefetch path derivation failed for %s — falling back to plain queryset",
            model.__name__,
        )
        return base_qs

    if not select_paths and not prefetch_paths:
        return base_qs

    try:
        qs = base_qs
        if select_paths:
            qs = qs.select_related(*select_paths)
        if prefetch_paths:
            qs = qs.prefetch_related(*prefetch_paths)
        logger.debug(
            "Watson indexing %s with select_related=%s prefetch_related=%s",
            model.__name__, sorted(select_paths), sorted(prefetch_paths),
        )
    except Exception:
        logger.exception(
            "Watson prefetch application failed for %s (select=%s prefetch=%s) — "
            "falling back to plain queryset",
            model.__name__, sorted(select_paths), sorted(prefetch_paths),
        )
        return base_qs
    else:
        return qs
