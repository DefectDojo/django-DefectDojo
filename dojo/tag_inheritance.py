"""
Tag inheritance — watson-style context manager.

Pattern mirrors `watson.search.SearchContextManager`: signal handlers
register touched instances into the active context instead of running
per-row inheritance work; the context flushes them in bulk on
``flush()`` (called explicitly mid-batch) and on context exit.

Usage:
    with tag_inheritance.batch() as ctx:
        # bulk operations create/modify many instances
        ...
        ctx.flush()  # optional, mid-batch sync (e.g. before JIRA push)
        ...
    # auto-flushes on outermost exit

The context lives in ``threading.local``, so concurrent threads (and
Celery workers in non-prefork pools) are unaffected by other threads'
batches.
"""
from __future__ import annotations

import logging
import threading
from collections import defaultdict
from contextlib import contextmanager

logger = logging.getLogger(__name__)

_state = threading.local()


class TagInheritanceContext:

    """
    Per-thread registrar for instances whose inherited tags need
    re-syncing in bulk.

    Layout: ``{product_id: {model_class: {pk, ...}}}`` for single-product
    children (Engagement / Test / Finding / Endpoint), plus a separate
    set of Location pks (locations are linked to many products via
    LocationProductReference / LocationFindingReference, so their target
    tag set is the union of all related products' tags).

    On ``flush()``: one bulk diff per (product, model) group via
    ``_sync_inheritance_for_qs``; locations route through the bulk
    target-map helper.
    """

    def __init__(self):
        self._depth = 0
        # product_id -> model_class -> set[pk]
        self._touched_by_product: dict[int, dict[type, set[int]]] = defaultdict(lambda: defaultdict(set))
        # Cached resolved Product instances so flush doesn't re-read.
        self._product_by_id: dict[int, object] = {}
        # Locations are multi-product; tracked separately and resolved at flush.
        self._touched_locations: set[int] = set()
        # System-wide inheritance flag is read from the DB and cached for
        # the lifetime of the context. Per-product flags are read off the
        # in-memory product instance (no DB cost).
        self._system_inheritance: bool | None = None

    def is_active(self) -> bool:
        return self._depth > 0

    def system_inheritance_enabled(self) -> bool:
        if self._system_inheritance is None:
            from dojo.utils import get_system_setting  # noqa: PLC0415
            self._system_inheritance = bool(get_system_setting("enable_product_tag_inheritance"))
        return self._system_inheritance

    def add(self, instance) -> None:
        """
        Register an instance for bulk-sync at next flush.

        For Location: always register (filtered at flush time, since
        per-location inheritance check would cost a DB query each).

        For other models: resolve product upfront (in-memory FK chain),
        skip when inheritance is disabled for that product. Stays cheap
        on inheritance-off products.
        """
        if instance is None or getattr(instance, "pk", None) is None:
            return

        from dojo.location.models import Location  # noqa: PLC0415
        if isinstance(instance, Location):
            self._touched_locations.add(instance.pk)
            return

        from dojo.tags_signals import get_products  # noqa: PLC0415
        for product in get_products(instance):
            if product is None:
                continue
            if not getattr(product, "enable_product_tag_inheritance", False):
                if not self.system_inheritance_enabled():
                    continue
            self._touched_by_product[product.id][type(instance)].add(instance.pk)
            self._product_by_id[product.id] = product

    def flush(self) -> None:
        """
        Bulk-sync inherited tags for every registered instance, then
        clear the registry. Idempotent and cheap when nothing was
        touched.
        """
        if not self._touched_by_product and not self._touched_locations:
            return
        # Local imports to avoid circulars at module import time.
        from dojo.location.models import Location  # noqa: PLC0415
        from dojo.product.helpers import (  # noqa: PLC0415
            _build_location_target_names_map,
            _sync_inheritance_for_qs,
        )

        touched_by_product = self._touched_by_product
        product_by_id = self._product_by_id
        touched_locations = self._touched_locations
        self._touched_by_product = defaultdict(lambda: defaultdict(set))
        self._product_by_id = {}
        self._touched_locations = set()

        for product_id, model_pks in touched_by_product.items():
            product = product_by_id.get(product_id)
            if product is None:
                continue
            target_tag_names = {tag.name for tag in product.tags.all()}
            for model_class, pks in model_pks.items():
                if not pks:
                    continue
                _sync_inheritance_for_qs(
                    model_class.objects.filter(pk__in=pks),
                    target_names_per_child=lambda _c, _t=target_tag_names: _t,
                )

        if touched_locations:
            target_map = _build_location_target_names_map(list(touched_locations))
            _sync_inheritance_for_qs(
                Location.objects.filter(pk__in=touched_locations),
                target_names_per_child=lambda loc, _m=target_map: _m.get(loc.pk, set()),
            )


def current() -> TagInheritanceContext | None:
    """Return the active context for this thread, if any."""
    return getattr(_state, "ctx", None)


def is_in_batch() -> bool:
    """Return True when the current thread is inside an active ``batch()``."""
    ctx = current()
    return ctx is not None and ctx.is_active()


@contextmanager
def batch():
    """
    Open a tag-inheritance context for the calling thread.

    Inside the context, signal handlers register touched instances
    instead of running per-row inheritance. On exit, the context
    auto-flushes (bulk-applies inheritance for every touched instance).

    Reentrant: nested ``with`` blocks share the context until the
    outermost block exits.
    """
    ctx = getattr(_state, "ctx", None)
    owner = ctx is None
    if owner:
        ctx = TagInheritanceContext()
        _state.ctx = ctx
    ctx._depth += 1
    try:
        yield ctx
    finally:
        ctx._depth -= 1
        if ctx._depth <= 0:
            try:
                ctx.flush()
            finally:
                if owner:
                    del _state.ctx
