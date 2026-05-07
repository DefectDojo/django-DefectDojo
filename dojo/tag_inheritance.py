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
    re-syncing in bulk. Touched instances are grouped by model class;
    ``flush()`` runs one bulk diff per (model, product) group via the
    existing ``_sync_inheritance_for_qs`` helper.
    """

    def __init__(self):
        self._depth = 0
        # model_class -> set of instance pks
        self._touched: dict[type, set[int]] = defaultdict(set)
        # System-wide inheritance flag is read from the DB and cached for
        # the lifetime of the context. Per-product flags are read directly
        # off the in-memory product instance.
        self._system_inheritance: bool | None = None

    def is_active(self) -> bool:
        return self._depth > 0

    def system_inheritance_enabled(self) -> bool:
        if self._system_inheritance is None:
            from dojo.utils import get_system_setting  # noqa: PLC0415
            self._system_inheritance = bool(get_system_setting("enable_product_tag_inheritance"))
        return self._system_inheritance

    def is_inheritance_enabled_for(self, instance) -> bool:
        """
        True when the given instance is under at least one product whose
        inheritance is enabled (per-product flag or system-wide).
        """
        from dojo.tags_signals import get_products  # noqa: PLC0415
        products = get_products(instance)
        if any(getattr(p, "enable_product_tag_inheritance", False) for p in products if p):
            return True
        return self.system_inheritance_enabled()

    def add(self, instance) -> None:
        """
        Register an instance for bulk-sync at next flush. No-op when
        inheritance is disabled for this instance, so the bulk path stays
        cheap on inheritance-off products.
        """
        if instance is None or getattr(instance, "pk", None) is None:
            return
        if not self.is_inheritance_enabled_for(instance):
            return
        self._touched[type(instance)].add(instance.pk)

    def flush(self) -> None:
        """
        Bulk-sync inherited tags for every registered instance, then
        clear the registry. Idempotent and cheap when nothing was
        touched.
        """
        if not self._touched:
            return
        # Local imports to avoid circulars at module import time.
        from dojo.location.models import Location  # noqa: PLC0415
        from dojo.product.helpers import (  # noqa: PLC0415
            _build_location_target_names_map,
            _sync_inheritance_for_qs,
        )
        from dojo.tags_signals import get_products  # noqa: PLC0415

        touched, self._touched = self._touched, defaultdict(set)

        for model_class, pks in touched.items():
            if not pks:
                continue
            queryset = model_class.objects.filter(pk__in=pks)
            if model_class is Location:
                # Location target = union of related products' tags. Use
                # the bulk precompute helper.
                target_map = _build_location_target_names_map(list(pks))
                _sync_inheritance_for_qs(
                    queryset,
                    target_names_per_child=lambda loc, _m=target_map: _m.get(loc.pk, set()),
                )
            else:
                # All other children belong to one product (Finding via
                # test, Endpoint via product, etc.). Group by product so
                # each group gets one target name set.
                instances = list(queryset)
                by_product: dict[int, list] = defaultdict(list)
                product_by_id: dict[int, object] = {}
                for inst in instances:
                    products = get_products(inst)
                    for product in products:
                        if product is None:
                            continue
                        by_product[product.id].append(inst)
                        product_by_id[product.id] = product
                for product_id, group in by_product.items():
                    product = product_by_id[product_id]
                    target_names = {tag.name for tag in product.tags.all()}
                    _sync_inheritance_for_qs(
                        group,
                        target_names_per_child=lambda _c, _t=target_names: _t,
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
