"""
Tag inheritance — central coordination module.

Provides a thread-local ``batch()`` context manager that suppresses
per-instance inheritance work driven by ``m2m_changed`` and ``post_save``
signals. While inside a batch, the signal handlers in
``dojo/tags_signals.py`` early-return; the calling code is responsible for
applying inheritance in bulk (e.g. via the importer's existing
``_bulk_inherit_tags`` path or ``propagate_tags_on_product_sync``).

This replaces the previous pattern of ``signals.m2m_changed.disconnect(...)``
in importer hot loops, which was process-global and unsafe under threaded
gunicorn / Celery thread pools / ASGI threadpools (see PR description for
the full rationale).
"""
from __future__ import annotations

import contextlib
import threading
from contextlib import contextmanager

_state = threading.local()


def is_in_batch() -> bool:
    """Return True when the current thread is inside an active ``batch()``."""
    return bool(getattr(_state, "depth", 0))


@contextmanager
def batch():
    """
    Suppress per-instance inheritance signals for the calling thread.

    Usage:
        with tag_inheritance.batch():
            # Bulk operations that would otherwise fire `make_inherited_tags_sticky`
            # or `inherit_tags_on_instance` per row.
            ...
        # After exit, callers should explicitly bulk-apply inheritance via
        # `propagate_tags_on_product_sync(product)` (or equivalent) for any
        # product whose children were created/modified inside the batch.

    The context is reentrant; nested ``with`` blocks share the suppression
    until the outermost block exits. State lives in ``threading.local()``,
    so concurrent threads (and Celery workers in non-prefork pools) are
    unaffected by other threads' batches.
    """
    _state.depth = getattr(_state, "depth", 0) + 1
    try:
        yield
    finally:
        _state.depth -= 1
        if _state.depth <= 0:
            # Clean up the attribute so leak-free thread reuse stays simple.
            with contextlib.suppress(AttributeError):
                del _state.depth


def flush_for_product(product) -> None:
    """
    Bulk-apply tag inheritance to all children of `product`.

    Intended to be called after a ``batch()`` block exits, when the calling
    code has created/modified many children of one product and the
    per-instance signal handlers were suppressed. Delegates to
    ``propagate_tags_on_product_sync``, which uses the Phase A bulk-diff
    helpers to sync `_inherited_tag_names` and `tags` across all children
    in O(1) queries per (model x tag) instead of O(N) rows.

    Short-circuits when tag inheritance is disabled (neither the system-wide
    flag nor the per-product flag is set) so callers (e.g. importers) can
    invoke this unconditionally without paying for it.
    """
    # Local imports to avoid circulars at module import time.
    from dojo.product.helpers import propagate_tags_on_product_sync  # noqa: PLC0415
    from dojo.utils import get_system_setting  # noqa: PLC0415
    if not getattr(product, "enable_product_tag_inheritance", False) and not get_system_setting("enable_product_tag_inheritance"):
        return
    propagate_tags_on_product_sync(product)
