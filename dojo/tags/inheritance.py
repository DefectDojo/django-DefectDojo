"""
Tag inheritance — central coordination module.

Provides:

- ``batch_mode()`` — thread-local context manager that suppresses
  per-instance inheritance work driven by ``m2m_changed`` and ``post_save``
  signals. While inside a batch, the signal handlers in
  ``dojo/tags/signals.py`` early-return; the calling code is responsible for
  applying inheritance in bulk (e.g. via the importer's existing
  ``_bulk_inherit_tags`` path or ``propagate_tags_on_product_sync``).

  This replaces the previous pattern of ``signals.m2m_changed.disconnect(...)``
  in importer hot loops, which was process-global and unsafe under threaded
  gunicorn / Celery thread pools / ASGI threadpools (see PR description for
  the full rationale).

- The per-instance inheritance helpers previously scattered across
  ``dojo/tags/signals.py``, ``dojo/models.py``, and ``dojo/product/helpers.py``
  (``_manage_inherited_tags``, ``get_products``, ``inherit_product_tags``,
  ``get_products_to_inherit_tags_from``, ``propagate_inheritance``,
  ``inherit_instance_tags``, ``inherit_linked_instance_tags``).

- The bulk product-wide inheritance sync (``propagate_tags_on_product_sync``)
  plus per-batch importer helpers (``apply_inherited_tags_for_findings`` /
  ``apply_inherited_tags_for_endpoints``) and their shared ``_sync_inheritance_for_qs``
  primitive.

Model imports are deferred to function bodies to keep this module loadable
before ``dojo.models`` finishes initialising.
"""
from __future__ import annotations

import contextlib
import logging
import threading
from collections import defaultdict
from contextlib import contextmanager

from django.conf import settings
from django.db.models import Q
from tagulous.models.managers import FakeTagRelatedManager

# Top-level imports of dojo internals are safe here because
# ``dojo.tags.inheritance`` is loaded lazily — never during the initial
# evaluation of ``dojo.models``. By the time anything imports this module
# (signals registration, importers, the per-model ``inherit_tags()`` shim
# in ``dojo.models``), the full model layer is initialised.
from dojo.location.models import Location
from dojo.models import Endpoint, Engagement, Finding, Product, Test
from dojo.tags.utils import bulk_add_tag_mapping, bulk_remove_tags_from_instances
from dojo.utils import get_system_setting

logger = logging.getLogger(__name__)

_state = threading.local()


def is_in_batch_mode() -> bool:
    """Return True when the current thread is inside an active ``batch()``."""
    return bool(getattr(_state, "depth", 0))


@contextmanager
def batch_mode():
    """
    Suppress per-instance inheritance signals for the calling thread.

    Usage:
        with tag_inheritance.batch():
            # Bulk operations that would otherwise fire `make_inherited_tags_sticky`
            # or `inherit_tags_on_instance` per row.
            ...

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


# ---------------------------------------------------------------------------
# Per-instance inheritance helpers (relocated from dojo/models.py +
# dojo/tags/signals.py). Logic unchanged.
# ---------------------------------------------------------------------------


def _manage_inherited_tags(obj, incoming_inherited_tags, potentially_existing_tags=None):
    # get copies of the current tag lists
    if potentially_existing_tags is None:
        potentially_existing_tags = []
    current_inherited_tags = [] if isinstance(obj.inherited_tags, FakeTagRelatedManager) else [tag.name for tag in obj.inherited_tags.all()]
    tag_list = potentially_existing_tags if isinstance(obj.tags, FakeTagRelatedManager) or len(potentially_existing_tags) > 0 else [tag.name for tag in obj.tags.all()]
    # Clean existing tag list from the old inherited tags. This represents the tags on the object and not the product
    cleaned_tag_list = [tag for tag in tag_list if tag not in current_inherited_tags]
    # Add the incoming inherited tag list
    if incoming_inherited_tags:
        for tag in incoming_inherited_tags:
            if tag not in cleaned_tag_list:
                cleaned_tag_list.append(tag)
    # Update the current list of inherited tags. iteratively do this because of tagulous object restraints
    if isinstance(obj.inherited_tags, FakeTagRelatedManager):
        obj.inherited_tags.set_tag_list(incoming_inherited_tags)
        if incoming_inherited_tags:
            obj.tags.set_tag_list(cleaned_tag_list)
    else:
        obj.inherited_tags.set(incoming_inherited_tags)
        if incoming_inherited_tags:
            obj.tags.set(cleaned_tag_list)


def get_products(instance):
    if isinstance(instance, Product):
        return [instance]
    if isinstance(instance, Endpoint):
        return [instance.product]
    if isinstance(instance, Engagement):
        return [instance.product]
    if isinstance(instance, Test):
        return [instance.engagement.product]
    if isinstance(instance, Finding):
        return [instance.test.engagement.product]
    if isinstance(instance, Location):
        return list(instance.all_related_products())
    return []


def inherit_product_tags(instance) -> bool:
    products = get_products(instance)
    # Save a read in the db
    if any(product.enable_product_tag_inheritance for product in products if product):
        return True

    return get_system_setting("enable_product_tag_inheritance")


def get_products_to_inherit_tags_from(instance):
    products = get_products(instance)
    system_wide_inherit = get_system_setting("enable_product_tag_inheritance")

    return [
        product for product in products if product.enable_product_tag_inheritance or system_wide_inherit
    ]


def propagate_inheritance(instance, tag_list=None):
    # Get the expected product tags
    if tag_list is None:
        tag_list = []
    product_inherited_tags = [
        tag.name
        for product in get_products_to_inherit_tags_from(instance)
        for tag in product.tags.all()
    ]
    existing_inherited_tags = [tag.name for tag in instance.inherited_tags.all()]
    # Check if product tags already matches inherited tags
    product_tags_equals_inherited_tags = product_inherited_tags == existing_inherited_tags
    # Check if product tags have already been inherited
    tags_have_already_been_inherited = set(product_inherited_tags) <= set(tag_list)
    return not (product_tags_equals_inherited_tags and tags_have_already_been_inherited)


def inherit_instance_tags(instance):
    """Usually nothing to do when saving a model, except for new models?"""
    # Suppress per-instance inheritance work inside an active batch. The
    # caller (signal handler or bulk_create cleanup) need not know about
    # batch_mode; whoever opened the batch is responsible for the bulk
    # apply at exit.
    if is_in_batch_mode():
        return
    if inherit_product_tags(instance):
        # TODO: Is this change OK to make?
        # tag_list = instance._tags_tagulous.get_tag_list()
        tag_list = instance.tags.get_tag_list()
        if propagate_inheritance(instance, tag_list=tag_list):
            instance.inherit_tags(tag_list)


def inherit_linked_instance_tags(instance):
    inherit_instance_tags(instance.location)


# ---------------------------------------------------------------------------
# Bulk product-wide inheritance (relocated from dojo/product/helpers.py).
# Logic unchanged.
# ---------------------------------------------------------------------------


def propagate_tags_on_product_sync(product):
    """
    Bulk-apply Product tag changes to all children using through-table SQL.

    Replaces the previous per-row `.save()` loop. For every child model owned
    by the product (Engagement, Test, Finding, plus Endpoint or Location
    depending on the V3_FEATURE_LOCATIONS flag), reads the existing
    `inherited_tags` per child in one query, computes the diff against the
    Product's current tags, and applies adds/removes via the bulk tag
    helpers. Both `tags` and `inherited_tags` fields are kept in sync.
    """
    # Skip the full child sweep when inheritance is disabled both system-wide
    # and on this product. Without this gate the importer hot path pays ~9
    # queries per scan (one product-tags read + one list/through-table read per
    # child kind) even when no inheritance work is possible. State transitions
    # (toggling the flag on/off) still trigger a full sweep via the m2m_changed
    # handler on `Product.tags.through` and the per-product flag save handler.
    if not (product.enable_product_tag_inheritance or get_system_setting("enable_product_tag_inheritance")):
        return
    inherited_tag_names = {tag.name for tag in product.tags.all()}

    logger.debug("Propagating tags from %s to all engagements", product)
    _sync_inheritance_for_qs(
        Engagement.objects.filter(product=product),
        target_names_per_child=lambda _child: inherited_tag_names,
    )
    logger.debug("Propagating tags from %s to all tests", product)
    _sync_inheritance_for_qs(
        Test.objects.filter(engagement__product=product),
        target_names_per_child=lambda _child: inherited_tag_names,
    )
    logger.debug("Propagating tags from %s to all findings", product)
    _sync_inheritance_for_qs(
        Finding.objects.filter(test__engagement__product=product),
        target_names_per_child=lambda _child: inherited_tag_names,
    )
    if settings.V3_FEATURE_LOCATIONS:
        logger.debug("Propagating tags from %s to all locations", product)
        location_qs = Location.objects.filter(
            Q(products__product=product)
            | Q(findings__finding__test__engagement__product=product),
        ).distinct().prefetch_related(*_LOCATION_PREFETCH_FOR_INHERITANCE)
        # Locations can be linked to multiple products, so the inherited target
        # is the union of every related product's tags. Compute per-location.
        _sync_inheritance_for_qs(
            location_qs,
            target_names_per_child=_inherited_tag_names_for_location,
        )
    else:
        logger.debug("Propagating tags from %s to all endpoints", product)
        _sync_inheritance_for_qs(
            Endpoint.objects.filter(product=product),
            target_names_per_child=lambda _child: inherited_tag_names,
        )


def apply_inherited_tags_for_endpoints(endpoints):
    """
    Bulk inheritance for a list of Endpoints, e.g. those just created via
    `Endpoint.objects.bulk_create` (which bypasses post_save signals).

    All endpoints are assumed to share a single Product — true for the
    importer's `EndpointManager`, which is per-product. If callers ever
    mix products, split the list before calling.
    """
    if not endpoints:
        return
    product = endpoints[0].product
    if not (product.enable_product_tag_inheritance or get_system_setting("enable_product_tag_inheritance")):
        return
    inherited_tag_names = {tag.name for tag in product.tags.all()}
    _sync_inheritance_for_qs(
        Endpoint.objects.filter(id__in=[e.pk for e in endpoints]),
        target_names_per_child=lambda _child: inherited_tag_names,
    )


def apply_inherited_tags_for_findings(findings):
    """
    Per-batch bulk inheritance for findings created during an import.

    Apply the owning Product's inherited tags to the given findings plus the
    Endpoints (V2) / Locations (V3) reachable from them. Called from the
    importer hot path right before each batch dispatches to
    `post_process_findings_batch` so rules / deduplication see inherited tags
    on `finding.tags`.

    Test and Engagement inheritance is handled by their own post_save handlers
    (those run outside the importer's `batch_mode()`, so per-instance signal
    work fires normally and applies inheritance on create).
    """
    if not findings:
        return
    # Single-product invariant inside one importer call. Smart upload calls
    # this per-product so the assumption holds there too.
    product = findings[0].test.engagement.product
    if not (product.enable_product_tag_inheritance or get_system_setting("enable_product_tag_inheritance")):
        return
    inherited_tag_names = {tag.name for tag in product.tags.all()}
    finding_ids = [f.pk for f in findings]

    _sync_inheritance_for_qs(
        Finding.objects.filter(id__in=finding_ids),
        target_names_per_child=lambda _child: inherited_tag_names,
    )
    if settings.V3_FEATURE_LOCATIONS:
        _sync_inheritance_for_qs(
            Location.objects.filter(findings__finding_id__in=finding_ids).distinct().prefetch_related(*_LOCATION_PREFETCH_FOR_INHERITANCE),
            target_names_per_child=_inherited_tag_names_for_location,
        )
    else:
        _sync_inheritance_for_qs(
            Endpoint.objects.filter(status_endpoint__finding_id__in=finding_ids).distinct(),
            target_names_per_child=lambda _child: inherited_tag_names,
        )


def _inherited_tag_names_for_location(location):
    """
    Compute the tag-name set this Location should have as `inherited_tags`.

    Unlike Finding / Test / Engagement / Endpoint (each owned by exactly one
    Product), a Location can be attached to multiple Products — directly via
    `LocationProductReference` or indirectly via `LocationFindingReference`
    -> Finding -> Test -> Engagement -> Product. The target inherited set is
    therefore the UNION of every related Product's tags.

    Used as the `target_names_per_child` callback for `_sync_inheritance_for_qs`
    on Location querysets; it must be called per Location because each Location
    has its own set of related Products. Uses `iter_related_products()` so
    that an upstream `prefetch_related(...)` reduces per-call cost to 0
    queries.
    """
    names: set[str] = set()
    for related_product in location.iter_related_products():
        if related_product is None:
            continue
        names.update(tag.name for tag in related_product.tags.all())
    return names


_LOCATION_PREFETCH_FOR_INHERITANCE = (
    "products__product__tags",
    "findings__finding__test__engagement__product__tags",
)


def _sync_inheritance_for_qs(queryset, *, target_names_per_child):
    """
    Sync inherited_tags + tags for every child in `queryset` to its target tag set.

    target_names_per_child: callable(child) -> set[str].

    Issues bulk SQL: one through-table read for current inherited_tags, then
    bulk add/remove on `tags` and `inherited_tags` fields.
    """
    children = list(queryset)
    if not children:
        return

    model_class = type(children[0])
    inherited_field = model_class._meta.get_field("inherited_tags")
    inherited_through = inherited_field.remote_field.through
    inherited_tag_model = inherited_field.related_model

    # Resolve through-table FK column for the source side.
    source_field_name = None
    for field in inherited_through._meta.fields:
        if hasattr(field, "remote_field") and field.remote_field and field.remote_field.model == model_class:
            source_field_name = field.name
            break

    child_ids = [c.pk for c in children]
    # One query: pull every (child_id, tag_name) pair from the inherited_tags through table.
    existing_pairs = inherited_through.objects.filter(
        **{f"{source_field_name}__in": child_ids},
    ).values_list(source_field_name, f"{inherited_tag_model._meta.model_name}__name")

    old_inherited_by_child: dict[int, set[str]] = defaultdict(set)
    for child_id, tag_name in existing_pairs:
        old_inherited_by_child[child_id].add(tag_name)

    # Compute per-child diff and bucket by tag name.
    add_map: dict[str, list] = defaultdict(list)
    remove_map: dict[str, list] = defaultdict(list)
    for child in children:
        target = target_names_per_child(child)
        old = old_inherited_by_child.get(child.pk, set())
        for name in target - old:
            add_map[name].append(child)
        for name in old - target:
            remove_map[name].append(child)

    # Apply adds. Both `tags` and `inherited_tags` get the same set of new
    # inherited names — `_manage_inherited_tags` did the same.
    if add_map:
        bulk_add_tag_mapping(add_map, tag_field_name="inherited_tags")
        bulk_add_tag_mapping(add_map, tag_field_name="tags")

    # Apply removes.
    for name, instances in remove_map.items():
        bulk_remove_tags_from_instances(name, instances, tag_field_name="inherited_tags")
        bulk_remove_tags_from_instances(name, instances, tag_field_name="tags")
