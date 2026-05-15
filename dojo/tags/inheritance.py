from __future__ import annotations

import logging
import threading
from collections import defaultdict
from contextlib import contextmanager, suppress

from django.conf import settings
from django.db.models import Q
from tagulous.models.managers import FakeTagRelatedManager

# Top-level imports of dojo internals are safe here because
# ``dojo.tags.inheritance`` is loaded lazily — never during the initial
# evaluation of ``dojo.models``. By the time anything imports this module
# (signals registration, importers, the per-model ``inherit_tags()`` shim
# in ``dojo.models``), the full model layer is initialised.
from dojo.celery import app
from dojo.location.models import Location
from dojo.models import Endpoint, Engagement, Finding, Product, Test
from dojo.tags.utils import bulk_add_tag_mapping, bulk_remove_tags_from_instances
from dojo.utils import get_system_setting

logger = logging.getLogger(__name__)

_state = threading.local()


def is_suppressed() -> bool:
    """Return True when the current thread is inside an active ``suppress_tag_inheritance()``."""
    return bool(getattr(_state, "depth", 0))


@contextmanager
def suppress_tag_inheritance():
    """
    Suppress per-instance inheritance signals for the calling thread.

    Usage:
        with tag_inheritance.suppress_tag_inheritance():
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
            with suppress(AttributeError):
                del _state.depth


def _sync_inherited_tags(obj, incoming_inherited_tags):
    """
    Sync ``obj.inherited_tags`` and ``obj.tags`` to match ``incoming_inherited_tags``.

    Diff-based: only the inherited names that changed are added/removed. Also
    re-adds any inherited name that has been stripped from ``obj.tags`` directly
    (sticky enforcement).

    Writes are wrapped in ``suppress_tag_inheritance()`` so the m2m_changed
    signal fired by each ``.add()``/``.remove()`` does not dispatch
    ``make_inherited_tags_sticky`` back into this function. The context
    manager is reentrant so callers that already opened a batch (e.g.
    ``auto_inherit_product_tags`` in ``dojo.tags.signals``, or the importer's
    bulk path)
    nest harmlessly.
    """
    target = set(incoming_inherited_tags or [])

    # Unsaved instance: FakeTagRelatedManager has no .all()/.add()/.remove().
    # Set in-memory tag lists directly, merging incoming into any preset tags.
    # set_tag_list() is purely in-memory — no DB write, no m2m_changed — so it
    # doesn't need the suppress wrap. The `obj.tags.add(*target)` fallback
    # below covers a theoretical mixed-state case (saved tags manager next to
    # an unsaved inherited_tags manager) and DOES fire m2m_changed, so it
    # gets wrapped.
    if isinstance(obj.inherited_tags, FakeTagRelatedManager):
        obj.inherited_tags.set_tag_list(list(target))
        if target:
            if isinstance(obj.tags, FakeTagRelatedManager):
                existing = obj.tags.get_tag_list()
                obj.tags.set_tag_list(list(dict.fromkeys([*existing, *target])))
            else:
                # avoid reentrancy: the `add(*target)` write fires m2m_changed
                with suppress_tag_inheritance():
                    obj.tags.add(*target)
        return

    current_inherited = {tag.name for tag in obj.inherited_tags.all()}
    current_tags = {tag.name for tag in obj.tags.all()}
    to_remove = current_inherited - target
    to_add = target - current_inherited
    # Sticky: any target name already absent from obj.tags AND not covered by
    # to_add (user-driven m2m_changed stripped it). Re-add separately.
    sticky_missing = (target - current_tags) - to_add

    # avoid reentrancy: the `remove(*to_remove)` / `add(*to_add)` / `add(*sticky_missing)` writes fire m2m_changed
    with suppress_tag_inheritance():
        if to_remove:
            obj.inherited_tags.remove(*to_remove)
            obj.tags.remove(*to_remove)
        if to_add:
            obj.inherited_tags.add(*to_add)
            obj.tags.add(*to_add)
        if sticky_missing:
            obj.tags.add(*sticky_missing)


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


def get_products_to_inherit_tags_from(instance):
    products = [p for p in get_products(instance) if p]
    # System-wide setting is cached — short-circuit before reading the
    # per-product flag on every related product.
    if get_system_setting("enable_product_tag_inheritance"):
        return products
    return [product for product in products if product.enable_product_tag_inheritance]


def is_tag_inheritance_enabled(instance) -> bool:
    # delegate so we have logic centralized. no products -> no inheritance enabled.
    return bool(get_products_to_inherit_tags_from(instance))


# ---------------------------------------------------------------------------
# Bulk product-wide inheritance
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
    if not (get_system_setting("enable_product_tag_inheritance") or product.enable_product_tag_inheritance):
        return

    inherited_tag_names = {tag.name for tag in product.tags.all()}

    logger.debug("Propagating tags from %s to all engagements", product)
    _sync_inheritance_for_qs(
        Engagement.objects.filter(product=product),
        target_tag_names_per_child=lambda _child: inherited_tag_names,
    )
    logger.debug("Propagating tags from %s to all tests", product)
    _sync_inheritance_for_qs(
        Test.objects.filter(engagement__product=product),
        target_tag_names_per_child=lambda _child: inherited_tag_names,
    )
    logger.debug("Propagating tags from %s to all findings", product)
    _sync_inheritance_for_qs(
        Finding.objects.filter(test__engagement__product=product),
        target_tag_names_per_child=lambda _child: inherited_tag_names,
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
            target_tag_names_per_child=_inherited_tag_names_for_location,
        )
    else:
        logger.debug("Propagating tags from %s to all endpoints", product)
        _sync_inheritance_for_qs(
            Endpoint.objects.filter(product=product),
            target_tag_names_per_child=lambda _child: inherited_tag_names,
        )


@app.task(name="dojo.product.helpers.propagate_tags_on_product")
def propagate_tags_on_product_deprecated(product_id, *args, **kwargs):
    # kept to make sure tasks are still processed if someone didn't do a clean shutdown before upgrading
    logger.warning("propagate_tags_on_product_deprecated is deprecated and will be removed in a future version. Use propagate_tags_on_product instead.")
    propagate_tags_on_product(product_id, *args, **kwargs)


@app.task(name="dojo.product.helpers.propagate_tags_on_product")
def propagate_tags_on_product(product_id, *args, **kwargs):
    """Load Product by id and run ``propagate_tags_on_product_sync`` (Celery worker)."""
    with suppress(Product.DoesNotExist):
        product = Product.objects.get(id=product_id)
        propagate_tags_on_product_sync(product)


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
    if not (get_system_setting("enable_product_tag_inheritance") or product.enable_product_tag_inheritance):
        return
    inherited_tag_names = {tag.name for tag in product.tags.all()}
    _sync_inheritance_for_qs(
        Endpoint.objects.filter(id__in=[e.pk for e in endpoints]),
        target_tag_names_per_child=lambda _child: inherited_tag_names,
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
    if not (get_system_setting("enable_product_tag_inheritance") or product.enable_product_tag_inheritance):
        return
    inherited_tag_names = {tag.name for tag in product.tags.all()}
    finding_ids = [f.pk for f in findings]

    _sync_inheritance_for_qs(
        Finding.objects.filter(id__in=finding_ids),
        target_tag_names_per_child=lambda _child: inherited_tag_names,
    )
    if settings.V3_FEATURE_LOCATIONS:
        _sync_inheritance_for_qs(
            Location.objects.filter(findings__finding_id__in=finding_ids).distinct().prefetch_related(*_LOCATION_PREFETCH_FOR_INHERITANCE),
            target_tag_names_per_child=_inherited_tag_names_for_location,
        )
    else:
        _sync_inheritance_for_qs(
            Endpoint.objects.filter(status_endpoint__finding_id__in=finding_ids).distinct(),
            target_tag_names_per_child=lambda _child: inherited_tag_names,
        )


def _inherited_tag_names_for_location(location):
    """
    Compute the tag-name set this Location should have as `inherited_tags`.

    Unlike Finding / Test / Engagement / Endpoint (each owned by exactly one
    Product), a Location can be attached to multiple Products — directly via
    `LocationProductReference` or indirectly via `LocationFindingReference`
    -> Finding -> Test -> Engagement -> Product. The target inherited set is
    therefore the UNION of every related Product's tags, restricted to
    Products whose own `enable_product_tag_inheritance` flag is on (or where
    the system-wide setting is on).

    Used as the `target_tag_names_per_child` callback for `_sync_inheritance_for_qs`
    on Location querysets; it must be called per Location because each Location
    has its own set of related Products. Uses `iter_related_products()` so
    that an upstream `prefetch_related(...)` reduces per-call cost to 0
    queries.
    """
    system_wide = bool(get_system_setting("enable_product_tag_inheritance"))
    names: set[str] = set()
    for related_product in location.iter_related_products():
        if related_product is None:
            continue
        if not system_wide and not related_product.enable_product_tag_inheritance:
            continue
        names.update(tag.name for tag in related_product.tags.all())
    return names


def apply_inherited_tags_for_locations(locations, *, product):
    """
    Per-batch bulk inheritance for Locations touched during an import.

    A Location can be linked to multiple Products via `LocationProductReference`
    (direct) or `LocationFindingReference` -> Finding -> Test -> Engagement ->
    Product (indirect). Target inherited set is the union of every contributing
    Product's tags, filtered by each Product's `enable_product_tag_inheritance`
    flag (skipped entirely when the system-wide setting is on).

    Gated on the importing `product`: when neither the system setting nor the
    importing product's flag is on, this is a no-op. Tags from other products
    propagate via their own `Product.tags.through` m2m_changed handler when
    they change, so skipping here is safe.

    Uses values_list-based ref-table lookups (4 small queries) rather than
    `prefetch_related(_LOCATION_PREFETCH_FOR_INHERITANCE)` to keep the
    importer hot path lean.
    """
    locations = list(locations)
    if not locations:
        return
    system_wide = bool(get_system_setting("enable_product_tag_inheritance"))
    if not system_wide and not getattr(product, "enable_product_tag_inheritance", False):
        return

    from dojo.location.models import (  # noqa: PLC0415
        LocationFindingReference,
        LocationProductReference,
    )

    location_ids = [loc.id for loc in locations]
    product_ids_by_location: dict[int, set[int]] = {loc.id: set() for loc in locations}

    for loc_id, prod_id in LocationProductReference.objects.filter(
        location_id__in=location_ids,
    ).values_list("location_id", "product_id"):
        product_ids_by_location[loc_id].add(prod_id)

    # LocationFindingReference -> Finding -> Test -> Engagement -> Product.
    # Shouldn't add anything new (LocationProductReference is created alongside),
    # but covers edge cases where only the finding ref exists.
    for loc_id, prod_id in (
        LocationFindingReference.objects
        .filter(location_id__in=location_ids)
        .values_list("location_id", "finding__test__engagement__product_id")
    ):
        product_ids_by_location[loc_id].add(prod_id)

    all_product_ids = {pid for pids in product_ids_by_location.values() for pid in pids}
    product_qs = Product.objects.filter(id__in=all_product_ids).prefetch_related("tags")
    if not system_wide:
        product_qs = product_qs.filter(enable_product_tag_inheritance=True)
    tags_by_product: dict[int, set[str]] = {
        p.id: {t.name for t in p.tags.all()} for p in product_qs
    }

    def _target_for_location(loc):
        names: set[str] = set()
        for pid in product_ids_by_location[loc.id]:
            # product_ids_by_location may contain products that shouldn't contribute
            # (ref lookups weren't flag-filtered); check membership in tags_by_product.
            tags = tags_by_product.get(pid)
            if tags:
                names |= tags
        return names

    _sync_inheritance_for_qs(locations, target_tag_names_per_child=_target_for_location)


_LOCATION_PREFETCH_FOR_INHERITANCE = (
    "products__product__tags",
    "findings__finding__test__engagement__product__tags",
)


def _sync_inheritance_for_qs(queryset, *, target_tag_names_per_child):
    """
    Sync inherited_tags + tags for every child in `queryset` to its target tag set.

    target_tag_names_per_child: callable(child) -> set[str].

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
        target = target_tag_names_per_child(child)
        old = old_inherited_by_child.get(child.pk, set())
        for name in target - old:
            add_map[name].append(child)
        for name in old - target:
            remove_map[name].append(child)

    # Apply adds. Both `tags` and `inherited_tags` get the same set of new
    # inherited names — `_sync_inherited_tags` did the same.
    if add_map:
        bulk_add_tag_mapping(add_map, tag_field_name="inherited_tags")
        bulk_add_tag_mapping(add_map, tag_field_name="tags")

    # Apply removes.
    for name, instances in remove_map.items():
        bulk_remove_tags_from_instances(name, instances, tag_field_name="inherited_tags")
        bulk_remove_tags_from_instances(name, instances, tag_field_name="tags")
