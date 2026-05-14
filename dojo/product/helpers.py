import contextlib
import logging
from collections import defaultdict

from django.conf import settings
from django.db.models import Q

from dojo.celery import app
from dojo.location.models import Location
from dojo.models import Endpoint, Engagement, Finding, Product, Test
from dojo.tag_utils import bulk_add_tag_mapping, bulk_remove_tags_from_instances
from dojo.utils import get_system_setting

logger = logging.getLogger(__name__)


@app.task
def propagate_tags_on_product(product_id, *args, **kwargs):
    with contextlib.suppress(Product.DoesNotExist):
        product = Product.objects.get(id=product_id)
        propagate_tags_on_product_sync(product)


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
