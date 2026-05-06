import contextlib
import logging
from collections import defaultdict

from django.conf import settings
from django.db.models import Q

from dojo.celery import app
from dojo.location.models import Location, LocationFindingReference, LocationProductReference
from dojo.models import Endpoint, Engagement, Finding, Product, Test
from dojo.tag_utils import bulk_add_tag_mapping, bulk_remove_tags_from_instances

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
    target_names = {tag.name for tag in product.tags.all()}

    logger.debug("Propagating tags from %s to all engagements", product)
    _sync_inheritance_for_qs(
        Engagement.objects.filter(product=product),
        target_names_per_child=lambda _child: target_names,
    )
    logger.debug("Propagating tags from %s to all tests", product)
    _sync_inheritance_for_qs(
        Test.objects.filter(engagement__product=product),
        target_names_per_child=lambda _child: target_names,
    )
    logger.debug("Propagating tags from %s to all findings", product)
    _sync_inheritance_for_qs(
        Finding.objects.filter(test__engagement__product=product),
        target_names_per_child=lambda _child: target_names,
    )
    if settings.V3_FEATURE_LOCATIONS:
        logger.debug("Propagating tags from %s to all locations", product)
        # Materialize once so we can build a precomputed
        # {location_id: set[tag_name]} map without re-evaluating the queryset
        # or paying N+1 in `_location_target_names`.
        locations = list(Location.objects.filter(
            Q(products__product=product)
            | Q(findings__finding__test__engagement__product=product),
        ).distinct())
        location_target_names = _build_location_target_names_map(
            [loc.pk for loc in locations],
        )
        _sync_inheritance_for_qs(
            locations,
            target_names_per_child=lambda loc: location_target_names.get(loc.pk, set()),
        )
    else:
        logger.debug("Propagating tags from %s to all endpoints", product)
        _sync_inheritance_for_qs(
            Endpoint.objects.filter(product=product),
            target_names_per_child=lambda _child: target_names,
        )


def _build_location_target_names_map(location_ids):
    """
    Bulk-compute {location_id: set[tag_name]} for the given locations.

    Replaces the per-location `_location_target_names` callable, which issued
    one `Product.objects.filter(...).distinct()` query plus N `.tags.all()`
    queries per location. Now: 3 queries total regardless of fan-out.
    """
    if not location_ids:
        return {}

    location_to_products: dict[int, set[int]] = defaultdict(set)
    for loc_id, prod_id in LocationProductReference.objects.filter(
        location_id__in=location_ids,
    ).values_list("location_id", "product_id"):
        location_to_products[loc_id].add(prod_id)
    for loc_id, prod_id in LocationFindingReference.objects.filter(
        location_id__in=location_ids,
    ).values_list("location_id", "finding__test__engagement__product_id"):
        if prod_id is not None:
            location_to_products[loc_id].add(prod_id)

    all_product_ids = {pid for pids in location_to_products.values() for pid in pids}
    if not all_product_ids:
        return {loc_id: set() for loc_id in location_ids}

    product_tags_through = Product.tags.through
    tag_model = Product.tags.tag_model
    tag_field_name = tag_model._meta.model_name
    product_to_tag_names: dict[int, set[str]] = defaultdict(set)
    for prod_id, tag_name in product_tags_through.objects.filter(
        product_id__in=all_product_ids,
    ).values_list("product_id", f"{tag_field_name}__name"):
        product_to_tag_names[prod_id].add(tag_name)

    return {
        loc_id: {
            name
            for pid in pids
            for name in product_to_tag_names.get(pid, set())
        }
        for loc_id, pids in location_to_products.items()
    }


def _sync_inheritance_for_qs(queryset, *, target_names_per_child):
    """
    Sync `_inherited_tag_names` (JSON column) + `tags` (M2M) for every child
    in `queryset` to its target tag set.

    target_names_per_child: callable(child) -> set[str].

    Issues bulk SQL:
      - one fetch of `(pk, _inherited_tag_names, tags through-table)`
      - bulk add/remove on `tags` based on the diff
      - bulk UPDATE of `_inherited_tag_names`
    """
    children = queryset if isinstance(queryset, list) else list(queryset.only("pk", "_inherited_tag_names"))
    if not children:
        return

    model_class = type(children[0])
    tags_field = model_class._meta.get_field("tags")
    tags_through = tags_field.remote_field.through
    tags_tag_model = tags_field.related_model

    # Resolve through-table FK column for the source side.
    source_field_name = None
    for field in tags_through._meta.fields:
        if hasattr(field, "remote_field") and field.remote_field and field.remote_field.model == model_class:
            source_field_name = field.name
            break

    child_ids = [c.pk for c in children]

    # Read each child's persisted "what was inherited" JSON column.
    old_inherited_by_child: dict[int, set[str]] = {
        c.pk: set(c._inherited_tag_names or []) for c in children
    }

    # Read each child's current `tags` through-table in one bulk SELECT.
    existing_tags_pairs = tags_through.objects.filter(
        **{f"{source_field_name}__in": child_ids},
    ).values_list(source_field_name, f"{tags_tag_model._meta.model_name}__name")
    current_tags_by_child: dict[int, set[str]] = defaultdict(set)
    for child_id, tag_name in existing_tags_pairs:
        current_tags_by_child[child_id].add(tag_name)

    # Compute per-child diff:
    #   - add_map: names in target but not currently inherited (need add to `tags`)
    #   - remove_map: names previously inherited but no longer in target (remove from `tags`)
    #   - remerge_map: names in target but missing from `tags` (sticky re-merge)
    #   - new_inherited_per_child: the JSON column write
    add_map: dict[str, list] = defaultdict(list)
    remove_map: dict[str, list] = defaultdict(list)
    remerge_map: dict[str, list] = defaultdict(list)
    new_inherited_per_child: dict[int, list[str]] = {}
    for child in children:
        target = set(target_names_per_child(child))
        old = old_inherited_by_child.get(child.pk, set())
        current_tags = current_tags_by_child.get(child.pk, set())

        # JSON column desired value: deterministic order = sorted names.
        new_inherited_per_child[child.pk] = sorted(target)

        # Names newly inherited (not previously recorded in JSON column).
        newly_added_names = target - old
        for name in newly_added_names:
            add_map[name].append(child)
        # Names previously inherited but no longer in target.
        for name in old - target:
            remove_map[name].append(child)
        # Sticky re-merge: target name missing from `tags`. Skip names
        # already covered by add_map for this child to avoid double-write.
        for name in (target - current_tags) - newly_added_names:
            remerge_map[name].append(child)

    # Apply tag-add. Combine add_map + remerge_map; the two never overlap
    # for the same (child, name) pair by construction above.
    combined_add: dict[str, list] = defaultdict(list)
    for name, lst in add_map.items():
        combined_add[name].extend(lst)
    for name, lst in remerge_map.items():
        combined_add[name].extend(lst)
    if combined_add:
        bulk_add_tag_mapping(combined_add, tag_field_name="tags")

    # Apply tag-remove.
    for name, instances in remove_map.items():
        bulk_remove_tags_from_instances(name, instances, tag_field_name="tags")

    # Bulk-write the JSON column. Group children by desired value to minimize
    # UPDATE statements.
    grouped_writes: dict[tuple[str, ...], list[int]] = defaultdict(list)
    for child_id, names in new_inherited_per_child.items():
        if names != sorted(old_inherited_by_child.get(child_id, set())):
            grouped_writes[tuple(names)].append(child_id)
    for names_tuple, ids in grouped_writes.items():
        model_class.objects.filter(pk__in=ids).update(_inherited_tag_names=list(names_tuple))
