import contextlib
import logging
from collections import defaultdict

from django.conf import settings
from django.db.models import Q

from dojo.celery import app
from dojo.location.models import Location
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
        location_qs = Location.objects.filter(
            Q(products__product=product)
            | Q(findings__finding__test__engagement__product=product),
        ).distinct()
        # Locations can be linked to multiple products, so the inherited target
        # is the union of every related product's tags. Compute per-location.
        _sync_inheritance_for_qs(
            location_qs,
            target_names_per_child=_location_target_names,
        )
    else:
        logger.debug("Propagating tags from %s to all endpoints", product)
        _sync_inheritance_for_qs(
            Endpoint.objects.filter(product=product),
            target_names_per_child=lambda _child: target_names,
        )


def _location_target_names(location):
    names: set[str] = set()
    for related_product in location.all_related_products():
        if related_product is None:
            continue
        names.update(tag.name for tag in related_product.tags.all())
    return names


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

    # Compute per-child diff and bucket by tag name. Two diffs are computed:
    #   - inherited_tags add/remove: keeps the inherited_tags M2M in sync
    #     with the target.
    #   - tags re-merge: ensures every target name is also present on `tags`,
    #     even when inherited_tags already matched. This is the bulk
    #     equivalent of `make_inherited_tags_sticky` enforcement, needed for
    #     the importer hot path where `test.tags.set([...])` overwrites the
    #     full tag list inside a `tag_inheritance.batch()` block.
    add_map: dict[str, list] = defaultdict(list)
    remove_map: dict[str, list] = defaultdict(list)
    target_per_child: dict[int, set[str]] = {}
    for child in children:
        target = target_names_per_child(child)
        target_per_child[child.pk] = target
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

    # Bulk re-merge: ensure every target name is present on `tags`. We need
    # this for the importer hot path where `tags.set([...])` inside a
    # `tag_inheritance.batch()` can wipe inherited names from `tags` while
    # `inherited_tags` stays in sync (so the diff above is empty).
    #
    # Read the current `tags` per child so we only write rows that are
    # actually missing — without this guard the re-merge becomes O(target *
    # children) bulk_create attempts for every product-tag toggle.
    tags_field = model_class._meta.get_field("tags")
    tags_through = tags_field.remote_field.through
    tags_tag_model = tags_field.related_model
    existing_tags_pairs = tags_through.objects.filter(
        **{f"{source_field_name}__in": child_ids},
    ).values_list(source_field_name, f"{tags_tag_model._meta.model_name}__name")

    current_tags_by_child: dict[int, set[str]] = defaultdict(set)
    for child_id, tag_name in existing_tags_pairs:
        current_tags_by_child[child_id].add(tag_name)

    remerge_map: dict[str, list] = defaultdict(list)
    for child in children:
        target = target_per_child[child.pk]
        current = current_tags_by_child.get(child.pk, set())
        # Skip names already added by the diff above; only fix true drift.
        already_added = {name for name, lst in add_map.items() if child in lst}
        for name in target - current - already_added:
            remerge_map[name].append(child)
    if remerge_map:
        bulk_add_tag_mapping(remerge_map, tag_field_name="tags")
