import contextlib
import logging

from django.db.models import signals
from django.dispatch import receiver

from dojo.celery_dispatch import dojo_dispatch_task
from dojo.location.models import Location, LocationFindingReference, LocationProductReference
from dojo.models import Endpoint, Engagement, Finding, Product, Test
from dojo.product import helpers as async_product_funcs
from dojo.utils import get_system_setting

logger = logging.getLogger(__name__)


@receiver(signals.m2m_changed, sender=Product.tags.through)
def product_tags_post_add_remove(sender, instance, action, **kwargs):
    if action in {"post_add", "post_remove"}:
        running_async_process = False
        with contextlib.suppress(AttributeError):
            running_async_process = instance.running_async_process
        # Check if the async process is already running to avoid calling it a second time
        if not running_async_process and inherit_product_tags(instance):
            dojo_dispatch_task(async_product_funcs.propagate_tags_on_product, instance.id, countdown=5)
            instance.running_async_process = True


@receiver(signals.m2m_changed, sender=Endpoint.tags.through)
@receiver(signals.m2m_changed, sender=Engagement.tags.through)
@receiver(signals.m2m_changed, sender=Test.tags.through)
@receiver(signals.m2m_changed, sender=Finding.tags.through)
@receiver(signals.m2m_changed, sender=Location.tags.through)
def make_inherited_tags_sticky(sender, instance, action, **kwargs):
    """Make sure inherited tags are added back in if they are removed"""
    if action in {"post_add", "post_remove"}:
        if inherit_product_tags(instance):
            tag_list = [tag.name for tag in instance.tags.all()]
            if propagate_inheritance(instance, tag_list=tag_list):
                instance.inherit_tags(tag_list)


def inherit_instance_tags(instance):
    """Usually nothing to do when saving a model, except for new models?"""
    if inherit_product_tags(instance):
        # TODO: Is this change OK to make?
        # tag_list = instance._tags_tagulous.get_tag_list()
        tag_list = instance.tags.get_tag_list()
        if propagate_inheritance(instance, tag_list=tag_list):
            instance.inherit_tags(tag_list)


def bulk_inherit_location_tags(locations, *, known_product=None):
    """
    Bulk equivalent of calling inherit_instance_tags(loc) for many Locations.

    Uses aggressive prefetching to produce O(1) queries for the "decide what needs
    to change" phase, and only runs per-instance mutation queries (~3 each) for
    locations that are actually out of sync with their product tags.

    Compared to the per-instance path, this avoids the N expensive JOINs in
    Location.all_related_products() (~50ms each).

    Args:
        locations: iterable of Location instances to update
        known_product: optional hint — if provided, used as the minimum product
            set for locations not already associated elsewhere. Not strictly
            required for correctness, but lets us skip the fetch-related-products
            query in the common case.

    """
    locations = list(locations)
    if not locations:
        return

    system_wide_inherit = bool(get_system_setting("enable_product_tag_inheritance"))

    # --- Bulk query: map location_id -> set[product_id] for every related product
    location_ids = [loc.id for loc in locations]
    product_ids_by_location: dict[int, set[int]] = {loc.id: set() for loc in locations}

    # Path 1: via LocationProductReference (direct association)
    for loc_id, prod_id in LocationProductReference.objects.filter(
        location_id__in=location_ids,
    ).values_list("location_id", "product_id"):
        product_ids_by_location[loc_id].add(prod_id)

    # Path 2: via LocationFindingReference -> Finding -> Test -> Engagement -> Product
    for loc_id, prod_id in (
        LocationFindingReference.objects
        .filter(location_id__in=location_ids)
        .values_list("location_id", "finding__test__engagement__product_id")
    ):
        if prod_id is not None:
            product_ids_by_location[loc_id].add(prod_id)

    # Seed with known_product so callers don't have to rely on refs being persisted before this call
    if known_product is not None:
        for loc_id in location_ids:
            product_ids_by_location[loc_id].add(known_product.id)

    # --- Bulk query: fetch the unique products with their tags and inheritance flag
    all_product_ids = {pid for pids in product_ids_by_location.values() for pid in pids}
    if not all_product_ids:
        return

    products = {
        p.id: p
        for p in Product.objects.filter(id__in=all_product_ids).prefetch_related("tags")
    }

    # Products that contribute to inheritance (either opted in themselves or system-wide on)
    contributing_product_ids = {
        pid for pid, p in products.items()
        if p.enable_product_tag_inheritance or system_wide_inherit
    }
    if not contributing_product_ids:
        # No product with inheritance enabled and system-wide is off → nothing to do
        return

    # Pre-compute the tag names each contributing product contributes
    tags_by_product: dict[int, set[str]] = {
        pid: {t.name for t in products[pid].tags.all()}
        for pid in contributing_product_ids
    }

    # --- Bulk query: existing inherited_tags per location
    inherited_through = Location.inherited_tags.through
    inherited_fk = Location.inherited_tags.field.m2m_reverse_field_name()
    existing_inherited_by_location: dict[int, set[str]] = {loc.id: set() for loc in locations}
    for loc_id, tag_name in inherited_through.objects.filter(
        location_id__in=location_ids,
    ).values_list("location_id", f"{inherited_fk}__name"):
        existing_inherited_by_location[loc_id].add(tag_name)

    # --- Bulk query: existing user tags per location (needed by _manage_inherited_tags)
    tags_through = Location.tags.through
    tags_fk = Location.tags.field.m2m_reverse_field_name()
    existing_tags_by_location: dict[int, list[str]] = {loc.id: [] for loc in locations}
    for loc_id, tag_name in tags_through.objects.filter(
        location_id__in=location_ids,
    ).values_list("location_id", f"{tags_fk}__name"):
        existing_tags_by_location[loc_id].append(tag_name)

    # --- Determine which locations are out of sync and call _manage_inherited_tags directly.
    # Calling _manage_inherited_tags with pre-computed values skips the expensive
    # products_to_inherit_tags_from() JOIN that location.inherit_tags() would run.
    #
    # Must disconnect make_inherited_tags_sticky while we mutate — otherwise each
    # tags.set() / inherited_tags.set() fires m2m_changed, re-enters the whole expensive
    # chain per location, and defeats the point of the bulk path.
    from dojo.models import _manage_inherited_tags  # noqa: PLC0415 circular import

    signals.m2m_changed.disconnect(make_inherited_tags_sticky, sender=tags_through)
    signals.m2m_changed.disconnect(make_inherited_tags_sticky, sender=inherited_through)
    try:
        for location in locations:
            target_tag_names: set[str] = set()
            for pid in product_ids_by_location[location.id]:
                if pid in contributing_product_ids:
                    target_tag_names |= tags_by_product[pid]

            existing = existing_inherited_by_location[location.id]
            if target_tag_names == existing:
                continue  # Already in sync — skip the expensive mutation path entirely

            _manage_inherited_tags(
                location,
                list(target_tag_names),
                potentially_existing_tags=existing_tags_by_location[location.id],
            )
    finally:
        signals.m2m_changed.connect(make_inherited_tags_sticky, sender=tags_through)
        signals.m2m_changed.connect(make_inherited_tags_sticky, sender=inherited_through)


def inherit_linked_instance_tags(instance: LocationFindingReference | LocationProductReference):
    inherit_instance_tags(instance.location)


@receiver(signals.post_save, sender=Endpoint)
@receiver(signals.post_save, sender=Engagement)
@receiver(signals.post_save, sender=Test)
@receiver(signals.post_save, sender=Finding)
@receiver(signals.post_save, sender=Location)
def inherit_tags_on_instance(sender, instance, created, **kwargs):
    inherit_instance_tags(instance)


@receiver(signals.post_save, sender=LocationFindingReference)
@receiver(signals.post_save, sender=LocationProductReference)
def inherit_tags_on_linked_instance(sender, instance, created, **kwargs):
    inherit_linked_instance_tags(instance)


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


def inherit_product_tags(instance) -> bool:
    products = get_products(instance)
    # Save a read in the db
    if any(product.enable_product_tag_inheritance for product in products if product):
        return True

    return get_system_setting("enable_product_tag_inheritance")


def get_products_to_inherit_tags_from(instance) -> list[Product]:
    products = get_products(instance)
    system_wide_inherit = get_system_setting("enable_product_tag_inheritance")

    return [
        product for product in products if product.enable_product_tag_inheritance or system_wide_inherit
    ]


def get_products(instance) -> list[Product]:
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
