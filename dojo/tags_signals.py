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
