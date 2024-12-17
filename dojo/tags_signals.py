import contextlib
import logging

from django.db.models import signals
from django.dispatch import receiver

from dojo.models import Endpoint, Engagement, Finding, Product, Test
from dojo.product import helpers as async_product_funcs
from dojo.utils import get_system_setting

logger = logging.getLogger(__name__)

@receiver(signals.post_delete, sender=Finding)
def delete_problem_if_no_findings(sender, instance, **kwargs):
    problem = instance._state.fields_cache.get('problem', None)
    if problem is not None:
        if not problem.findings.exists():  
            problem.delete()

@receiver(signals.m2m_changed, sender=Product.tags.through)
def product_tags_post_add_remove(sender, instance, action, **kwargs):
    if action in ["post_add", "post_remove"]:
        running_async_process = False
        with contextlib.suppress(AttributeError):
            running_async_process = instance.running_async_process
        # Check if the async process is already running to avoid calling it a second time
        if not running_async_process and inherit_product_tags(instance):
            async_product_funcs.propagate_tags_on_product(instance.id, countdown=5)
            instance.running_async_process = True


@receiver(signals.m2m_changed, sender=Endpoint.tags.through)
@receiver(signals.m2m_changed, sender=Engagement.tags.through)
@receiver(signals.m2m_changed, sender=Test.tags.through)
@receiver(signals.m2m_changed, sender=Finding.tags.through)
def make_inherited_tags_sticky(sender, instance, action, **kwargs):
    if action in ["post_add", "post_remove"]:
        if inherit_product_tags(instance):
            tag_list = [tag.name for tag in instance.tags.all()]
            if propagate_inheritance(instance, tag_list=tag_list):
                instance.inherit_tags(tag_list)


@receiver(signals.post_save, sender=Endpoint)
@receiver(signals.post_save, sender=Engagement)
@receiver(signals.post_save, sender=Test)
@receiver(signals.post_save, sender=Finding)
def inherit_tags_on_instance(sender, instance, created, **kwargs):
    if inherit_product_tags(instance):
        tag_list = instance._tags_tagulous.get_tag_list()
        if propagate_inheritance(instance, tag_list=tag_list):
            instance.inherit_tags(tag_list)


def propagate_inheritance(instance, tag_list=[]):
    # Get the expected product tags
    product_inherited_tags = [tag.name for tag in get_product(instance).tags.all()]
    existing_inherited_tags = [tag.name for tag in instance.inherited_tags.all()]
    # Check if product tags already matches inherited tags
    product_tags_equals_inherited_tags = product_inherited_tags == existing_inherited_tags
    # Check if product tags have already been inherited
    tags_have_already_been_inherited = set(product_inherited_tags) <= set(tag_list)
    return not (product_tags_equals_inherited_tags and tags_have_already_been_inherited)


def inherit_product_tags(instance) -> bool:
    product = get_product(instance)
    # Save a read in the db
    if product and product.enable_product_tag_inheritance:
        return True

    return get_system_setting("enable_product_tag_inheritance")


def get_product(instance):
    if isinstance(instance, Product):
        return instance
    if isinstance(instance, Endpoint):
        return instance.product
    if isinstance(instance, Engagement):
        return instance.product
    if isinstance(instance, Test):
        return instance.engagement.product
    if isinstance(instance, Finding):
        return instance.test.engagement.product
    return None
