import contextlib
from django.db.models import signals
from django.dispatch import receiver
import logging
from dojo.models import Product, Engagement, Test, Finding, Endpoint
from dojo.utils import get_system_setting
from dojo.product import helpers as async_product_funcs

logger = logging.getLogger(__name__)


@receiver(signals.m2m_changed, sender=Product.tags.through)
def product_tags_post_add_remove(sender, instance, action, **kwargs):
    if action in ["post_add", "post_remove"]:
        # Get the tags from the presave signal
        running_async_process = False
        with contextlib.suppress(AttributeError):
            running_async_process = instance.running_async_process
        # Check if the async process is already running to avoid calling it a second time
        if not running_async_process and inherit_product_tags(instance):
            async_product_funcs.propagate_tags_on_product.apply_async(args=(instance.id, ), countdown=5)
            instance.running_async_process = True


@receiver(signals.m2m_changed, sender=Endpoint.tags.through)
@receiver(signals.m2m_changed, sender=Engagement.tags.through)
@receiver(signals.m2m_changed, sender=Test.tags.through)
@receiver(signals.m2m_changed, sender=Finding.tags.through)
def object_tags_post_add_remove(sender, instance, action, **kwargs):
    if action in ["post_add", "post_remove"]:
        if inherit_product_tags(instance):
            instance = instance.inherit_tags()
            instance.save()


@receiver(signals.post_save, sender=Endpoint)
@receiver(signals.post_save, sender=Engagement)
@receiver(signals.post_save, sender=Test)
@receiver(signals.post_save, sender=Finding)
def inherit_tags_object_no_tags(sender, instance, **kwargs):
    if instance.tags.all().count() == 0 and inherit_product_tags(instance):
        instance = instance.inherit_tags()


def inherit_product_tags(object) -> bool:
    object_level_preference = False
    if isinstance(object, Product):
        object_level_preference = object.enable_product_tag_inheritance
    if isinstance(object, Endpoint):
        object_level_preference = object.product.enable_product_tag_inheritance
    if isinstance(object, Engagement):
        object_level_preference = object.product.enable_product_tag_inheritance
    if isinstance(object, Test):
        object_level_preference = object.engagement.product.enable_product_tag_inheritance
    if isinstance(object, Finding):
        object_level_preference = object.test.engagement.product.enable_product_tag_inheritance
    # Save a read in the db
    if object_level_preference:
        return True

    return get_system_setting('enable_product_tag_inheritance')
