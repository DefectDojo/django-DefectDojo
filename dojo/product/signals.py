import contextlib
from django.db.models import signals
from django.dispatch import receiver
import logging
from dojo.models import Product, Engagement, Test, Finding, Endpoint
from dojo.utils import get_system_setting
from dojo.product import helpers as async_product_funcs

logger = logging.getLogger(__name__)


@receiver(signals.pre_save, sender=Product)
def initial_product_save_sla_configuration(sender, instance, **kwargs):
    # post save, it is not a guarantee that the product exists yet (i.e. a brand new product)
    sla_config = getattr(Product.objects.filter(id=instance.id).first(), 'sla_configuration', None)
    if sla_config:
        instance._old_sla_configuration = sla_config


@receiver(signals.post_save, sender=Product)
def post_product_save_sla_configuration(sender, instance, **kwargs):
    # post save, it is not a guarantee that the product went through the pre save signal
    old_sla_config = getattr(instance, '_old_sla_configuration', None)

    # check to see if the sla configuration changed (check pre save against post save attribute)
    if old_sla_config and old_sla_config != instance.sla_configuration:
        logger.debug(f"{instance} SLA configuration changed - updating the SLA expiration date on each finding")
        async_product_funcs.update_sla_expiration_dates_product_async(instance)


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

    return get_system_setting('enable_product_tag_inheritance')


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
