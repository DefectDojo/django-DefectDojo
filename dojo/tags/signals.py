import contextlib
import logging

from django.db.models import signals
from django.dispatch import receiver

from dojo.celery_dispatch import dojo_dispatch_task
from dojo.location.models import Location, LocationFindingReference, LocationProductReference
from dojo.models import Endpoint, Engagement, Finding, Product, Test
from dojo.product import helpers as async_product_funcs
from dojo.tags import inheritance as tag_inheritance
from dojo.tags.inheritance import (
    get_products,  # noqa: F401 -- backward compat re-export
    get_products_to_inherit_tags_from,  # noqa: F401 -- backward compat re-export
    inherit_instance_tags,  # noqa: F401 -- backward compat re-export
    inherit_linked_instance_tags,  # noqa: F401 -- backward compat re-export
    inherit_product_tags,
    propagate_inheritance,
)

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
    # Inside a `tag_inheritance.batch()` block the caller takes responsibility
    # for applying inheritance in bulk; per-row signal work would defeat the
    # purpose. This replaces the old `signals.m2m_changed.disconnect(...)`
    # pattern, which was process-global and unsafe under threaded workers.
    if tag_inheritance.is_suppressed():
        return
    if action in {"post_add", "post_remove"}:
        if inherit_product_tags(instance):
            tag_list = [tag.name for tag in instance.tags.all()]
            if propagate_inheritance(instance, tag_list=tag_list):
                instance.inherit_tags(tag_list)


@receiver(signals.post_save, sender=Endpoint)
@receiver(signals.post_save, sender=Engagement)
@receiver(signals.post_save, sender=Test)
@receiver(signals.post_save, sender=Finding)
@receiver(signals.post_save, sender=Location)
def inherit_tags_on_instance(sender, instance, created, **kwargs):
    # Only inherit on creation. The previous behavior fired on every save
    # (create OR update), repeatedly re-applying inherited tags to children
    # whose tag state had not changed. Sticky enforcement on user-driven
    # tag edits is handled by `make_inherited_tags_sticky` (m2m_changed).
    # `inherit_instance_tags` itself early-returns when a batch is active.
    if not created:
        return
    tag_inheritance.inherit_instance_tags(instance)


@receiver(signals.post_save, sender=LocationFindingReference)
@receiver(signals.post_save, sender=LocationProductReference)
def inherit_tags_on_linked_instance(sender, instance, created, **kwargs):
    tag_inheritance.inherit_linked_instance_tags(instance)
