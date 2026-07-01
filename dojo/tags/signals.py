import contextlib
import logging

from django.db.models import signals
from django.dispatch import receiver
from tagulous.models.fields import SingleTagField, TagField

from dojo.celery_dispatch import dojo_dispatch_task
from dojo.location.models import Location, LocationFindingReference, LocationProductReference
from dojo.models import Endpoint, Engagement, Finding, Product, Test
from dojo.tags import inheritance as tag_inheritance
from dojo.tags.inheritance import (
    _sync_inherited_tags,
    get_products_to_inherit_tags_from,
    is_suppressed,
)

logger = logging.getLogger(__name__)


def _flush_pending_tag_fields(instance):
    """
    Persist any tags assigned to ``instance`` *before* it was first saved.

    Tagulous holds tags set on an unsaved instance (``finding.tags = [...]``
    followed by ``finding.save()``) in an in-memory manager and only writes
    them to the through table from its own ``post_save`` handler. That handler
    is registered by ``tagulous``' AppConfig.ready(), which runs *after*
    ``dojo``'s (``dojo`` precedes ``tagulous`` in ``INSTALLED_APPS``), so the
    inheritance ``post_save`` handler below fires first. When it reads
    ``instance.tags`` on the freshly-saved row it loads an empty, DB-backed
    manager and the pending pre-save tags are lost — the user's tags silently
    disappear on finding creation when product tag inheritance is enabled
    (#15092).

    Flushing here makes the inheritance path independent of signal-handler
    ordering: the instance's own tags are committed first, then inheritance
    merges the product tags on top.
    """
    for field in instance._meta.get_fields():
        if isinstance(field, SingleTagField | TagField):
            descriptor = getattr(type(instance), field.name)
            descriptor.get_manager(instance).post_save_handler()


def auto_inherit_product_tags(instance):
    """
    Apply product-inherited tags to ``instance`` from the auto-inheritance
    signal path.

    Skipped while a ``suppress_tag_inheritance()`` context is active so bulk
    callers (e.g. the importer hot loop) can defer per-instance work and run
    inheritance once at batch time. The underlying ``_sync_inherited_tags``
    diffs the current vs target inherited set and only writes the delta.
    """
    if is_suppressed():
        return
    products = get_products_to_inherit_tags_from(instance)
    if not products:
        return
    # Commit the instance's own (possibly pre-save assigned) tags before we
    # read/merge them, so inheritance never clobbers them — see #15092.
    _flush_pending_tag_fields(instance)
    incoming_inherited_tags = [tag.name for product in products for tag in product.tags.all()]
    _sync_inherited_tags(instance, incoming_inherited_tags)


@receiver(signals.m2m_changed, sender=Product.tags.through)
def product_tags_post_add_remove(sender, instance, action, **kwargs):
    if action in {"post_add", "post_remove"}:
        # `running_async_process` is an in-memory dedup flag on the Product
        # instance. `tags.set([...])` fires m2m_changed twice on the SAME
        # instance — once `post_remove` for dropped tags, once `post_add` for
        # added tags — and we only want one `propagate_tags_on_product` task
        # per Python-level operation. Not persisted: scope is exactly the
        # lifetime of this in-memory instance. Two separate `Product.objects
        # .get(id=X).tags.add(...)` calls still dispatch twice; the
        # downstream task is idempotent (diff-based sync, no-op when nothing
        # changed) so duplicates waste a slot but don't corrupt state.
        running_async_process = False
        with contextlib.suppress(AttributeError):
            running_async_process = instance.running_async_process
        if not running_async_process and tag_inheritance.is_tag_inheritance_enabled(instance):
            dojo_dispatch_task(tag_inheritance.propagate_tags_on_product, instance.id, countdown=5)
            instance.running_async_process = True


@receiver(signals.m2m_changed, sender=Endpoint.tags.through)
@receiver(signals.m2m_changed, sender=Engagement.tags.through)
@receiver(signals.m2m_changed, sender=Test.tags.through)
@receiver(signals.m2m_changed, sender=Finding.tags.through)
@receiver(signals.m2m_changed, sender=Location.tags.through)
def make_inherited_tags_sticky(sender, instance, action, **kwargs):
    """Make sure inherited tags are added back in if they are removed."""
    if action in {"post_add", "post_remove"}:
        auto_inherit_product_tags(instance)


@receiver(signals.post_save, sender=Endpoint)
@receiver(signals.post_save, sender=Engagement)
@receiver(signals.post_save, sender=Test)
@receiver(signals.post_save, sender=Finding)
@receiver(signals.post_save, sender=Location)
@receiver(signals.post_save, sender=LocationFindingReference)
@receiver(signals.post_save, sender=LocationProductReference)
def inherit_tags_on_instance(sender, instance, created, **kwargs):
    # Only inherit on creation. Previously fired on every save (create OR
    # update), repeatedly re-applying inherited tags to children whose tag
    # state had not changed. Sticky enforcement on user-driven tag edits is
    # handled by `make_inherited_tags_sticky` (m2m_changed).
    # `auto_inherit_product_tags` itself early-returns when suppressed.
    #
    # For LocationFindingReference / LocationProductReference, the new link
    # means the referenced Location may have a different set of related
    # Products, so re-sync the Location's inherited tags. Ref status updates
    # via `set_status` don't change the related-product set and are skipped.
    if not created:
        return
    target = instance.location if isinstance(instance, LocationFindingReference | LocationProductReference) else instance
    auto_inherit_product_tags(target)
