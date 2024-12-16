from auditlog.models import LogEntry
from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver
from django.urls import reverse
from django.utils.translation import gettext as _

from dojo.models import Product
from dojo.notifications.helper import create_notification


@receiver(post_save, sender=Product)
def product_post_save(sender, instance, created, **kwargs):
    if created:
        create_notification(event="product_added",
                            title=instance.name,
                            product=instance,
                            url=reverse("view_product", args=(instance.id,)),
                            url_api=reverse("product-detail", args=(instance.id,)),
                        )


@receiver(post_delete, sender=Product)
def product_post_delete(sender, instance, **kwargs):
    if settings.ENABLE_AUDITLOG:
        le = LogEntry.objects.get(
            action=LogEntry.Action.DELETE,
            content_type=ContentType.objects.get(app_label="dojo", model="product"),
            object_id=instance.id,
        )
        description = _('The product "%(name)s" was deleted by %(user)s') % {
                            "name": instance.name, "user": le.actor}
    else:
        description = _('The product "%(name)s" was deleted') % {"name": instance.name}
    create_notification(event="product_deleted",  # template does not exists, it will default to "other" but this event name needs to stay because of unit testing
                        title=_("Deletion of %(name)s") % {"name": instance.name},
                        description=description,
                        url=reverse("product"),
                        icon="exclamation-triangle")
