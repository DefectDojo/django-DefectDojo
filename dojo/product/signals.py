import contextlib

from auditlog.models import LogEntry
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver
from django.urls import reverse
from django.utils.translation import gettext as _

from dojo.labels import get_labels
from dojo.models import Product
from dojo.notifications.helper import create_notification
from dojo.pghistory_models import DojoEvents

labels = get_labels()


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
    # Catch instances in async delete where a single object is deleted more than once
    with contextlib.suppress(sender.DoesNotExist):
        description = labels.ASSET_DELETE_WITH_NAME_SUCCESS_MESSAGE % {"name": instance.name}
        user = None

        if settings.ENABLE_AUDITLOG:
            # First try to find deletion author in pghistory events
            # Look for delete events for this specific product instance
            pghistory_delete_events = DojoEvents.objects.filter(
                pgh_obj_model="dojo.Product",
                pgh_obj_id=instance.id,
                pgh_label="delete",
            ).order_by("-pgh_created_at")

            if pghistory_delete_events.exists():
                latest_delete = pghistory_delete_events.first()
                # Extract user from pghistory context
                if latest_delete.user:
                    User = get_user_model()
                    with contextlib.suppress(User.DoesNotExist):
                        user = User.objects.get(id=latest_delete.user)

            # Fall back to django-auditlog if no user found in pghistory
            if not user:
                if le := LogEntry.objects.filter(
                    action=LogEntry.Action.DELETE,
                    content_type=ContentType.objects.get(app_label="dojo", model="product"),
                    object_id=instance.id,
                ).order_by("-id").first():
                    user = le.actor

            # Update description with user if found
            if user:
                description = labels.ASSET_DELETE_WITH_NAME_WITH_USER_SUCCESS_MESSAGE % {"name": instance.name, "user": le.actor}
        create_notification(event="product_deleted",  # template does not exists, it will default to "other" but this event name needs to stay because of unit testing
                            title=_("Deletion of %(name)s") % {"name": instance.name},
                            description=description,
                            url=reverse("product"),
                            icon="exclamation-triangle")
