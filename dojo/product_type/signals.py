import contextlib

from crum import get_current_user
from django.conf import settings
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver
from django.urls import reverse
from django.utils.translation import gettext as _

from dojo.auditlog.helpers import get_delete_event_user
from dojo.celery_dispatch import dojo_dispatch_task
from dojo.labels import get_labels
from dojo.models import Product_Type
from dojo.notifications.helper import async_create_notification, create_notification

labels = get_labels()


@receiver(post_save, sender=Product_Type)
def product_type_post_save(sender, instance, created, **kwargs):
    # raw=True is set by loaddata; skip dispatch so fixture loading doesn't require a live broker.
    if kwargs.get("raw"):
        return
    if created:
        dojo_dispatch_task(
            async_create_notification,
            event="product_type_added",
            title=instance.name,
            product_type_id=instance.id,
            url=reverse("view_product_type", args=(instance.id,)),
            url_api=reverse("product_type-detail", args=(instance.id,)),
        )


@receiver(post_delete, sender=Product_Type)
def product_type_post_delete(sender, instance, **kwargs):
    # Catch instances in async delete where a single object is deleted more than once
    with contextlib.suppress(sender.DoesNotExist):
        description = labels.ORG_DELETE_WITH_NAME_SUCCESS_MESSAGE % {"name": instance.name}

        if settings.ENABLE_AUDITLOG:
            # Find deletion author in pghistory events
            user = get_delete_event_user(instance)

            # Fallback to the current user of the request (Which might be not available for ASYNC_OBJECT_DELETE scenario's)
            if not user:
                current_user = get_current_user()
                user = current_user

            # Update description with user if found
            if user:
                description = labels.ORG_DELETE_WITH_NAME_WITH_USER_SUCCESS_MESSAGE % {"name": instance.name, "user": user}

        create_notification(event="product_type_deleted",  # template does not exists, it will default to "other" but this event name needs to stay because of unit testing
                            title=_("Deletion of %(name)s") % {"name": instance.name},
                            description=description,
                            no_users=True,
                            url=reverse("product_type"),
                            icon="exclamation-triangle")
