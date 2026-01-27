import contextlib

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db.models.signals import post_delete
from django.dispatch import receiver
from django.urls import reverse
from django.utils.translation import gettext as _

from dojo.notifications.helper import create_notification
from dojo.pghistory_models import DojoEvents
from dojo.url.models import URL


@receiver(post_delete, sender=URL)
def url_post_delete(sender, instance, using, origin, **kwargs):
    # Catch instances in async delete where a single object is deleted more than once
    with contextlib.suppress(sender.DoesNotExist):
        if instance == origin:
            description = _('The URL "%(name)s" was deleted') % {"name": str(instance)}
            user = None

            if settings.ENABLE_AUDITLOG:
                pghistory_delete_events = DojoEvents.objects.filter(
                    pgh_obj_model="dojo.URL",
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

                if user:
                    description = _('The URL "%(name)s" was deleted by %(user)s') % {
                        "name": str(instance), "user": user}
            create_notification(event="url_deleted",  # template does not exist, it will default to "other" but this event name needs to stay because of unit testing
                                title=_("Deletion of %(name)s") % {"name": str(instance)},
                                description=description,
                                url=reverse("endpoint"),
                                icon="exclamation-triangle")
