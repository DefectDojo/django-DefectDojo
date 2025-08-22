import contextlib

from auditlog.models import LogEntry
from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.db.models.signals import post_delete
from django.dispatch import receiver
from django.urls import reverse
from django.utils.translation import gettext as _

from dojo.models import Endpoint
from dojo.notifications.helper import create_notification


@receiver(post_delete, sender=Endpoint)
def endpoint_post_delete(sender, instance, using, origin, **kwargs):
    # Catch instances in async delete where a single object is deleted more than once
    with contextlib.suppress(sender.DoesNotExist):
        if instance == origin:
            description = _('The endpoint "%(name)s" was deleted') % {"name": str(instance)}
            if settings.ENABLE_AUDITLOG:
                if le := LogEntry.objects.filter(
                    action=LogEntry.Action.DELETE,
                    content_type=ContentType.objects.get(app_label="dojo", model="endpoint"),
                    object_id=instance.id,
                ).order_by("-id").first():
                    description = _('The endpoint "%(name)s" was deleted by %(user)s') % {
                                    "name": str(instance), "user": le.actor}
            create_notification(event="endpoint_deleted",  # template does not exists, it will default to "other" but this event name needs to stay because of unit testing
                                title=_("Deletion of %(name)s") % {"name": str(instance)},
                                description=description,
                                url=reverse("endpoint"),
                                icon="exclamation-triangle")
