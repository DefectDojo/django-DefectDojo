import contextlib

from auditlog.models import LogEntry
from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.db.models.signals import post_delete
from django.dispatch import receiver
from django.urls import reverse
from django.utils.translation import gettext as _

from dojo.models import Finding_Group
from dojo.notifications.helper import create_notification


@receiver(post_delete, sender=Finding_Group)
def finding_group_post_delete(sender, instance, using, origin, **kwargs):
    if instance == origin:
        description = _('The finding group "%(name)s" was deleted') % {"name": instance.name}
        user = None

        if settings.ENABLE_AUDITLOG:
            # First try to find deletion author in pghistory events
            from dojo.pghistory_models import DojoEvents
            # Look for delete events for this specific finding_group instance
            pghistory_delete_events = DojoEvents.objects.filter(
                pgh_obj_model="dojo.Finding_Group",
                pgh_obj_id=instance.id,
                pgh_label="delete",
            ).order_by("-pgh_created_at")

            if pghistory_delete_events.exists():
                latest_delete = pghistory_delete_events.first()
                # Extract user from pghistory context
                if latest_delete.user:
                    from django.contrib.auth import get_user_model
                    User = get_user_model()
                    with contextlib.suppress(User.DoesNotExist):
                        user = User.objects.get(id=latest_delete.user)

            # Fall back to django-auditlog if no user found in pghistory
            if not user:
                if le := LogEntry.objects.filter(
                    action=LogEntry.Action.DELETE,
                    content_type=ContentType.objects.get(app_label="dojo", model="finding_group"),
                    object_id=instance.id,
                ).order_by("-id").first():
                    user = le.actor

            # Update description with user if found
            if user:
                description = _('The finding group "%(name)s" was deleted by %(user)s') % {
                                "name": instance.name, "user": user}
        create_notification(event="finding_group_deleted",  # template does not exists, it will default to "other" but this event name needs to stay because of unit testing
                            title=_("Deletion of %(name)s") % {"name": instance.name},
                            description=description,
                            product=instance.test.engagement.product,
                            url=reverse("view_test", args=(instance.test.id, )),
                            icon="exclamation-triangle")
