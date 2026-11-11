from django.conf import settings
from django.db.models.signals import post_delete
from django.dispatch import receiver
from django.urls import reverse
from django.utils.translation import gettext as _

from dojo.auditlog.helpers import get_delete_event_user
from dojo.models import Finding_Group
from dojo.notifications.helper import create_notification


@receiver(post_delete, sender=Finding_Group)
def finding_group_post_delete(sender, instance, using, origin, **kwargs):
    if instance == origin:
        description = _('The finding group "%(name)s" was deleted') % {"name": instance.name}

        if settings.ENABLE_AUDITLOG:
            # Find deletion author in pghistory events
            user = get_delete_event_user(instance)

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
