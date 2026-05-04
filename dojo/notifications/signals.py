import logging

from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

from dojo.models import Dojo_User
from dojo.notifications.models import Notifications

logger = logging.getLogger(__name__)


@receiver(post_save, sender=User)
@receiver(post_save, sender=Dojo_User)
def create_default_notifications(sender, instance, created, **kwargs):
    """
    Create a default Notifications row for newly-created users.

    Cloned from the template row when present so admins can pre-configure
    a system-wide default. Runs for users created via any auth backend
    (LDAP, OAuth, SAML, etc.) which is why it lives as a signal.
    """
    if not created:
        return
    try:
        notifications = Notifications.objects.get(template=True)
        notifications.pk = None
        notifications.template = False
        notifications.user = instance
        logger.info("creating default set (from template) of notifications for: " + str(instance))
    except Notifications.DoesNotExist:
        notifications = Notifications(user=instance)
        logger.info("creating default set of notifications for: " + str(instance))
    notifications.save()
