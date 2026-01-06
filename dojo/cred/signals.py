import logging

from django.db.models.signals import pre_delete
from django.dispatch import receiver

from dojo.models import Cred_User
from dojo.notes.helper import delete_related_notes

logger = logging.getLogger(__name__)


@receiver(pre_delete, sender=Cred_User)
def cred_user_pre_delete(sender, instance, **kwargs):
    delete_related_notes(instance)
