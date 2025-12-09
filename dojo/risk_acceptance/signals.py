import logging

from django.db.models.signals import pre_delete
from django.dispatch import receiver

from dojo.models import Risk_Acceptance
from dojo.notes.helper import delete_related_notes

logger = logging.getLogger(__name__)


@receiver(pre_delete, sender=Risk_Acceptance)
def risk_acceptance_pre_delete(sender, instance, **kwargs):
    delete_related_notes(instance)
