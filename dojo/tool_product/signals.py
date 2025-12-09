import logging

from django.db.models.signals import pre_delete
from django.dispatch import receiver

from dojo.models import Tool_Product_Settings
from dojo.notes.helper import delete_related_notes

logger = logging.getLogger(__name__)


@receiver(pre_delete, sender=Tool_Product_Settings)
def tool_product_settings_pre_delete(sender, instance, **kwargs):
    delete_related_notes(instance)
