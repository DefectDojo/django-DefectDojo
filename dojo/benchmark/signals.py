import logging

from django.db.models.signals import pre_delete
from django.dispatch import receiver

from dojo.models import Benchmark_Product
from dojo.notes.helper import delete_related_notes

logger = logging.getLogger(__name__)


@receiver(pre_delete, sender=Benchmark_Product)
def benchmark_product_pre_delete(sender, instance, **kwargs):
    delete_related_notes(instance)
