import contextlib
from django.db.models import signals
from django.dispatch import receiver
import logging
from dojo.models import SLA_Configuration, Finding

logger = logging.getLogger(__name__)


@receiver(signals.post_save, sender=SLA_Configuration)
def update_found_by_for_findings(sender, instance, **kwargs):
    with contextlib.suppress(sender.DoesNotExist):
        obj = sender.objects.get(pk=instance.pk)

        for f in Finding.objects.filter(test__engagement__product__sla_configuration_id=obj.id):
            f.set_sla_expiration_date()
            f.save()
