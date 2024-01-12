from django.db.models import signals
from django.dispatch import receiver
from dojo.models import SLA_Configuration
import dojo.sla_config.helpers as async_sla_config_funcs


@receiver(signals.post_save, sender=SLA_Configuration)
def update_sla_expiration_dates(sender, instance, **kwargs):
    sla_config = sender.objects.get(id=instance.id)
    async_sla_config_funcs.update_sla_expiration_dates_sla_config_async(sla_config)
