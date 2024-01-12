import logging
from dojo.models import Finding
from dojo.celery import app
from dojo.decorators import dojo_async_task

logger = logging.getLogger(__name__)


@dojo_async_task
@app.task
def update_sla_expiration_dates_sla_config_async(sla_config, *args, **kwargs):
    update_sla_expiration_dates_sla_config_sync(sla_config)


def update_sla_expiration_dates_sla_config_sync(sla_config):
    logger.debug(f"Updating finding SLA expiration dates within the {sla_config} SLA configuration")
    # update each finding that is within the SLA configuration that was saved
    for f in Finding.objects.filter(test__engagement__product__sla_configuration_id=sla_config.id):
        f.set_sla_expiration_date()
        f.save()
