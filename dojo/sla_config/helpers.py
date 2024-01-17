import logging
from dojo.models import SLA_Configuration, Finding
from dojo.celery import app
from dojo.decorators import dojo_async_task

logger = logging.getLogger(__name__)


@dojo_async_task
@app.task
def update_sla_expiration_dates_sla_config_async(sla_config, severities, *args, **kwargs):
    update_sla_expiration_dates_sla_config_sync(sla_config, severities)


def update_sla_expiration_dates_sla_config_sync(sla_config, severities):
    logger.debug(f"Updating finding SLA expiration dates within the {sla_config} SLA configuration")
    # set the async updating flag to true
    sla_config.async_updating = True
    super(SLA_Configuration, sla_config).save()
    # update each finding that is within the SLA configuration that was saved
    for f in Finding.objects.filter(test__engagement__product__sla_configuration_id=sla_config.id, severity__in=severities):
        f.save()
    # reset the async updating flag to false
    sla_config.async_updating = False
    super(SLA_Configuration, sla_config).save()
