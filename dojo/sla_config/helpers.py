import logging

from dojo.celery import app
from dojo.decorators import dojo_async_task
from dojo.models import Finding, Product, SLA_Configuration

logger = logging.getLogger(__name__)


@dojo_async_task
@app.task
def update_sla_expiration_dates_sla_config_async(sla_config, severities, products, *args, **kwargs):
    update_sla_expiration_dates_sla_config_sync(sla_config, severities, products)


def update_sla_expiration_dates_sla_config_sync(sla_config, severities, products):
    logger.info(f"Updating finding SLA expiration dates within the {sla_config} SLA configuration")
    # update each finding that is within the SLA configuration that was saved
    for f in Finding.objects.filter(test__engagement__product__sla_configuration_id=sla_config.id, severity__in=severities):
        f.save()
    # reset the async updating flag to false for all products using this sla config
    for product in products:
        product.async_updating = False
        super(Product, product).save()
    # reset the async updating flag to false for this sla config
    sla_config.async_updating = False
    super(SLA_Configuration, sla_config).save()
