import logging

from dojo.celery import app
from dojo.models import Finding, Product, SLA_Configuration, System_Settings
from dojo.utils import get_custom_method, mass_model_updater

logger = logging.getLogger(__name__)


@app.task
def async_update_sla_expiration_dates_sla_config_sync(sla_config: SLA_Configuration, products: list[Product], *args, severities: list[str] | None = None, **kwargs):
    if method := get_custom_method("FINDING_SLA_EXPIRATION_CALCULATION_METHOD"):
        method(sla_config, products, severities=severities)
    else:
        update_sla_expiration_dates_sla_config_sync(sla_config, products, severities=severities)


def update_sla_expiration_dates_sla_config_sync(sla_config: SLA_Configuration, products: list[Product], severities: list[str] | None = None):
    logger.info("Updating finding SLA expiration dates within the %s SLA configuration", sla_config)
    # First check if SLA is enabled globally
    system_settings = System_Settings.objects.get()
    if not system_settings.enable_finding_sla:
        return
    # update each finding that is within the SLA configuration that was saved
    findings = Finding.objects.filter(test__engagement__product__sla_configuration_id=sla_config.id)
    if products:
        findings = findings.filter(test__engagement__product__in=products)
    if severities:
        findings = findings.filter(severity__in=severities)

    findings = (
        findings.prefetch_related(
            "test",
            "test__engagement",
            "test__engagement__product",
            "test__engagement__product__sla_configuration",
        )
        .order_by("id")
        .only("id", "sla_start_date", "date", "severity", "test")
    )
    # Call the internal method so that we are not checking system settings for each finding
    mass_model_updater(Finding, findings, lambda f: f.set_sla_expiration_date(), fields=["sla_expiration_date"])

    # reset the async updating flag to false for all products using this sla config
    # use update as we don't want save() and signals to be triggered
    products.update(async_updating=False)

    # reset the async updating flag to false for this sla config
    sla_config.async_updating = False
    super(SLA_Configuration, sla_config).save()
    logger.info("DONE Updating finding SLA expiration dates within the %s SLA configuration", sla_config)
