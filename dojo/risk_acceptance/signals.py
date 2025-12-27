import logging

from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.db.models.signals import m2m_changed, pre_delete
from django.dispatch import receiver

from dojo.models import Finding, Risk_Acceptance
from dojo.notes.helper import delete_related_notes

logger = logging.getLogger(__name__)


@receiver(pre_delete, sender=Risk_Acceptance)
def risk_acceptance_pre_delete(sender, instance, **kwargs):
    delete_related_notes(instance)


@receiver(m2m_changed, sender=Risk_Acceptance.accepted_findings.through)  # TODO: test
def validate_findings_product(sender, instance, action, reverse, model, pk_set, using, **kwargs):
    if action == "pre_add":
        # Using loaddata or fixtures, not all objects are already fully created. In that case we should not check all relationships
        try:
            if not instance.pk:
                logger.debug("RA without pk")
                return
            if not instance.product.pk:
                logger.debug("Product without pk")
                return
            for pk in pk_set:
                if not Finding.objects.get(pk=pk).test.engagement.product.pk:
                    logger.debug("Finding's Product without pk")
                    return
        except ObjectDoesNotExist:
            logger.debug("Some object in chain does not exist yet")
            return

        if pk_set:  # Do not validate for empty set
            findings_product_ids = set(Finding.objects.filter(pk__in=pk_set).values_list("test__engagement__product_id", flat=True))
            if len(findings_product_ids) > 1 or (instance.product_id not in findings_product_ids):
                msg = f"All findings must belong to the same product as the risk_acc. Findings '{pk_set}' are part of '{findings_product_ids}' products, not product '{instance.product_id}' (as expected)."
                logger.error(msg)
                raise ValidationError(msg)
