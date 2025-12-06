# Generated migration - Step 2: Migrate Risk_Acceptance data from Engagement to Product

from django.db import migrations

import logging

logger = logging.getLogger(__name__)

def migrate_risk_acceptance_to_product(apps, schema_editor):
    """
    Migrate existing risk acceptances from engagement level to product level.
    For each risk acceptance, find its engagement and set the product field.
    """
    Risk_Acceptance = apps.get_model('dojo', 'Risk_Acceptance')
    Engagement = apps.get_model('dojo', 'Engagement')

    # Get all risk acceptances that don't have a product set
    risk_acceptances_updated = 0
    risk_acceptances_orphaned = 0

    for risk_acceptance in Risk_Acceptance.objects.filter(product__isnull=True):
        # Find the engagement that has this risk acceptance
        engagement = Engagement.objects.filter(risk_acceptance=risk_acceptance).first()
        if engagement:
            # Set the product from the engagement
            risk_acceptance.product = engagement.product
            risk_acceptance.save()
            risk_acceptances_updated += 1
        else:
            # This shouldn't happen in normal cases, but if a risk acceptance has no engagement,
            # we need to handle it. We should delete.
            risk_acceptance.delete()
            risk_acceptances_orphaned += 1
            logger.warning(f"Risk Acceptance {risk_acceptance.id} '{risk_acceptance.name}' has no associated engagement so it can be removed.")

    logger.debug(f"Migration complete: {risk_acceptances_updated} risk acceptances migrated to product level")
    if risk_acceptances_orphaned > 0:
        logger.warning(f"{risk_acceptances_orphaned} orphaned risk acceptances found (no associated engagement)")


def reverse_migrate_risk_acceptance_to_engagement(apps, schema_editor):
    """
    Reverse migration: restore engagement associations based on the product field.
    For each risk acceptance with a product, find an engagement in that product
    and associate the risk acceptance with it.
    """
    Risk_Acceptance = apps.get_model('dojo', 'Risk_Acceptance')
    Engagement = apps.get_model('dojo', 'Engagement')

    risk_acceptances_restored = 0

    # For each risk acceptance with a product, find an engagement in that product
    # and associate the risk acceptance with it
    for risk_acceptance in Risk_Acceptance.objects.filter(product__isnull=False):
        # Find the first engagement in this product
        engagement = Engagement.objects.filter(product=risk_acceptance.product).first()
        if engagement:
            # Add the risk acceptance to the engagement
            engagement.risk_acceptance.add(risk_acceptance)
            risk_acceptances_restored += 1
        else:
            logger.warning(f"Could not find engagement for Risk Acceptance {risk_acceptance.id} in product {risk_acceptance.product.name}")

    logger.debug(f"Reverse migration complete: {risk_acceptances_restored} risk acceptances restored to engagement level")


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0249_risk_acceptance_add_product_field'),
    ]

    operations = [
        # Populate the product field from engagement relationships
        migrations.RunPython(
            migrate_risk_acceptance_to_product,
            reverse_migrate_risk_acceptance_to_engagement
        ),
    ]
