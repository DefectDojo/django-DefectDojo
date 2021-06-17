from django.db import migrations
import logging

logger = logging.getLogger(__name__)


def sq_clean(apps, schema_editor):
    Sonarqube_Product_model = apps.get_model('dojo', 'Sonarqube_Product')
    for sq in Sonarqube_Product_model.objects.filter(
            sonarqube_project_key__isnull=True,
            sonarqube_tool_config__isnull=True
    ):
        logger.info('Removing empty SonarQube configuration for product {}'.format(sq.product.pk))
        sq.delete()


class Migration(migrations.Migration):
    dependencies = [
        ('dojo', '0107_global_role'),
    ]

    operations = [
        migrations.RunPython(sq_clean)
    ]
