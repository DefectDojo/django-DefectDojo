from django.db import migrations
import logging

logger = logging.getLogger(__name__)


def sq_clean(apps, schema_editor):
    Sonarqube_Product_model = apps.get_model('dojo', 'Sonarqube_Product')
    Sonarqube_Product_model.objects.filter(
        sonarqube_project_key__isnull=True,
        sonarqube_tool_config__isnull=True
    ).delete()


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ('dojo', '0124_sonarqube_api_type_length_change'),
    ]

    operations = [
        migrations.RunPython(sq_clean),
    ]
