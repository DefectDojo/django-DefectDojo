from django.db import migrations
from django.db.models import Count, Q
import logging

logger = logging.getLogger(__name__)


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0156_migrate_finding_groups_setting'),
    ]

    def remove_broken_endpoint_statuses(apps, schema_editor):
        Endpoint_Status = apps.get_model('dojo', 'endpoint_status')
        broken_eps = Endpoint_Status.objects.filter(Q(endpoint=None) | Q(finding=None))
        if broken_eps.count() == 0:
            logger.info('There is no broken endpoint_status')
        else:
            logger.warning('We identified %s broken endpoint_statuses', broken_eps.count())
            deleted = broken_eps.delete()
            logger.warning('We removed %s broken endpoint_statuses', deleted)

    operations = [
        migrations.RunPython(remove_broken_endpoint_statuses)
    ]
