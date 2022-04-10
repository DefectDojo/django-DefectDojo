from django.db import migrations
from django.db.models import Q
import logging

logger = logging.getLogger(__name__)


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0156_migrate_finding_groups_setting'),
    ]

    def remove_broken_endpoint_statuses(apps, schema_editor):
        Finding = apps.get_model('dojo', 'Finding')
        Endpoint = apps.get_model('dojo', 'Endpoint')
        Endpoint_Status = apps.get_model('dojo', 'endpoint_status')
        broken_eps = Endpoint_Status.objects.filter(Q(endpoint=None) | Q(finding=None))
        if broken_eps.count() == 0:
            logger.info('There is no broken endpoint_status')
        else:
            logger.warning('We identified %s broken endpoint_statuses', broken_eps.count())
            deleted = broken_eps.delete()
            logger.warning('We removed %s broken endpoint_statuses', deleted)

        epss = Endpoint_Status.objects.all()

        eps_findings = set()
        for f in Finding.objects.all():
            eps_findings.add(f.endpoint_status)
        missing_eps_findings = [eps for eps in eps_findings if eps not in epss]

        for f in Finding.objects.filter(finding_endpoint_status__in=missing_eps_findings):
            f.endpoint_status.remove(missing_eps_findings)

        eps_endpoints = set()
        for e in Endpoint.objects.all():
            eps_endpoints.add(e.endpoint_status)
        missing_eps_endpoints = [eps for eps in eps_endpoints if eps not in epss]

        for e in Endpoint.objects.filter(endpoint_endpoint_status__in=missing_eps_endpoints):
            endpoint_status.remove(missing_eps_endpoints)

    operations = [
        migrations.RunPython(remove_broken_endpoint_statuses)
    ]
