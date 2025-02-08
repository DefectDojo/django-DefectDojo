from django.db import migrations
import logging

logger = logging.getLogger(__name__)


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0152_notifications_template'),
    ]

    def migrate_endpoint_mitigated(apps, schema_editor):
        Endpoint = apps.get_model('dojo', 'Endpoint')
        Endpoint_Status = apps.get_model('dojo', 'Endpoint_Status')

        all_ep = Endpoint.objects.filter(mitigated=True)

        if all_ep.count() == 0:
            logger.info('There is nothing to process')
        else:
            logger.warning('We identified %s endpoints marked as Mitigated and their status will be updated',
                           all_ep.count())

            for ep in all_ep:
                epss = Endpoint_Status.objects.select_related('finding').filter(endpoint=ep, mitigated=False)
                for eps in epss:
                    eps.date = eps.finding.date
                    eps.mitigated = True
                    eps.mitigated_by = eps.finding.reporter
                    eps.save()
                    logger.debug('Status for finding "%s" on endpoint "%s" marked as mitigated at "%s" by "%s"',
                                 str(eps.finding),
                                 str(ep),
                                 eps.date,
                                 eps.mitigated_by
                                 )

    operations = [
        migrations.RunPython(migrate_endpoint_mitigated)
    ]
