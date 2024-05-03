from django.db import migrations
from django.db.models import Count, Q
import logging

logger = logging.getLogger(__name__)


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0149_harmonize_user_format'),
    ]

    def dedupe_endpoint_status(apps, schema_editor):
        Endpoint_Status = apps.get_model('dojo', 'endpoint_status')
        Endpoint = apps.get_model('dojo', 'endpoint')
        Finding = apps.get_model('dojo', 'finding')

        to_process = Endpoint_Status.objects.exclude(Q(endpoint=None) | Q(finding=None))\
            .values('finding', 'endpoint').annotate(cnt=Count('id')).filter(cnt__gt=1)
        if to_process.count() == 0:
            logger.info('There is nothing to process')
        else:
            logger.warning('We identified %s group(s) of endpoint status which needs to be deduplicated',
                           to_process.count())

            for eps_group in to_process:

                finding = Finding.objects.get(id=eps_group.get('finding'))
                ep = Endpoint.objects.get(id=eps_group.get('endpoint'))
                epss = Endpoint_Status.objects.filter(finding=finding, endpoint=ep)

                # we need to identify, when first was created
                first_date = epss.order_by('date').first().date

                # next we need to know, which store the most recent information
                last_id = epss.order_by('last_modified').last().id

                logger.debug('Redundant endpoint statuses on finding: "%s" & endpoint "%s" will be removed. We are '
                             'keeping only id: "%s" and we are setting date of the first identification: %s',
                             str(finding), str(ep), last_id, first_date)

                # Remove all except of the most fresh one
                Endpoint_Status.objects.filter(finding=eps_group.get('finding'),
                                               endpoint=eps_group.get('endpoint')).exclude(id=last_id).delete()

                # Use the date from the oldest one
                eps = Endpoint_Status.objects.get(id=last_id)
                eps.date = first_date
                eps.save()

    operations = [
        migrations.RunPython(dedupe_endpoint_status)
    ]
