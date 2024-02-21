from django.db import migrations
from django.utils import timezone
from datetime import datetime
from django.conf import settings
from dateutil.relativedelta import relativedelta
import logging

from dojo.utils import get_work_days

logger = logging.getLogger(__name__)


def calculate_sla_expiration_dates(apps, schema_editor):
    System_Settings = apps.get_model('dojo', 'System_Settings')

    ss, _ = System_Settings.objects.get_or_create()
    if not ss.enable_finding_sla:
        return

    logger.info('Calculating SLA expiration dates for all findings')

    SLA_Configuration = apps.get_model('dojo', 'SLA_Configuration')
    Finding = apps.get_model('dojo', 'Finding')

    findings = Finding.objects.filter(sla_expiration_date__isnull=True).order_by('id').only('id', 'sla_start_date', 'date', 'severity', 'test', 'mitigated')

    page_size = 1000
    total_count = Finding.objects.filter(id__gt=0).count()
    logger.info('Found %d findings to be updated', total_count)

    i = 0
    batch = []
    last_id = 0
    total_pages = (total_count // page_size) + 2
    for p in range(1, total_pages):
        page = findings.filter(id__gt=last_id)[:page_size]
        for find in page:
            i += 1
            last_id = find.id

            start_date = find.sla_start_date if find.sla_start_date else find.date

            sla_config = SLA_Configuration.objects.filter(id=find.test.engagement.product.sla_configuration_id).first()
            sla_period = getattr(sla_config, find.severity.lower(), None)

            days = None
            if settings.SLA_BUSINESS_DAYS:
                if find.mitigated:
                    days = get_work_days(find.date, find.mitigated.date())
                else:
                    days = get_work_days(find.date, timezone.now().date())
            else:
                if isinstance(start_date, datetime):
                    start_date = start_date.date()

                if find.mitigated:
                    days = (find.mitigated.date() - start_date).days
                else:
                    days = (timezone.now().date() - start_date).days

            days = days if days > 0 else 0

            days_remaining = None
            if sla_period:
                days_remaining = sla_period - days

            if days_remaining:
                if find.mitigated:
                    find.sla_expiration_date = find.mitigated.date() + relativedelta(days=days_remaining)
                else:
                    find.sla_expiration_date = timezone.now().date() + relativedelta(days=days_remaining)

            batch.append(find)

            if (i > 0 and i % page_size == 0):
                Finding.objects.bulk_update(batch, ['sla_expiration_date'])
                batch = []
                logger.info('%s out of %s findings processed...', i, total_count)

    Finding.objects.bulk_update(batch, ['sla_expiration_date'])
    batch = []
    logger.info('%s out of %s findings processed...', i, total_count)


def reset_sla_expiration_dates(apps, schema_editor):
    System_Settings = apps.get_model('dojo', 'System_Settings')

    ss, _ = System_Settings.objects.get_or_create()
    if not ss.enable_finding_sla:
        return

    logger.info('Resetting SLA expiration dates for all findings')

    Finding = apps.get_model('dojo', 'Finding')

    findings = Finding.objects.filter(sla_expiration_date__isnull=False).order_by('id').only('id')

    page_size = 1000
    total_count = Finding.objects.filter(id__gt=0).count()
    logger.info('Found %d findings to be reset', total_count)

    i = 0
    batch = []
    last_id = 0
    total_pages = (total_count // page_size) + 2
    for p in range(1, total_pages):
        page = findings.filter(id__gt=last_id)[:page_size]
        for find in page:
            i += 1
            last_id = find.id

            find.sla_expiration_date = None
            batch.append(find)

            if (i > 0 and i % page_size == 0):
                Finding.objects.bulk_update(batch, ['sla_expiration_date'])
                batch = []
                logger.info('%s out of %s findings processed...', i, total_count)

    Finding.objects.bulk_update(batch, ['sla_expiration_date'])
    batch = []
    logger.info('%s out of %s findings processed...', i, total_count)


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0200_finding_sla_expiration_date_product_async_updating_and_more'),
    ]

    operations = [
        migrations.RunPython(calculate_sla_expiration_dates, reset_sla_expiration_dates),
    ]
