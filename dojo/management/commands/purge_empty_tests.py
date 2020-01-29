from django.core.management.base import BaseCommand
from pytz import timezone

from dojo.models import Test
from dojo.utils import get_system_setting
import logging
from datetime import datetime, timedelta
from django.db.models import Count, Q
from django.contrib.admin.utils import NestedObjects
from django.db import DEFAULT_DB_ALIAS

locale = timezone(get_system_setting('time_zone'))

logger = logging.getLogger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")

"""
Author: Valentijn Scholten
This script will remove tests (scans) without findings. Tests younger than 2 weeks will not be removed.
"""


class Command(BaseCommand):
    help = 'This script will remove tests (scans) without findings. Tests younger than 2 weeks will not be removed.'

    def handle(self, *args, **options):

        logger.info("######## Removing tests older than 14 days and having no findings in them ########")
        safe_period_days = 14
        safe_end_date = datetime.now()-timedelta(days=safe_period_days)
        tests = Test.objects.filter(created__lt=safe_end_date).annotate(finding_count=Count("finding__id")).filter(finding_count__lte=0)

        count = 0
        for test in tests:
            print(test.id, test.title, test.test_type)
            collector = NestedObjects(using=DEFAULT_DB_ALIAS)
            collector.collect([test])
            rels = collector.nested()
            if len(rels) != 1:
                # we expect only a Test object selected for deletion, anything else is suspect.
                logger.warn('skipping removal of test %s:%s:%s as related objects is not exactly one.', test.id, test.title, test.test_type)
            logger.debug('removing test %s:%s:%s.', test.id, test.title, test.test_type)
            test.delete()
            count += 1

        logger.info("######## Done Removing %i tests older than 14 days and having no findings in them ########", count)
