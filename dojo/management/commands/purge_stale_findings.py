from django.core.management.base import BaseCommand
from pytz import timezone

from dojo.models import Finding
from tagging.models import TaggedItem
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
This script will remove findings tagged as stale because they were no longer present in scans. Only findings older then 2 weeks are removed.
"""


class Command(BaseCommand):
    help = 'This script will remove findings tagged as stale because they were no longer present in scans. Only findings older then 2 weeks are removed.'

    def handle(self, *args, **options):

        logger.info("######## Removing state findings older than 14 days ########")
        safe_period_days = 14
        safe_end_date = datetime.now() - timedelta(days=safe_period_days)
        findings = Finding.objects.filter(active=False, duplicate=False, created__lt=safe_end_date)
        tagged_findings = TaggedItem.objects.get_by_model(findings, "stale")

        logger.debug("About to remove %i stale findings", tagged_findings.count())

        count = 0
        # for finding in [findings[0]]:
        for finding in findings:
            # print(finding.id, finding.title, finding.created, finding.tags)
            collector = NestedObjects(using=DEFAULT_DB_ALIAS)
            collector.collect([finding])
            rels = collector.nested()
            # print('rels: ', rels)
            # for rel in rels:
            #     print('rel_type: ', type(rel))
            if len(rels) != 2:
                # we expect only a Test object selected for deletion, anything else is suspect.
                logger.warn('skipping removal of finding %s:%s:%s as related objects are not exactly two.', finding.id, finding.title, finding.created)
            logger.debug('removing finding %s:%s:%s.', finding.id, finding.title, finding.created)
            finding.delete()
            count += 1

        logger.info("######## Done Removing %i stale findings older than 14 days ########", count)

