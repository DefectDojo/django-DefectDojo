from django.core.management.base import BaseCommand
from dojo.models import Endpoint_Status
from django.db.models import Q

import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):

    help = 'Usage: manage.py fix_0150 [--dry-run]'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Just look for broken endpoint_statuses',
        )

    def handle(self, *args, **options):
        broken_eps = Endpoint_Status.objects.filter(Q(endpoint=None) | Q(finding=None))
        if broken_eps.count() == 0:
            logger.info('There is no broken endpoint_status')
        else:
            logger.warning('We identified %s broken endpoint_statuses', broken_eps.count())
            if not options.get('dry_run'):
                deleted = broken_eps.delete()
                logger.warning('We removed %s broken endpoint_statuses', deleted)
