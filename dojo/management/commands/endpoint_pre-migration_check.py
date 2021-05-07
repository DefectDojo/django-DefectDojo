from django.core.management.base import BaseCommand
from django.apps import apps
from dojo.endpoint.utils import clean_hosts_run
from django.core.exceptions import FieldError

import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):

    help = 'Usage: manage.py endpoint_pre-migration_check.py'

    def handle(self, *args, **options):
        try:
            clean_hosts_run(apps=apps, change=False)
        except FieldError as f:
            logger.error('Migration is not possible: {}'.format(f))
        else:
            logger.info('There is no problem with migration')
