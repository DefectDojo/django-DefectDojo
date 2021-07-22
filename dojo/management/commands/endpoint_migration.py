from django.core.management.base import BaseCommand
from django.apps import apps
from dojo.endpoint.utils import clean_hosts_run

import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):

    help = 'Usage: manage.py endpoint_migration.py [--dry-run]'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Just look for broken endpoints',
        )

    def handle(self, *args, **options):
        clean_hosts_run(apps=apps, change=bool(options.get('dry_run')))
