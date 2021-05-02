from django.core.management.base import BaseCommand
from django.apps import apps
from dojo.db_migrations.0094_endpoint_host_migration import clean_hosts_run

import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):

    help = 'Usage: manage.py endpoint_pre-migration_check.py'

    def handle(self, *args, **options):
        clean_hosts_run(apps=apps, change=False)