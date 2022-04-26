from django.core.management.base import BaseCommand
from django.apps import apps
from dojo.endpoint.utils import remove_broken_endpoint_statuses

import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):

    help = 'Usage: manage.py remove_broken_endpoint_statuses.py'

    def handle(self, *args, **options):
        remove_broken_endpoint_statuses(apps=apps)
