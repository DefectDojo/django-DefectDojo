import logging

from django.core.management.base import BaseCommand
from dojo.checks import check_configuration_deduplication

logger = logging.getLogger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")


class Command(BaseCommand):
    help = "Validate deduplication logic in settings"

    def handle(self, *args, **options):
        errors = check_configuration_deduplication(None)
        for error in errors:
            deduplicationLogger.error(f"{error} - Using default fields")
