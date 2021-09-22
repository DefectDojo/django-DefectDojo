from django.core.management.base import BaseCommand
from django.conf import settings
import logging


logger = logging.getLogger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")


class Command(BaseCommand):
    help = 'Validate deduplication logic in settings'

    def handle(self, *args, **options):
        for scanner in settings.HASHCODE_FIELDS_PER_SCANNER:
            for field in settings.HASHCODE_FIELDS_PER_SCANNER.get(scanner):
                if field not in settings.HASHCODE_ALLOWED_FIELDS:
                    deduplicationLogger.error(f"Configuration error in HASHCODE_FIELDS_PER_SCANNER: Element {field} is not in the allowed list HASHCODE_ALLOWED_FIELDS for {scanner}. " "Using default fields")
