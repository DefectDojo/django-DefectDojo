from django.core.management.base import BaseCommand
from django.conf import settings
import logging


logger = logging.getLogger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")


class Command(BaseCommand):
    help = 'Validate deduplication logic in settings'

    def handle(self, *args, **options):
        for each_var in settings.HASHCODE_FIELDS_PER_SCANNER:
            for each_ind in each_var:
                if each_ind not in settings.HASHCODE_ALLOWED_FIELDS:
                    deduplicationLogger.error("compute_hash_code - configuration error: some elements of HASHCODE_FIELDS_PER_SCANNER are not in the allowed list HASHCODE_ALLOWED_FIELDS. " "Using default fields")
