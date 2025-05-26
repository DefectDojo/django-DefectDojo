import logging

from django.contrib.contenttypes.models import ContentType
from django.core.management.base import BaseCommand

logger = logging.getLogger(__name__)


class Command(BaseCommand):

    """This management command creates non-standard Django permissions"""

    help = "Usage: manage.py initialize_permissions"

    def handle(self, *args, **options):
        try:
            # nothing left here after google sheets removal
            logger.info("Non-standard permissions have been created")
        except ContentType.DoesNotExist:
            logger.warning("No content type found for dojo.system_settings")
        except ContentType.MultipleObjectsReturned:
            logger.warning("Multiple content types found for dojo.system_settings")
