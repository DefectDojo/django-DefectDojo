import logging
from django.core.management.base import BaseCommand
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth.models import Permission


logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """
    This management command creates non-standard Django permissions
    """
    help = 'Usage: manage.py initialize_permissions'

    def handle(self, *args, **options):
        try:
            content_type_system_settings = ContentType.objects.get(app_label='dojo', model='system_settings')
            google_permission = Permission.objects.filter(content_type=content_type_system_settings,
                codename='change_google_sheet').count()
            if google_permission == 0:
                Permission.objects.create(
                    name='Can change Google Sheet',
                    content_type=content_type_system_settings,
                    codename='change_google_sheet'
                )

            logger.info('Non-standard permissions have been created')
        except ContentType.DoesNotExist:
            logger.warning('No content type found for dojo.system_settings')
        except ContentType.MultipleObjectsReturned:
            logger.warning('Multiple content types found for dojo.system_settings')
