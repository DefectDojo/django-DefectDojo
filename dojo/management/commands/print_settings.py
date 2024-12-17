import logging
import os
from pprint import pformat

from django.conf import settings
from django.core.management.base import BaseCommand

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Display all the currently loaded settings in the project"

    def handle(self, *args, **options):

        os.environ["DJANGO_SETTINGS_MODULE"] = "my_django_project.settings"

        a_dict = {}

        for attr in dir(settings):
            value = getattr(settings, attr)
            a_dict[attr] = value

        logger.info(pformat(a_dict))
