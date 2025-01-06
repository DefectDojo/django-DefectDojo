import json
import logging

import requests
from django.conf import settings
from django.core.management.base import BaseCommand

from dojo.models import Language_Type

logger = logging.getLogger(__name__)


class Command(BaseCommand):

    """
    GitHub maintains a wide range of languages with colors. The project https://github.com/ozh/github-colors
    converts them regularly in a json file, which we can use to update Language_Types
    """

    help = "Usage: manage.py migraimport_github_languages"

    def handle(self, *args, **options):
        logger.info("Started importing languages from GitHub ...")

        try:
            deserialized = json.loads(
                requests.get(
                    "https://raw.githubusercontent.com/ozh/github-colors/master/colors.json",
                    timeout=settings.REQUESTS_TIMEOUT,
                ).text,
            )
        except:
            msg = "Invalid format"
            raise Exception(msg)

        new_language_types = 0

        for name in deserialized:
            element = deserialized[name]
            color = element.get("color", None)

            if color is not None:
                try:
                    language_type, created = Language_Type.objects.get_or_create(language=name)
                except Language_Type.MultipleObjectsReturned:
                    logger.warning(f"Language_Type {name} exists multiple times")
                    continue

                if created:
                    new_language_types += 1

                language_type.color = element.get("color", 0)
                language_type.save()

        logger.info(f"Finished importing languages from GitHub, added {new_language_types} Language_Types")
