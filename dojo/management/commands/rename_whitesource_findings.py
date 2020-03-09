from django.core.management.base import BaseCommand
from pytz import timezone
from dojo.utils import rename_whitesource_finding


locale = timezone(get_system_setting('time_zone'))

"""
Author: Aaron Weaver
This script will update the hashcode and dedupe findings in DefectDojo:
"""


class Command(BaseCommand):
    help = 'No input commands for dedupe findings.'

    def handle(self, *args, **options):
        rename_whitesource_finding()
