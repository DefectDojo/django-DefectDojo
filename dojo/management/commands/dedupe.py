from django.core.management.base import BaseCommand
from pytz import timezone

from dojo.models import Finding
from dojo.utils import get_system_setting
from dojo.utils import sync_dedupe

locale = timezone(get_system_setting('time_zone'))

"""
Author: Aaron Weaver
This script will update the hashcode and dedupe findings in DefectDojo:
"""


class Command(BaseCommand):
    help = 'No input commands for dedupe findings.'

    def handle(self, *args, **options):

        findings = Finding.objects.all()
        print("######## Updating Hashcodes (deduplication is done in background using django signals upon finding save ########")
        for finding in findings:
            finding.hash_code = finding.compute_hash_code()
            finding.save()
