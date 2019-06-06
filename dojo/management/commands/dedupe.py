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
        print("######## Updating Hashcodes ########")
        for finding in findings:
            finding.hash_code = finding.compute_hash_code()
            finding.save()
        findings = findings.filter(verified=True, active=True, duplicate_finding__id=None).order_by('created')
        print("######## Deduping ########")
        for finding in findings:
            sync_dedupe(finding)
