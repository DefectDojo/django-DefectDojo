from django.core.management.base import BaseCommand
from pytz import timezone

from dojo.models import Finding
from dojo.utils import update_issue, get_system_setting

locale = timezone(get_system_setting('time_zone'))

"""
Author: Aaron Weaver
This script will locate open, active findings and update them in Jira. Useful if you need to make bulk changes with Jira:
"""


class Command(BaseCommand):
    help = 'No input commands for Jira bulk update.'

    def handle(self, *args, **options):

        findings = Finding.objects.exclude(jira_issue__isnull=True)
        findings = findings.filter(verified=True, active=True)

        for finding in findings:
            print(("Checking issue:" + str(finding.id)))
            update_issue(finding, finding.status(), True)
            print("########\n")
