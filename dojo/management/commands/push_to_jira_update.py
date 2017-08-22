from django.contrib.contenttypes.models import ContentType

from django.core.management.base import BaseCommand
from pytz import timezone
from requests.auth import HTTPBasicAuth

from dojo.models import Finding, JIRA_PKey, JIRA_Issue, Product, Engagement, Alerts
import dojo.settings as settings
from datetime import datetime
from auditlog.models import LogEntry
from jira import JIRA
from jira.exceptions import JIRAError
from dojo.utils import add_comment, add_epic, add_issue, update_epic, update_issue, close_epic, get_system_setting
from django.core.urlresolvers import get_resolver, reverse

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
            print "Checking issue:" + str(finding.id)
            update_issue(finding, finding.status(), True)
            print "########\n"
