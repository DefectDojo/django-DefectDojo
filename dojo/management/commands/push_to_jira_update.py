import logging

from django.core.management.base import BaseCommand
from pytz import timezone

import dojo.jira_link.helper as jira_helper
from dojo.models import Finding
from dojo.utils import get_system_setting

logger = logging.getLogger(__name__)

locale = timezone(get_system_setting("time_zone"))

"""
Author: Aaron Weaver
This script will locate open, active findings and update them in Jira. Useful if you need to make bulk changes with Jira:
"""


class Command(BaseCommand):
    help = "No input commands for Jira bulk update."

    def handle(self, *args, **options):

        findings = Finding.objects.exclude(jira_issue__isnull=True)
        if get_system_setting("enforce_verified_status", True):
            findings = findings.filter(verified=True, active=True)
        else:
            findings = findings.filter(active=True)

        for finding in findings:
            logger.info("Checking issue:" + str(finding.id))
            jira_helper.update_jira_issue(finding)
            logger.info("########\n")
