import logging

from django.core.management.base import BaseCommand
from jira.exceptions import JIRAError

import dojo.jira_link.helper as jira_helper
from dojo.models import Dojo_User, Finding, Notes, User
from dojo.utils import get_system_setting, timezone

"""
Author: Aaron Weaver
This script will locate open, active findings and update them in JIRA.
Useful if you need to make bulk changes with JIRA:
"""

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = "No input commands for JIRA bulk update."

    def handle(self, *args, **options):

        findings = Finding.objects.exclude(jira_issue__isnull=True)
        if get_system_setting("enforce_verified_status", True) or get_system_setting("enforce_verified_status_jira", True):
            findings = findings.filter(verified=True, active=True)
        else:
            findings = findings.filter(active=True)

        findings = findings.prefetch_related("jira_issue")
        # finding = Finding.objects.get(id=1)
        for finding in findings:
            #    try:
            JIRAError.log_to_tempfile = False
            jira = jira_helper.get_jira_connection(finding)
            j_issue = finding.jira_issue
            issue = jira.issue(j_issue.jira_id)

            # Issue Cloned
            logger.info(issue.fields.issuelinks[0])

            logger.info("Jira Issue: " + str(issue))
            logger.info("Resolution: " + str(issue.fields.resolution))

            if issue.fields.resolution is not None \
                    and not finding.under_defect_review:
                logger.info("Jira Issue: " + str(issue) + " changed status")

                # Create Jira Note
                now = timezone.now()
                new_note = Notes()
                new_note.entry = "Please Review Jira Request: " + str(
                    issue) + ". Review status has changed to " + str(
                    issue.fields.resolution) + "."
                new_note.author = User.objects.get(username="JIRA")
                new_note.date = now
                new_note.save()
                finding.notes.add(new_note)
                finding.under_defect_review = True
                dojo_user = Dojo_User.objects.get(username="JIRA")
                finding.defect_review_requested_by = dojo_user

                # Create alert to notify user
                jira_helper.log_jira_message("Jira issue status change, please review.",
                                 finding)
                finding.save()
            else:
                logger.info("No update necessary")
