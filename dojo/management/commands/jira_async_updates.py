from django.contrib.contenttypes.models import ContentType

from django.core.management.base import BaseCommand
from django.utils import timezone
from requests.auth import HTTPBasicAuth

from dojo.models import Finding, JIRA_PKey, JIRA_Issue, Product, Engagement, Alerts, Notes, User, Dojo_User
import dojo.settings as settings
from datetime import datetime
from auditlog.models import LogEntry
from jira import JIRA
from jira.exceptions import JIRAError
from dojo.utils import add_comment, add_epic, add_issue, update_epic, update_issue, close_epic, jira_get_resolution_id, \
 jira_change_resolution_id, log_jira_message, get_jira_connection, get_system_setting
from django.core.urlresolvers import get_resolver, reverse

"""
Author: Aaron Weaver
This script will locate open, active findings and update them in Jira. Useful if you need to make bulk changes with Jira:
"""


class Command(BaseCommand):
    help = 'No input commands for Jira bulk update.'

    def handle(self, *args, **options):

        findings = Finding.objects.exclude(jira_issue__isnull=True)
        findings = findings.filter(verified=True, active=True)
        #finding = Finding.objects.get(id=1)
        for finding in findings:
        #    try:
            JIRAError.log_to_tempfile=False
            jira = get_jira_connection(finding)
            j_issue = JIRA_Issue.objects.get(finding=finding)
            issue = jira.issue(j_issue.jira_id)

            #Issue Cloned
            print issue.fields.issuelinks[0]

            print "Jira Issue: " + str(issue)
            print "Resolution: " + str(issue.fields.resolution)

            if issue.fields.resolution is not None and finding.under_defect_review == False:
                #print issue.fields.__dict__
                print "Jira Issue: " + str(issue) + " changed status"

                #Create Jira Note
                now = timezone.now()
                new_note = Notes()
                new_note.entry = "Please Review Jira Request: " + str(issue) + ". Review status has changed to " + str(issue.fields.resolution) + "."
                new_note.author = User.objects.get(username='JIRA')
                new_note.date = now
                new_note.save()
                finding.notes.add(new_note)
                finding.under_defect_review = True
                dojo_user = Dojo_User.objects.get(username='JIRA')
                finding.defect_review_requested_by = dojo_user

                #Create alert to notify user
                log_jira_message("Jira issue status change, please review.", finding)
                finding.save()
            else:
                print "No update necessary"
