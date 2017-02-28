from django.contrib.contenttypes.models import ContentType

from django.core.management.base import BaseCommand
from pytz import timezone
from requests.auth import HTTPBasicAuth
import csv
from dojo.models import Finding, JIRA_PKey, JIRA_Issue, Product, Engagement, Alerts
import dojo.settings as settings
from datetime import datetime
from auditlog.models import LogEntry
from jira import JIRA
from jira.exceptions import JIRAError
from dojo.utils import add_comment, add_epic, add_issue, update_epic, update_issue, close_epic
from django.core.urlresolvers import get_resolver, reverse
from itertools import chain

locale = timezone(settings.TIME_ZONE)

"""
Author: Aaron Weaver
This script will extract all verified and active findings
"""


class Command(BaseCommand):
    help = 'Input: Filepath and name'

    def add_arguments(self, parser):
        parser.add_argument('file_path')

    def handle(self, *args, **options):
        file_path = options['file_path']

        findings = Finding.objects.filter(verified=True, active=True).select_related("test__engagement__product")
        opts = findings.model._meta
        model = findings.model

        model = findings.model
        writer = csv.writer(open(file_path, 'w'))

        headers = []
        headers.append("product_name")
        headers.append("id")
        headers.append("title")
        headers.append("cwe")
        headers.append("date")
        headers.append("url")
        headers.append("severity")
        
        #for field in opts.fields:
        #    headers.append(field.name)

        writer.writerow(headers)
        for obj in findings:
            row = []
            row.append(obj.test.engagement.product)
            for field in headers:
                if field is not "product_name":
                    value = getattr(obj, field)
                    if isinstance(value, unicode):
                        value = value.encode('utf-8').strip()

                    row.append(value)
            writer.writerow(row)
