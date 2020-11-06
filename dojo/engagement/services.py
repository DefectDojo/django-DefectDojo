# #  engagements
import logging

from django.utils import timezone
from dojo.models import JIRA_Project
from dojo.utils import get_system_setting, close_epic
import dojo.jira_link.jira_helper as jira_helper

logger = logging.getLogger(__name__)


def close_engagement(eng):
    eng.active = False
    eng.status = 'Completed'
    eng.updated = timezone.now()
    eng.save()

    if jira_helper.get_jira_project(eng):
        close_epic(eng, True)


def reopen_engagement(eng):
    eng.active = True
    eng.status = 'In Progress'
    eng.save()
