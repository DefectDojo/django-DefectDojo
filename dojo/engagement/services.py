# #  engagements
import logging

from django.utils import timezone
from dojo.models import JIRA_PKey
from dojo.utils import get_system_setting
from dojo.tasks import close_epic_task

logger = logging.getLogger(__name__)


def close_engagement(eng):
    eng.active = False
    eng.status = 'Completed'
    eng.updated = timezone.now()
    eng.save()

    if get_system_setting('enable_jira'):
        jpkey_set = JIRA_PKey.objects.filter(product=eng.product)
        if jpkey_set.count() >= 1:
            close_epic_task(eng, True)


def reopen_engagement(eng):
    eng.active = True
    eng.status = 'In Progress'
    eng.save()
