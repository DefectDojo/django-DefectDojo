# #  engagements
import logging

from django.db.models.signals import pre_save
from django.dispatch import receiver

import dojo.jira_link.helper as jira_helper
from dojo.celery_dispatch import dojo_dispatch_task
from dojo.models import Engagement

logger = logging.getLogger(__name__)


def close_engagement(eng):
    eng.active = False
    eng.status = "Completed"
    eng.save()

    if jira_helper.get_jira_project(eng):
        dojo_dispatch_task(jira_helper.close_epic, eng.id, push_to_jira=True)


def reopen_engagement(eng):
    eng.active = True
    eng.status = "In Progress"
    eng.save()


@receiver(pre_save, sender=Engagement)
def set_name_if_none(sender, instance, *args, **kwargs):
    if not instance.name:
        instance.name = str(instance.target_start)
