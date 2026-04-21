# #  engagements
import logging

from django.db.models.signals import pre_save
from django.dispatch import receiver

from dojo.celery_dispatch import dojo_dispatch_task
from dojo.jira import services as jira_services
from dojo.models import Engagement

logger = logging.getLogger(__name__)


def close_engagement(eng):
    eng.active = False
    eng.status = "Completed"
    eng.save()

    if jira_services.get_project(eng):
        task = jira_services.get_epic_task("close_epic")
        if task:
            dojo_dispatch_task(task, eng.id, push_to_jira=True)


def reopen_engagement(eng):
    eng.active = True
    eng.status = "In Progress"
    eng.save()


@receiver(pre_save, sender=Engagement)
def set_name_if_none(sender, instance, *args, **kwargs):
    if not instance.name:
        instance.name = str(instance.target_start)
