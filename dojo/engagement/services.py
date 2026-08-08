# #  engagements
import logging

from django.db.models.signals import pre_save
from django.dispatch import receiver
from django.urls import reverse
from django.utils.translation import gettext as _

from dojo.celery_dispatch import dojo_dispatch_task
from dojo.jira import services as jira_services
from dojo.models import Engagement
from dojo.notifications.helper import create_notification
from dojo.utils import calculate_grade

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


def copy_engagement(engagement, user):
    """
    Copy an engagement (and its tests/findings) within the same product, recalculate the
    product grade, and notify. Returns the new engagement.

    HTTP-free so both the UI view and (eventually) the API can call it.
    """
    product = engagement.product
    engagement_copy = engagement.copy()
    dojo_dispatch_task(calculate_grade, product.id)
    create_notification(
        event="engagement_copied",
        title=_("Copying of %s") % engagement.name,
        description=f'The engagement "{engagement.name}" was copied by {user}',
        product=product,
        url=reverse("view_engagement", args=(engagement_copy.id,)),
        recipients=[engagement.lead],
        icon="exclamation-triangle",
    )
    return engagement_copy


@receiver(pre_save, sender=Engagement)
def set_name_if_none(sender, instance, *args, **kwargs):
    if not instance.name:
        instance.name = str(instance.target_start)
