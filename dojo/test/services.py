# #  tests
import logging

from crum import get_current_request
from django.urls import reverse
from django.utils.translation import gettext as _

from dojo.celery_dispatch import dojo_dispatch_task
from dojo.notifications.helper import create_notification, process_tag_notifications
from dojo.utils import calculate_grade

logger = logging.getLogger(__name__)


def process_note_added(test, note, *, user):
    """
    Fire the same side-effects as the v2 test notes ``@action`` create branch
    (``dojo/test/api/views.py``) after a note is persisted and linked: @mention notifications only --
    the test @action has **no** JIRA comment sync and **no** ``last_reviewed`` stamping. Reuses the
    exact v2 parsing/notification helper (``process_tag_notifications``); the request is read from crum
    (see ``dojo/finding/services.py``), and mentions are skipped with no request. ``user`` is part of
    the callback contract (I6) but unused here (no side-effect needs it).
    """
    request = get_current_request()
    if request is not None:
        process_tag_notifications(
            request=request,
            note=note,
            parent_url=request.build_absolute_uri(reverse("view_test", args=(test.id,))),
            parent_title=f"Test: {test.title}",
        )


def copy_test(test, engagement, user):
    """
    Copy a test (and its findings) into the given engagement, recalculate the product
    grade, and notify. Returns the new test.

    HTTP-free so both the UI view and (eventually) the API can call it.
    """
    product = test.engagement.product
    test_copy = test.copy(engagement=engagement)
    dojo_dispatch_task(calculate_grade, product.id)
    create_notification(
        event="test_copied",
        title=_("Copying of %s") % test.title,
        description=f'The test "{test.title}" was copied by {user} to {engagement.name}',
        product=product,
        url=reverse("view_test", args=(test_copy.id,)),
        recipients=[test.engagement.lead],
        icon="exclamation-triangle",
    )
    return test_copy
