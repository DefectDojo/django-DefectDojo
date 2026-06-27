# #  tests
import logging

from django.urls import reverse
from django.utils.translation import gettext as _

from dojo.celery_dispatch import dojo_dispatch_task
from dojo.notifications.helper import create_notification
from dojo.utils import calculate_grade

logger = logging.getLogger(__name__)


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
