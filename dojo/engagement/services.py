# #  engagements
import logging

from crum import get_current_request
from django.conf import settings
from django.db.models.signals import pre_save
from django.dispatch import receiver
from django.urls import reverse
from django.utils.translation import gettext as _

from dojo.celery_dispatch import dojo_dispatch_task
from dojo.jira import services as jira_services
from dojo.models import Engagement
from dojo.notifications.helper import create_notification, process_tag_notifications
from dojo.utils import calculate_grade

logger = logging.getLogger(__name__)


def process_note_added(engagement, note, *, user):
    """
    Fire the same side-effects as the v2 engagement notes ``@action`` create branch
    (``dojo/engagement/api/views.py``) after a note is persisted and linked: @mention notifications
    only -- the engagement @action has **no** JIRA comment sync and **no** ``last_reviewed`` stamping.
    Reuses the exact v2 parsing/notification helper (``process_tag_notifications``); the request is read
    from crum (see ``dojo/finding/services.py``), and mentions are skipped with no request. ``user`` is
    part of the callback contract (I6) but unused here (no side-effect needs it).
    """
    request = get_current_request()
    if request is not None:
        process_tag_notifications(
            request=request,
            note=note,
            parent_url=request.build_absolute_uri(reverse("view_engagement", args=(engagement.id,))),
            parent_title=f"Engagement: {engagement.name}",
        )


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


def reassign_engagement_product_endpoints(engagement, old_product, new_product):
    """
    Re-home the endpoints (legacy) or locations (V3) of an engagement's findings onto
    new_product after the engagement has been moved there.

    An endpoint/location carries its own product association, independent of the
    finding -> test -> engagement -> product chain, so moving an engagement between
    products would otherwise leave the findings' endpoints/locations pointing at the
    source product. HTTP-free so both the UI view and the API can call it.
    """
    if old_product == new_product:
        return

    if settings.V3_FEATURE_LOCATIONS:
        from dojo.location.models import (  # noqa: PLC0415 -- avoid import cycle
            Location,
            LocationFindingReference,
            LocationProductReference,
        )
        # Distinct locations referenced by this engagement's findings
        location_ids = set(
            LocationFindingReference.objects.filter(
                finding__test__engagement=engagement,
            ).values_list("location_id", flat=True),
        )
        for location in Location.objects.filter(id__in=location_ids):
            # Associate with the destination product and (re)assess its status, since an
            # already-existing reference is returned without recomputation.
            new_ref = location.associate_with_product(new_product)
            new_ref.status = location.status_from_product(new_product)
            new_ref.save(update_fields=["status"])
            # For the source product: drop the association if no finding remaining there
            # references this (shared) location, otherwise reassess its status because the
            # moved finding no longer counts toward the old product.
            still_used = LocationFindingReference.objects.filter(
                location=location,
                finding__test__engagement__product=old_product,
            ).exists()
            if still_used:
                old_ref = LocationProductReference.objects.filter(
                    location=location,
                    product=old_product,
                ).first()
                if old_ref is not None:
                    old_ref.status = location.status_from_product(old_product)
                    old_ref.save(update_fields=["status"])
            else:
                location.disassociate_from_product(old_product)
    else:
        # TODO: Delete this after the move to Locations
        from dojo.endpoint.utils import endpoint_get_or_create  # noqa: PLC0415 -- avoid import cycle
        from dojo.models import Endpoint_Status  # noqa: PLC0415 -- avoid import cycle
        statuses = Endpoint_Status.objects.filter(
            finding__test__engagement=engagement,
        ).select_related("endpoint")
        # Cache re-homed endpoints so an endpoint shared across many findings is only
        # get_or_create'd once for the destination product.
        rehomed = {}
        for status in statuses:
            endpoint = status.endpoint
            if endpoint.product_id == new_product.id:
                continue
            key = (endpoint.protocol, endpoint.host, endpoint.port, endpoint.path, endpoint.query, endpoint.fragment)
            new_endpoint = rehomed.get(key)
            if new_endpoint is None:
                new_endpoint, _ = endpoint_get_or_create(
                    protocol=endpoint.protocol,
                    host=endpoint.host,
                    port=endpoint.port,
                    path=endpoint.path,
                    query=endpoint.query,
                    fragment=endpoint.fragment,
                    product=new_product,
                )
                rehomed[key] = new_endpoint
            status.endpoint = new_endpoint
            status.save()

    # Findings moved between products change the aggregate grade of both, so recompute
    # the grade for the source and destination product.
    dojo_dispatch_task(calculate_grade, old_product.id)
    dojo_dispatch_task(calculate_grade, new_product.id)


@receiver(pre_save, sender=Engagement)
def set_name_if_none(sender, instance, *args, **kwargs):
    if not instance.name:
        instance.name = str(instance.target_start)
