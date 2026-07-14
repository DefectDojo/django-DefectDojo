"""Audit-log UI views."""
import logging

from auditlog.models import LogEntry
from django.conf import settings
from django.contrib import messages
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ObjectDoesNotExist, PermissionDenied
from django.http import Http404
from django.shortcuts import get_object_or_404, render

from dojo.auditlog.filters import LogEntryFilter, PgHistoryFilter
from dojo.auditlog.helpers import process_events_for_display
from dojo.auditlog.models import DojoEvents
from dojo.authorization.authorization import (
    user_has_configuration_permission_or_403,
    user_has_global_permission,
    user_has_permission,
    user_has_permission_or_403,
)
from dojo.location.models import Location
from dojo.models import (
    Endpoint,
    Engagement,
    Finding,
    Product,
    Test,
)
from dojo.utils import Product_Tab, get_page_items

logger = logging.getLogger(__name__)


def action_history(request, cid, oid):
    try:
        ct = ContentType.objects.get_for_id(cid)
        obj = ct.get_object_for_this_type(pk=oid)
    except (KeyError, ObjectDoesNotExist):
        raise Http404

    product_id = None
    active_tab = None
    finding = None
    test = False
    object_value = None

    if ct.model == "product":
        user_has_permission_or_403(request.user, obj, "view")
        product_id = obj.id
        active_tab = "overview"
        object_value = Product.objects.get(id=obj.id)
    elif ct.model == "engagement":
        user_has_permission_or_403(request.user, obj, "view")
        object_value = Engagement.objects.get(id=obj.id)
        product_id = object_value.product.id
        active_tab = "engagements"
    elif ct.model == "test":
        user_has_permission_or_403(request.user, obj, "view")
        object_value = Test.objects.get(id=obj.id)
        product_id = object_value.engagement.product.id
        active_tab = "engagements"
        test = True
    elif ct.model == "finding":
        user_has_permission_or_403(request.user, obj, "view")
        object_value = Finding.objects.get(id=obj.id)
        product_id = object_value.test.engagement.product.id
        active_tab = "findings"
        finding = object_value
    elif ct.model == "location":
        user_has_permission_or_403(request.user, obj, "view")
        object_value = Location.objects.get(id=obj.id)
        active_tab = "endpoints"
    # TODO: Delete this after the move to Locations
    elif ct.model == "endpoint":
        user_has_permission_or_403(request.user, obj, "view")
        with Endpoint.allow_endpoint_init():
            object_value = Endpoint.objects.get(id=obj.id)
        product_id = object_value.product.id
        active_tab = "endpoints"
    elif ct.model == "risk_acceptance":
        engagements = Engagement.objects.filter(risk_acceptance=obj)
        authorized = False
        fetched_engagements = list(engagements)
        if len(fetched_engagements) == 0:
            authorized = user_has_global_permission(request.user, "edit")
        else:
            for engagement in fetched_engagements:
                if user_has_permission(request.user, engagement, "view"):
                    authorized = True
                    break
        if not authorized:
            raise PermissionDenied
    elif ct.model == "user":
        user_has_configuration_permission_or_403(request.user, "auth.view_user")
    elif not request.user.is_superuser:
        raise PermissionDenied

    product_tab = None
    if product_id:
        product_tab = Product_Tab(get_object_or_404(Product, id=product_id), title="History", tab=active_tab)
        if active_tab == "engagements":
            if str(ct) == "engagement":
                product_tab.setEngagement(object_value)
            else:
                product_tab.setEngagement(object_value.engagement)

    # Get audit history from pghistory (and legacy django-auditlog entries if available)
    auditlog_history = []
    pghistory_history = []

    auditlog_queryset = LogEntry.objects.filter(
        content_type=ct,
        object_pk=obj.id,
    ).order_by("-timestamp")
    auditlog_history = auditlog_queryset

    # Use custom DojoEvents proxy model — provides proper diff calculation and context fields.
    # references() returns events where any FK points to the object (including through models like tags/reviewers).
    # Events is a CTE that doesn't support select_related, but includes context data.
    pghistory_history = DojoEvents.objects.references(obj).order_by("-pgh_created_at")

    pghistory_filter = PgHistoryFilter(request.GET, queryset=pghistory_history)
    filtered_pghistory = pghistory_filter.qs

    processed_events = list(filtered_pghistory)
    process_events_for_display(processed_events)

    paged_pghistory_history = get_page_items(request, processed_events, 25)

    auditlog_filter = LogEntryFilter(request.GET, queryset=auditlog_history)
    paged_auditlog_history = get_page_items(request, auditlog_filter.qs, 25)

    if not settings.ENABLE_AUDITLOG:
        messages.add_message(
            request,
            messages.WARNING,
            "Audit logging is currently disabled in System Settings.",
            extra_tags="alert-danger")

    return render(request, "dojo/action_history.html",
                  {"auditlog_history": paged_auditlog_history,
                   "pghistory_history": paged_pghistory_history,
                   "product_tab": product_tab,
                   "filtered": auditlog_history,
                   "log_entry_filter": auditlog_filter,
                   "pghistory_filter": pghistory_filter,
                   "obj": obj,
                   "test": test,
                   "object_value": object_value,
                   "finding": finding,
                   })
