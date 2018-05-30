import logging

from auditlog.models import LogEntry
from django.contrib.contenttypes.models import ContentType
from django.http import Http404
from django.shortcuts import render
from dojo.models import System_Settings, Engagement, Test, Finding, Endpoint
from dojo.filters import LogEntryFilter
from dojo.utils import get_page_items, add_breadcrumb, tab_view_count

logger = logging.getLogger(__name__)


def action_history(request, cid, oid):
    try:
        ct = ContentType.objects.get_for_id(cid)
        obj = ct.get_object_for_this_type(pk=oid)
    except KeyError:
        raise Http404()

    product_id = None
    tab_product = None
    tab_engagements = None
    tab_findings = None
    tab_endpoints = None
    tab_benchmarks = None
    active_tab = None

    if str(ct) == "product":
        product_id = obj.id
        active_tab = "overview"
    elif str(ct) == "engagement":
        object_value = Engagement.objects.get(id=obj.id)
        product_id = object_value.product.id
        active_tab = "engagements"
    elif str(ct) == "test":
        object_value = Test.objects.get(id=obj.id)
        product_id = object_value.engagement.product.id
        active_tab = "engagements"
    elif str(ct) == "finding":
        object_value = Finding.objects.get(id=obj.id)
        product_id = object_value.test.engagement.product.id
        active_tab = "findings"
    elif str(ct) == "endpoint":
        object_value = Endpoint.objects.get(id=obj.id)
        product_id = object_value.product.id
        active_tab = "endpoints"

    if product_id:
        tab_product, tab_engagements, tab_findings, tab_endpoints, tab_benchmarks = tab_view_count(product_id)

    system_settings = System_Settings.objects.get()
    history = LogEntry.objects.filter(content_type=ct,
                                      object_pk=obj.id).order_by('-timestamp')
    history = LogEntryFilter(request.GET, queryset=history)
    paged_history = get_page_items(request, history.qs, 25)
    add_breadcrumb(parent=obj, title="Action History", top_level=False,
                   request=request)
    return render(request, 'dojo/action_history.html',
                  {"history": paged_history,
                   'tab_product': tab_product,
                   'tab_engagements': tab_engagements,
                   'tab_findings': tab_findings,
                   'tab_endpoints': tab_endpoints,
                   'tab_benchmarks': tab_benchmarks,
                   'active_tab': active_tab,
                   'system_settings': system_settings,
                   "filtered": history,
                   "obj": obj,
                   })
