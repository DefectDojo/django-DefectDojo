import logging

from auditlog.models import LogEntry
from django.contrib.contenttypes.models import ContentType
from django.http import Http404
from django.shortcuts import render
from dojo.models import Engagement, Test, Finding, Endpoint, Product
from dojo.filters import LogEntryFilter
from dojo.utils import get_page_items, Product_Tab

logger = logging.getLogger(__name__)


def action_history(request, cid, oid):
    try:
        ct = ContentType.objects.get_for_id(cid)
        obj = ct.get_object_for_this_type(pk=oid)
    except KeyError:
        raise Http404()

    product_id = None
    active_tab = None
    finding = None
    test = False
    if str(ct) == "product":
        product_id = obj.id
        active_tab = "overview"
        object_value = Product.objects.get(id=obj.id)
    elif str(ct) == "engagement":
        object_value = Engagement.objects.get(id=obj.id)
        product_id = object_value.product.id
        active_tab = "engagements"
    elif str(ct) == "test":
        object_value = Test.objects.get(id=obj.id)
        product_id = object_value.engagement.product.id
        active_tab = "engagements"
        test = True
    elif str(ct) == "finding":
        object_value = Finding.objects.get(id=obj.id)
        product_id = object_value.test.engagement.product.id
        active_tab = "findings"
        finding = object_value
    elif str(ct) == "endpoint":
        object_value = Endpoint.objects.get(id=obj.id)
        product_id = object_value.product.id
        active_tab = "endpoints"

    product_tab = None
    if product_id:
        product_tab = Product_Tab(product_id, title="History", tab=active_tab)
        if active_tab == "engagements":
            if str(ct) == "engagement":
                product_tab.setEngagement(object_value)
            else:
                product_tab.setEngagement(object_value.engagement)

    history = LogEntry.objects.filter(content_type=ct,
                                      object_pk=obj.id).order_by('-timestamp')
    history = LogEntryFilter(request.GET, queryset=history)
    paged_history = get_page_items(request, history.qs, 25)

    return render(request, 'dojo/action_history.html',
                  {"history": paged_history,
                   'product_tab': product_tab,
                   "filtered": history,
                   "obj": obj,
                   "test": test,
                   "object_value": object_value,
                   "finding": finding
                   })
