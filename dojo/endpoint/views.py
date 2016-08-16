# # endpoints

import logging
from datetime import datetime
from dateutil.relativedelta import relativedelta
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.core.exceptions import PermissionDenied
from django.core.urlresolvers import reverse
from django.db.models import Count
from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import render, get_object_or_404
from django.utils.html import escape
from pytz import timezone
from dojo.filters import EndpointFilter
from dojo.forms import EditEndpointForm, \
    DeleteEndpointForm, AddEndpointForm
from dojo.models import Product, Endpoint, Finding
from dojo.utils import get_page_items, add_breadcrumb, get_period_counts

localtz = timezone(settings.TIME_ZONE)

logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)d] %(message)s',
    datefmt='%d/%b/%Y %H:%M:%S',
    filename=settings.DOJO_ROOT + '/../django_app.log',
)
logger = logging.getLogger(__name__)


@user_passes_test(lambda u: u.is_staff)
def vulnerable_endpoints(request):
    endpoints = Endpoint.objects.filter(finding__active=True, finding__verified=True, finding__false_p=False,
                                        finding__duplicate=False, finding__out_of_scope=False).distinct()

    product = None
    if 'product' in request.GET:
        p = request.GET.getlist('product', [])
        if len(p) == 1:
            product = get_object_or_404(Product, id=p[0])

    ids = get_endpoint_ids(EndpointFilter(request.GET, queryset=endpoints, user=request.user))
    endpoints = EndpointFilter(request.GET, queryset=endpoints.filter(id__in=ids), user=request.user)
    paged_endpoints = get_page_items(request, endpoints, 25)
    add_breadcrumb(title="Vulnerable Endpoints", top_level=not len(request.GET), request=request)
    return render(request,
                  'dojo/endpoints.html',
                  {"endpoints": paged_endpoints,
                   "filtered": endpoints,
                   "name": "Vulnerable Endpoints",
                   })


def all_endpoints(request):
    endpoints = Endpoint.objects.all()
    # are they authorized
    if request.user.is_staff:
        pass
    else:
        products = Product.objects.filter(authorized_users__in=[request.user])
        if products.exists():
            endpoints = endpoints.filter(product__in=products.all())
        else:
            raise PermissionDenied

    product = None
    if 'product' in request.GET:
        p = request.GET.getlist('product', [])
        if len(p) == 1:
            product = get_object_or_404(Product, id=p[0])

    ids = get_endpoint_ids(EndpointFilter(request.GET, queryset=endpoints, user=request.user))
    endpoints = EndpointFilter(request.GET, queryset=endpoints.filter(id__in=ids), user=request.user)
    paged_endpoints = get_page_items(request, endpoints, 25)
    add_breadcrumb(title="All Endpoints", top_level=not len(request.GET), request=request)
    return render(request,
                  'dojo/endpoints.html',
                  {"endpoints": paged_endpoints,
                   "filtered": endpoints,
                   "name": "All Endpoints",
                   })


def get_endpoint_ids(endpoints):
    hosts = []
    ids = []
    for e in endpoints:
        if ":" in e.host:
            host_no_port = e.host[:e.host.index(':')]
        else:
            host_no_port = e.host

        if host_no_port in hosts:
            continue
        else:
            hosts.append(host_no_port)
            ids.append(e.id)
    return ids


def view_endpoint(request, eid):
    endpoint = get_object_or_404(Endpoint, id=eid)
    host = endpoint.host_no_port
    endpoints = Endpoint.objects.filter(host__regex="^" + host + ":?",
                                        product=endpoint.product).distinct()

    if (request.user in endpoint.product.authorized_users.all()) or request.user.is_staff:
        pass
    else:
        raise PermissionDenied

    all_findings = Finding.objects.filter(endpoints__in=endpoints).distinct()

    active_findings = Finding.objects.filter(endpoints__in=endpoints,
                                             active=True,
                                             verified=True).distinct()
    if all_findings:
        start_date = localtz.localize(datetime.combine(all_findings.last().date, datetime.min.time()))
    else:
        start_date = localtz.localize(datetime.today())
    end_date = localtz.localize(datetime.today())

    r = relativedelta(end_date, start_date)
    months_between = (r.years * 12) + r.months
    # include current month
    months_between += 1

    monthly_counts = get_period_counts(all_findings, all_findings, None, months_between, start_date,
                                       relative_delta='months')
    paged_findings = get_page_items(request, active_findings, 25)

    add_breadcrumb(parent=endpoint, top_level=False, request=request)
    return render(request,
                  "dojo/view_endpoint.html",
                  {"endpoint": endpoint,
                   "endpoints": endpoints,
                   "findings": paged_findings,
                   'all_findings': all_findings,
                   'opened_per_month': monthly_counts['opened_per_period'],
                   })


@user_passes_test(lambda u: u.is_staff)
def edit_endpoint(request, eid):
    endpoint = get_object_or_404(Endpoint, id=eid)
    form = EditEndpointForm(instance=endpoint)
    if request.method == 'POST':
        form = EditEndpointForm(request.POST, instance=endpoint)
        if form.is_valid():
            form.save()
            tags = form.cleaned_data['tags']
            endpoint.tags = tags
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Endpoint updated successfully.',
                                 extra_tags='alert-success')
    add_breadcrumb(parent=endpoint, title="Edit", top_level=False, request=request)
    form.initial['tags'] = ", ".join([tag.name for tag in endpoint.tags])
    return render(request,
                  "dojo/edit_endpoint.html",
                  {"endpoint": endpoint,
                   "form": form,
                   })


@user_passes_test(lambda u: u.is_staff)
def delete_endpoint(request, eid):
    endpoint = get_object_or_404(Endpoint, pk=eid)
    product = endpoint.product
    form = DeleteEndpointForm(instance=endpoint)

    from django.contrib.admin.util import NestedObjects
    from django.db import DEFAULT_DB_ALIAS

    collector = NestedObjects(using=DEFAULT_DB_ALIAS)
    collector.collect([endpoint])
    rels = collector.nested()

    if request.method == 'POST':
        if 'id' in request.POST and str(endpoint.id) == request.POST['id']:
            form = DeleteEndpointForm(request.POST, instance=endpoint)
            if form.is_valid():
                del endpoint.tags
                endpoint.delete()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'Endpoint and relationships removed.',
                                     extra_tags='alert-success')
                return HttpResponseRedirect(reverse('view_product', args=(product.id,)))
    add_breadcrumb(parent=endpoint, title="Delete", top_level=False, request=request)
    return render(request, 'dojo/delete_endpoint.html',
                  {'endpoint': endpoint,
                   'form': form,
                   'rels': rels,
                   })


@user_passes_test(lambda u: u.is_staff)
def add_endpoint(request, pid):
    product = get_object_or_404(Product, id=pid)
    template = 'dojo/add_endpoint.html'
    if '_popup' in request.GET:
        template = 'dojo/add_related.html'
    else:
        add_breadcrumb(parent=product, title="Add Endpoint", top_level=False, request=request)

    form = AddEndpointForm(product=product)

    if request.method == 'POST':
        form = AddEndpointForm(request.POST, product=product)
        if form.is_valid():
            endpoints = form.save()
            tags = form.cleaned_data['tags']
            for e in endpoints:
                e.tags = tags
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Endpoint added successfully.',
                                 extra_tags='alert-success')
            if '_popup' in request.GET:
                resp = '<script type="text/javascript">opener.emptyEndpoints(window);</script>'
                for endpoint in endpoints:
                    resp += '<script type="text/javascript">opener.dismissAddAnotherPopupDojo(window, "%s", "%s");</script>' \
                            % (escape(endpoint._get_pk_val()), escape(endpoint))
                resp += '<script type="text/javascript">window.close();</script>'
                return HttpResponse(resp)

    return render(request, template, {
        'name': 'Add Endpoint',
        'form': form})


@user_passes_test(lambda u: u.is_staff)
def add_product_endpoint(request):
    form = AddEndpointForm()
    if request.method == 'POST':
        form = AddEndpointForm(request.POST)
        if form.is_valid():
            endpoints = form.save()
            tags = form.cleaned_data['tags']
            for e in endpoints:
                e.tags = tags
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Endpoint added successfully.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('endpoints'))
    add_breadcrumb(title="Add Endpoint", top_level=False, request=request)
    return render(request,
                  'dojo/add_endpoint.html',
                  {'name': 'Add Endpoint',
                   'form': form,
                   })
