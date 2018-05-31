# # endpoints

import logging
from datetime import datetime
from dateutil.relativedelta import relativedelta
from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.core.exceptions import PermissionDenied
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import render, get_object_or_404
from django.utils.html import escape
from django.utils import timezone
from dojo.filters import EndpointFilter
from dojo.forms import EditEndpointForm, \
    DeleteEndpointForm, AddEndpointForm, EndpointMetaDataForm
from dojo.models import Product, Endpoint, Finding, System_Settings
from dojo.utils import get_page_items, add_breadcrumb, get_period_counts, get_system_setting, tab_view_count
from django.contrib.contenttypes.models import ContentType
from custom_field.models import CustomFieldValue, CustomField

logger = logging.getLogger(__name__)


def vulnerable_endpoints(request):
    endpoints = Endpoint.objects.filter(finding__active=True, finding__verified=True, finding__false_p=False,
                                        finding__duplicate=False, finding__out_of_scope=False).distinct()

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

    ids = get_endpoint_ids(EndpointFilter(request.GET, queryset=endpoints, user=request.user).qs)
    endpoints = EndpointFilter(request.GET, queryset=endpoints.filter(id__in=ids), user=request.user)
    paged_endpoints = get_page_items(request, endpoints.qs, 25)
    add_breadcrumb(title="Vulnerable Endpoints", top_level=not len(request.GET), request=request)

    system_settings = System_Settings.objects.get()

    tab_product = None
    tab_engagements = None
    tab_findings = None
    tab_endpoints = None
    tab_benchmarks = None
    active_tab = None
    view_name = "All Endpoints"
    if product:
        active_tab = "endpoints"
        tab_product, tab_engagements, tab_findings, tab_endpoints, tab_benchmarks = tab_view_count(product.id)

    return render(
        request, 'dojo/endpoints.html', {
            'tab_product': tab_product,
            'tab_engagements': tab_engagements,
            'tab_findings': tab_findings,
            'tab_endpoints': tab_endpoints,
            'tab_benchmarks': tab_benchmarks,
            'active_tab': active_tab,
            'system_settings': system_settings,
            "endpoints": paged_endpoints,
            "filtered": endpoints,
            "name": "Vulnerable Endpoints",
        })


def all_endpoints(request):
    endpoints = Endpoint.objects.all()
    show_uri = get_system_setting('display_endpoint_uri')
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

    if show_uri:
        endpoints = EndpointFilter(request.GET, queryset=endpoints, user=request.user)
        paged_endpoints = get_page_items(request, endpoints.qs, 25)
    else:
        ids = get_endpoint_ids(EndpointFilter(request.GET, queryset=endpoints, user=request.user).qs)
        endpoints = EndpointFilter(request.GET, queryset=endpoints.filter(id__in=ids), user=request.user)
        paged_endpoints = get_page_items(request, endpoints.qs, 25)
    add_breadcrumb(title="All Endpoints", top_level=not len(request.GET), request=request)

    system_settings = System_Settings.objects.get()

    tab_product = None
    tab_engagements = None
    tab_findings = None
    tab_endpoints = None
    tab_benchmarks = None
    active_tab = None
    view_name = "All Endpoints"
    if product:
        view_name = "Endpoints"
        active_tab = "endpoints"
        tab_product, tab_engagements, tab_findings, tab_endpoints, tab_benchmarks = tab_view_count(product.id)

    return render(
        request, 'dojo/endpoints.html', {
            'tab_product': tab_product,
            'tab_engagements': tab_engagements,
            'tab_findings': tab_findings,
            'tab_endpoints': tab_endpoints,
            'tab_benchmarks': tab_benchmarks,
            'active_tab': active_tab,
            'system_settings': system_settings,
            "endpoints": paged_endpoints,
            "filtered": endpoints,
            "name": view_name,
            "show_uri": show_uri
        })


def get_endpoint_ids(endpoints):
    hosts = []
    ids = []
    for e in endpoints:
        if ":" in e.host:
            host_no_port = e.host[:e.host.index(':')]
        else:
            host_no_port = e.host
        key = host_no_port + '-' + str(e.product.id)
        if key in hosts:
            continue
        else:
            hosts.append(key)
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

    ct = ContentType.objects.get_for_model(endpoint)
    endpoint_cf = CustomField.objects.filter(content_type=ct)
    endpoint_metadata = {}

    for cf in endpoint_cf:
        cfv = CustomFieldValue.objects.filter(field=cf, object_id=endpoint.id)
        if len(cfv):
            endpoint_metadata[cf] = cfv[0]

    all_findings = Finding.objects.filter(endpoints__in=endpoints).distinct()

    active_findings = Finding.objects.filter(endpoints__in=endpoints,
                                             active=True,
                                             verified=True).distinct()

    closed_findings = Finding.objects.filter(endpoints__in=endpoints,
                                             mitigated__isnull=False).distinct()
    if all_findings:
        start_date = timezone.make_aware(datetime.combine(all_findings.last().date, datetime.min.time()))
    else:
        start_date = timezone.now()
    end_date = timezone.now()

    r = relativedelta(end_date, start_date)
    months_between = (r.years * 12) + r.months
    # include current month
    months_between += 1

    monthly_counts = get_period_counts(active_findings, all_findings, closed_findings, None, months_between, start_date,
                                       relative_delta='months')

    paged_findings = get_page_items(request, active_findings, 25)

    vulnerable = False

    if active_findings.count() != 0:
        vulnerable = True

    system_settings = System_Settings.objects.get()
    tab_product, tab_engagements, tab_findings, tab_endpoints, tab_benchmarks = tab_view_count(endpoint.product.id)
    add_breadcrumb(parent=endpoint, top_level=False, request=request)
    return render(request,
                  "dojo/view_endpoint.html",
                  {"endpoint": endpoint,
                   'tab_product': tab_product,
                   'tab_engagements': tab_engagements,
                   'tab_findings': tab_findings,
                   'tab_endpoints': tab_endpoints,
                   'tab_benchmarks': tab_benchmarks,
                   'active_tab': "endpoints",
                   'system_settings': system_settings,
                   "endpoints": endpoints,
                   "findings": paged_findings,
                   'all_findings': all_findings,
                   'opened_per_month': monthly_counts['opened_per_period'],
                   'endpoint_metadata': endpoint_metadata,
                   'vulnerable': vulnerable,
                   })


@user_passes_test(lambda u: u.is_staff)
def edit_endpoint(request, eid):
    endpoint = get_object_or_404(Endpoint, id=eid)

    if request.method == 'POST':
        form = EditEndpointForm(request.POST, instance=endpoint)
        if form.is_valid():
            endpoint = form.save()
            tags = request.POST.getlist('tags')
            t = ", ".join(tags)
            endpoint.tags = t
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Endpoint updated successfully.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_endpoint', args=(endpoint.id,)))
    add_breadcrumb(parent=endpoint, title="Edit", top_level=False, request=request)
    form = EditEndpointForm(instance=endpoint)
    form.initial['tags'] = [tag.name for tag in endpoint.tags]

    system_settings = System_Settings.objects.get()
    tab_product, tab_engagements, tab_findings, tab_endpoints, tab_benchmarks = tab_view_count(endpoint.product.id)

    return render(request,
                  "dojo/edit_endpoint.html",
                  {"endpoint": endpoint,
                   'tab_product': tab_product,
                   'tab_engagements': tab_engagements,
                   'tab_findings': tab_findings,
                   'tab_endpoints': tab_endpoints,
                   'tab_benchmarks': tab_benchmarks,
                   'active_tab': "endpoints",
                   'system_settings': system_settings,
                   "form": form,
                   })


@user_passes_test(lambda u: u.is_staff)
def delete_endpoint(request, eid):
    endpoint = get_object_or_404(Endpoint, pk=eid)
    product = endpoint.product
    form = DeleteEndpointForm(instance=endpoint)

    from django.contrib.admin.utils import NestedObjects
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
                return HttpResponseRedirect(reverse('view_endpoint', args=(product.id,)))
    add_breadcrumb(parent=endpoint, title="Delete", top_level=False, request=request)

    system_settings = System_Settings.objects.get()
    tab_product, tab_engagements, tab_findings, tab_endpoints, tab_benchmarks = tab_view_count(endpoint.product.id)

    return render(request, 'dojo/delete_endpoint.html',
                  {'endpoint': endpoint,
                   'tab_product': tab_product,
                   'tab_engagements': tab_engagements,
                   'tab_findings': tab_findings,
                   'tab_endpoints': tab_endpoints,
                   'tab_benchmarks': tab_benchmarks,
                   'active_tab': "endpoints",
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
            tags = request.POST.getlist('tags')
            t = ", ".join(tags)
            for e in endpoints:
                e.tags = t
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
            else:
                return HttpResponseRedirect(reverse('endpoints') + "?product=" + pid)

    system_settings = System_Settings.objects.get()

    tab_product = None
    tab_engagements = None
    tab_findings = None
    tab_endpoints = None
    tab_benchmarks = None
    active_tab = None

    if '_popup' not in request.GET:
        view_name = "Endpoints"
        active_tab = "endpoints"
        tab_product, tab_engagements, tab_findings, tab_endpoints, tab_benchmarks = tab_view_count(pid)

    return render(request, template, {
        'tab_product': tab_product,
        'tab_engagements': tab_engagements,
        'tab_findings': tab_findings,
        'tab_endpoints': tab_endpoints,
        'tab_benchmarks': tab_benchmarks,
        'active_tab': 'endpoints',
        'system_settings': system_settings,
        'name': 'Add Endpoint',
        'form': form})


@user_passes_test(lambda u: u.is_staff)
def add_product_endpoint(request):
    form = AddEndpointForm()
    if request.method == 'POST':
        form = AddEndpointForm(request.POST)
        if form.is_valid():
            endpoints = form.save()
            tags = request.POST.getlist('tags')
            t = ", ".join(tags)
            for e in endpoints:
                e.tags = t
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Endpoint added successfully.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_endpoint'))
    add_breadcrumb(title="Add Endpoint", top_level=False, request=request)
    return render(request,
                  'dojo/add_endpoint.html',
                  {'name': 'Add Endpoint',
                   'form': form,
                   })


@user_passes_test(lambda u: u.is_staff)
def add_meta_data(request, eid):
    endpoint = Endpoint.objects.get(id=eid)
    ct = ContentType.objects.get_for_model(endpoint)

    if request.method == 'POST':
        form = EndpointMetaDataForm(request.POST)
        if form.is_valid():
            cf, created = CustomField.objects.get_or_create(name=form.cleaned_data['name'],
                                                            content_type=ct,
                                                            field_type='a')
            cf.save()
            cfv, created = CustomFieldValue.objects.get_or_create(field=cf,
                                                                  object_id=endpoint.id)
            cfv.value = form.cleaned_data['value']
            cfv.clean()
            cfv.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Metadata added successfully.',
                                 extra_tags='alert-success')
            if 'add_another' in request.POST:
                return HttpResponseRedirect(reverse('add_meta_data', args=(eid,)))
            else:
                return HttpResponseRedirect(reverse('view_endpoint', args=(eid,)))
    else:
        form = EndpointMetaDataForm(initial={'content_type': endpoint})

    add_breadcrumb(parent=endpoint, title="Add Metadata", top_level=False, request=request)

    return render(request,
                  'dojo/add_endpoint_meta_data.html',
                  {'form': form,
                   'endpoint': endpoint,
                   })


@user_passes_test(lambda u: u.is_staff)
def edit_meta_data(request, eid):

    endpoint = Endpoint.objects.get(id=eid)
    ct = ContentType.objects.get_for_model(endpoint)

    endpoint_cf = CustomField.objects.filter(content_type=ct)
    endpoint_metadata = {}

    for cf in endpoint_cf:
        cfv = CustomFieldValue.objects.filter(field=cf, object_id=endpoint.id)
        if len(cfv):
            endpoint_metadata[cf] = cfv[0]

    if request.method == 'POST':
        for key, value in request.POST.iteritems():
            if key.startswith('cfv_'):
                cfv_id = int(key.split('_')[1])
                cfv = get_object_or_404(CustomFieldValue, id=cfv_id)

                value = value.strip()
                if value:
                    cfv.value = value
                    cfv.save()
                else:
                    cfv.delete()
        messages.add_message(request,
                             messages.SUCCESS,
                             'Metadata edited successfully.',
                             extra_tags='alert-success')
        return HttpResponseRedirect(reverse('view_endpoint', args=(eid,)))

    add_breadcrumb(parent=endpoint, title="Edit Metadata", top_level=False, request=request)

    return render(request,
                  'dojo/edit_endpoint_meta_data.html',
                  {'endpoint': endpoint,
                   'endpoint_metadata': endpoint_metadata,
                   })
