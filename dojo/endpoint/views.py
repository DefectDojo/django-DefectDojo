import logging
from datetime import datetime
from dateutil.relativedelta import relativedelta
from django.contrib import messages
from django.conf import settings
from django.urls import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import render, get_object_or_404
from django.utils import timezone
from django.contrib.admin.utils import NestedObjects
from django.db import DEFAULT_DB_ALIAS
from django.db.models import Q, QuerySet, Count

from dojo.endpoint.utils import clean_hosts_run, endpoint_meta_import
from dojo.filters import EndpointFilter
from dojo.forms import EditEndpointForm, \
    DeleteEndpointForm, AddEndpointForm, DojoMetaDataForm, ImportEndpointMetaForm
from dojo.models import Product, Endpoint, Finding, DojoMeta, Endpoint_Status
from dojo.utils import get_page_items, add_breadcrumb, get_period_counts, Product_Tab, calculate_grade, redirect, \
    add_error_message_to_response, is_scan_file_too_large
from dojo.notifications.helper import create_notification
from dojo.authorization.authorization_decorators import user_is_authorized
from dojo.authorization.roles_permissions import Permissions
from dojo.authorization.authorization import user_has_permission_or_403
from dojo.endpoint.queries import get_authorized_endpoints
from django.apps import apps


logger = logging.getLogger(__name__)


def process_endpoints_view(request, host_view=False, vulnerable=False):

    if vulnerable:
        endpoints = Endpoint.objects.filter(
            finding__active=True,
            finding__verified=True,
            finding__out_of_scope=False,
            finding__mitigated__isnull=True,
            finding__false_p=False,
            finding__duplicate=False,
            status_endpoint__mitigated=False,
            status_endpoint__false_positive=False,
            status_endpoint__out_of_scope=False,
            status_endpoint__risk_accepted=False)
    else:
        endpoints = Endpoint.objects.all()

    endpoints = endpoints.prefetch_related('product', 'product__tags', 'tags').distinct()
    endpoints = get_authorized_endpoints(Permissions.Endpoint_View, endpoints, request.user)

    if host_view:
        ids = get_endpoint_ids(EndpointFilter(request.GET, queryset=endpoints, user=request.user).qs)
        endpoints = EndpointFilter(request.GET, queryset=endpoints.filter(id__in=ids), user=request.user)
    else:
        endpoints = EndpointFilter(request.GET, queryset=endpoints, user=request.user)

    paged_endpoints = get_page_items(request, endpoints.qs, 25)

    if vulnerable:
        view_name = "Vulnerable"
    else:
        view_name = "All"

    if host_view:
        view_name += " Hosts"
    else:
        view_name += " Endpoints"

    add_breadcrumb(title=view_name, top_level=not len(request.GET), request=request)

    product_tab = None
    if 'product' in request.GET:
        p = request.GET.getlist('product', [])
        if len(p) == 1:
            product = get_object_or_404(Product, id=p[0])
            user_has_permission_or_403(request.user, product, Permissions.Product_View)
            product_tab = Product_Tab(product, view_name, tab="endpoints")

    return render(
        request, 'dojo/endpoints.html', {
            'product_tab': product_tab,
            "endpoints": paged_endpoints,
            "filtered": endpoints,
            "name": view_name,
            "host_view": host_view,
            "product_tab": product_tab
        })


def get_endpoint_ids(endpoints):
    hosts = []
    ids = []
    for e in endpoints:
        key = e.host + '-' + str(e.product.id)
        if key in hosts:
            continue
        else:
            hosts.append(key)
            ids.append(e.id)
    return ids


def all_endpoints(request):
    return process_endpoints_view(request, host_view=False, vulnerable=False)


def all_endpoint_hosts(request):
    return process_endpoints_view(request, host_view=True, vulnerable=False)


def vulnerable_endpoints(request):
    return process_endpoints_view(request, host_view=False, vulnerable=True)


def vulnerable_endpoint_hosts(request):
    return process_endpoints_view(request, host_view=True, vulnerable=True)


def process_endpoint_view(request, eid, host_view=False):
    endpoint = get_object_or_404(Endpoint, id=eid)

    if host_view:
        endpoints = endpoint.host_endpoints()
        endpoint_metadata = None
        all_findings = endpoint.host_findings()
        active_verified_findings = endpoint.host_active_verified_findings()
    else:
        endpoints = None
        endpoint_metadata = dict(endpoint.endpoint_meta.values_list('name', 'value'))
        all_findings = endpoint.findings.all()
        active_verified_findings = endpoint.active_verified_findings()

    if all_findings:
        start_date = timezone.make_aware(datetime.combine(all_findings.last().date, datetime.min.time()))
    else:
        start_date = timezone.now()
    end_date = timezone.now()

    r = relativedelta(end_date, start_date)
    months_between = (r.years * 12) + r.months
    # include current month
    months_between += 1

    # closed_findings is needed as a parameter for get_periods_counts, but they are not relevant in the endpoint view
    closed_findings = Finding.objects.none()

    monthly_counts = get_period_counts(all_findings, closed_findings, None, months_between, start_date,
                                       relative_delta='months')

    paged_findings = get_page_items(request, active_verified_findings, 25)

    vulnerable = False

    if active_verified_findings.count() != 0:
        vulnerable = True

    product_tab = Product_Tab(endpoint.product, "Host" if host_view else "Endpoint", tab="endpoints")
    return render(request,
                  "dojo/view_endpoint.html",
                  {"endpoint": endpoint,
                   'product_tab': product_tab,
                   "endpoints": endpoints,
                   "findings": paged_findings,
                   'all_findings': all_findings,
                   'opened_per_month': monthly_counts['opened_per_period'],
                   'endpoint_metadata': endpoint_metadata,
                   'vulnerable': vulnerable,
                   'host_view': host_view,
                   })


@user_is_authorized(Endpoint, Permissions.Endpoint_View, 'eid')
def view_endpoint(request, eid):
    return process_endpoint_view(request, eid, host_view=False)


@user_is_authorized(Endpoint, Permissions.Endpoint_View, 'eid')
def view_endpoint_host(request, eid):
    return process_endpoint_view(request, eid, host_view=True)


@user_is_authorized(Endpoint, Permissions.Endpoint_View, 'eid')
def edit_endpoint(request, eid):
    endpoint = get_object_or_404(Endpoint, id=eid)

    if request.method == 'POST':
        form = EditEndpointForm(request.POST, instance=endpoint)
        if form.is_valid():
            logger.debug('saving endpoint')
            endpoint = form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Endpoint updated successfully.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_endpoint', args=(endpoint.id,)))
    else:
        add_breadcrumb(parent=endpoint, title="Edit", top_level=False, request=request)
        form = EditEndpointForm(instance=endpoint)

    product_tab = Product_Tab(endpoint.product, "Endpoint", tab="endpoints")

    return render(request,
                  "dojo/edit_endpoint.html",
                  {"endpoint": endpoint,
                   'product_tab': product_tab,
                   "form": form,
                   })


@user_is_authorized(Endpoint, Permissions.Endpoint_Delete, 'eid')
def delete_endpoint(request, eid):
    endpoint = get_object_or_404(Endpoint, pk=eid)
    product = endpoint.product
    form = DeleteEndpointForm(instance=endpoint)

    if request.method == 'POST':
        if 'id' in request.POST and str(endpoint.id) == request.POST['id']:
            form = DeleteEndpointForm(request.POST, instance=endpoint)
            if form.is_valid():
                product = endpoint.product
                endpoint.delete()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'Endpoint and relationships removed.',
                                     extra_tags='alert-success')
                create_notification(event='other',
                                    title='Deletion of %s' % endpoint,
                                    product=product,
                                    description='The endpoint "%s" was deleted by %s' % (endpoint, request.user),
                                    url=reverse('endpoint'),
                                    icon="exclamation-triangle")
                return HttpResponseRedirect(reverse('view_product', args=(product.id,)))

    collector = NestedObjects(using=DEFAULT_DB_ALIAS)
    collector.collect([endpoint])
    rels = collector.nested()

    product_tab = Product_Tab(endpoint.product, "Delete Endpoint", tab="endpoints")

    return render(request, 'dojo/delete_endpoint.html',
                  {'endpoint': endpoint,
                   'product_tab': product_tab,
                   'form': form,
                   'rels': rels,
                   })


@user_is_authorized(Product, Permissions.Endpoint_Add, 'pid')
def add_endpoint(request, pid):
    product = get_object_or_404(Product, id=pid)
    template = 'dojo/add_endpoint.html'

    form = AddEndpointForm(product=product)
    if request.method == 'POST':
        form = AddEndpointForm(request.POST, product=product)
        if form.is_valid():
            endpoints = form.save()
            tags = request.POST.get('tags')
            for e in endpoints:
                e.tags = tags
                e.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Endpoint added successfully.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('endpoint') + "?product=" + pid)

    product_tab = Product_Tab(product, "Add Endpoint", tab="endpoints")

    return render(request, template, {
        'product_tab': product_tab,
        'name': 'Add Endpoint',
        'form': form})


def add_product_endpoint(request):
    form = AddEndpointForm()
    if request.method == 'POST':
        form = AddEndpointForm(request.POST)
        if form.is_valid():
            user_has_permission_or_403(request.user, form.product, Permissions.Endpoint_Add)
            endpoints = form.save()
            tags = request.POST.get('tags')
            for e in endpoints:
                e.tags = tags
                e.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Endpoint added successfully.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('endpoint') + "?product=%s" % form.product.id)
    add_breadcrumb(title="Add Endpoint", top_level=False, request=request)
    return render(request,
                  'dojo/add_endpoint.html',
                  {'name': 'Add Endpoint',
                   'form': form,
                   })


@user_is_authorized(Endpoint, Permissions.Endpoint_Edit, 'eid')
def add_meta_data(request, eid):
    endpoint = Endpoint.objects.get(id=eid)
    if request.method == 'POST':
        form = DojoMetaDataForm(request.POST, instance=DojoMeta(endpoint=endpoint))
        if form.is_valid():
            form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Metadata added successfully.',
                                 extra_tags='alert-success')
            if 'add_another' in request.POST:
                return HttpResponseRedirect(reverse('add_endpoint_meta_data', args=(eid,)))
            else:
                return HttpResponseRedirect(reverse('view_endpoint', args=(eid,)))
    else:
        form = DojoMetaDataForm()

    add_breadcrumb(parent=endpoint, title="Add Metadata", top_level=False, request=request)
    product_tab = Product_Tab(endpoint.product, "Add Metadata", tab="endpoints")
    return render(request,
                  'dojo/add_endpoint_meta_data.html',
                  {'form': form,
                   'product_tab': product_tab,
                   'endpoint': endpoint,
                   })


@user_is_authorized(Endpoint, Permissions.Endpoint_Edit, 'eid')
def edit_meta_data(request, eid):
    endpoint = Endpoint.objects.get(id=eid)

    if request.method == 'POST':
        for key, value in request.POST.items():
            if key.startswith('cfv_'):
                cfv_id = int(key.split('_')[1])
                cfv = get_object_or_404(DojoMeta, id=cfv_id)

                value = value.strip()
                if value:
                    cfv.value = value
                    cfv.save()
            if key.startswith('delete_'):
                cfv_id = int(key.split('_')[2])
                cfv = get_object_or_404(DojoMeta, id=cfv_id)
                cfv.delete()

        messages.add_message(request,
                             messages.SUCCESS,
                             'Metadata edited successfully.',
                             extra_tags='alert-success')
        return HttpResponseRedirect(reverse('view_endpoint', args=(eid,)))

    product_tab = Product_Tab(endpoint.product, "Edit Metadata", tab="endpoints")
    return render(request,
                  'dojo/edit_endpoint_meta_data.html',
                  {'endpoint': endpoint,
                   'product_tab': product_tab,
                   })


# bulk mitigate and delete are combined, so we can't have the nice user_is_authorized decorator
def endpoint_bulk_update_all(request, pid=None):
    if request.method == "POST":
        endpoints_to_update = request.POST.getlist('endpoints_to_update')
        endpoints = Endpoint.objects.filter(id__in=endpoints_to_update).order_by("endpoint_meta__product__id")
        total_endpoint_count = endpoints.count()

        if request.POST.get('delete_bulk_endpoints') and endpoints_to_update:

            if pid is not None:
                product = get_object_or_404(Product, id=pid)
                user_has_permission_or_403(request.user, product, Permissions.Endpoint_Delete)

            endpoints = get_authorized_endpoints(Permissions.Endpoint_Delete, endpoints, request.user)

            skipped_endpoint_count = total_endpoint_count - endpoints.count()
            deleted_endpoint_count = endpoints.count()

            product_calc = list(Product.objects.filter(endpoint__id__in=endpoints_to_update).distinct())
            endpoints.delete()
            for prod in product_calc:
                calculate_grade(prod)

            if skipped_endpoint_count > 0:
                add_error_message_to_response('Skipped deletion of {} endpoints because you are not authorized.'.format(skipped_endpoint_count))

            if deleted_endpoint_count > 0:
                messages.add_message(request,
                    messages.SUCCESS,
                    'Bulk delete of {} endpoints was successful.'.format(deleted_endpoint_count),
                    extra_tags='alert-success')
        else:
            if endpoints_to_update:

                if pid is not None:
                    product = get_object_or_404(Product, id=pid)
                    user_has_permission_or_403(request.user, product, Permissions.Finding_Edit)

                endpoints = get_authorized_endpoints(Permissions.Endpoint_Edit, endpoints, request.user)

                skipped_endpoint_count = total_endpoint_count - endpoints.count()
                updated_endpoint_count = endpoints.count()

                if skipped_endpoint_count > 0:
                    add_error_message_to_response('Skipped mitigation of {} endpoints because you are not authorized.'.format(skipped_endpoint_count))

                eps_count = Endpoint_Status.objects.filter(endpoint__in=endpoints).update(
                    mitigated=True,
                    mitigated_by=request.user,
                    mitigated_time=timezone.now(),
                    last_modified=timezone.now()
                )

                if updated_endpoint_count > 0:
                    messages.add_message(request,
                                        messages.SUCCESS,
                                        'Bulk mitigation of {} endpoints ({} endpoint statuses) was successful.'.format(
                                            updated_endpoint_count, eps_count),
                                        extra_tags='alert-success')
            else:
                messages.add_message(request,
                                     messages.ERROR,
                                     'Unable to process bulk update. Required fields were not selected.',
                                     extra_tags='alert-danger')
    return HttpResponseRedirect(reverse('endpoint', args=()))


@user_is_authorized(Finding, Permissions.Finding_Edit, 'fid')
def endpoint_status_bulk_update(request, fid):
    if request.method == "POST":
        post = request.POST
        endpoints_to_update = post.getlist('endpoints_to_update')
        status_list = ['active', 'false_positive', 'mitigated', 'out_of_scope', 'risk_accepted']
        enable = [item for item in status_list if item in list(post.keys())]

        if endpoints_to_update and len(enable) > 0:
            endpoints = Endpoint.objects.filter(id__in=endpoints_to_update).order_by("endpoint_meta__product__id")
            for endpoint in endpoints:
                endpoint_status = Endpoint_Status.objects.get(
                    endpoint=endpoint,
                    finding__id=fid)
                for status in status_list:
                    if status in enable:
                        endpoint_status.__setattr__(status, True)
                        if status == 'mitigated':
                            endpoint_status.mitigated_by = request.user
                            endpoint_status.mitigated_time = timezone.now()
                    else:
                        endpoint_status.__setattr__(status, False)
                endpoint_status.last_modified = timezone.now()
                endpoint_status.save()
            messages.add_message(request,
                                    messages.SUCCESS,
                                    'Bulk edit of endpoints was successful. Check to make sure it is what you intended.',
                                    extra_tags='alert-success')
        else:
            messages.add_message(request,
                                    messages.ERROR,
                                    'Unable to process bulk update. Required fields were not selected.',
                                    extra_tags='alert-danger')
    return redirect(request, post['return_url'])


def prefetch_for_endpoints(endpoints):
    if isinstance(endpoints, QuerySet):
        endpoints = endpoints.prefetch_related('product', 'tags', 'product__tags')
        endpoints = endpoints.annotate(active_finding_count=Count('finding__id', filter=Q(finding__active=True)))
    else:
        logger.debug('unable to prefetch because query was already executed')

    return endpoints


def migrate_endpoints_view(request):

    view_name = 'Migrate endpoints'

    html_log = clean_hosts_run(apps=apps, change=(request.method == 'POST'))

    return render(
        request, 'dojo/migrate_endpoints.html', {
            'product_tab': None,
            "name": view_name,
            "html_log": html_log
        })


@user_is_authorized(Product, Permissions.Endpoint_Edit, 'pid')
def import_endpoint_meta(request, pid):
    product = get_object_or_404(Product, id=pid)
    form = ImportEndpointMetaForm()
    if request.method == 'POST':
        form = ImportEndpointMetaForm(request.POST, request.FILES)
        if form.is_valid():
            file = request.FILES.get('file', None)
            # Make sure size is not too large
            if file and is_scan_file_too_large(file):
                messages.add_message(
                    request,
                    messages.ERROR,
                    "Report file is too large. Maximum supported size is {} MB".format(settings.SCAN_FILE_MAX_SIZE),
                    extra_tags='alert-danger')

            create_endpoints = form.cleaned_data['create_endpoints']
            create_tags = form.cleaned_data['create_tags']
            create_dojo_meta = form.cleaned_data['create_dojo_meta']

            try:
                endpoint_meta_import(file, product, create_endpoints, create_tags, create_dojo_meta, origin='UI', request=request)
            except Exception as e:
                logger.exception(e)
                add_error_message_to_response('An exception error occurred during the report import:%s' % str(e))
            return HttpResponseRedirect(reverse('endpoint') + "?product=" + pid)

    add_breadcrumb(title="Endpoint Meta Importer", top_level=False, request=request)
    product_tab = Product_Tab(product, title="Endpoint Meta Importer", tab="endpoints")
    return render(request, 'dojo/endpoint_meta_importer.html', {
        'product_tab': product_tab,
        'form': form,
    })
