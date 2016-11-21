# #  product
import calendar as tcalendar
import logging
import sys
from collections import OrderedDict
from datetime import datetime, date, timedelta
from math import ceil

from dateutil.relativedelta import relativedelta
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.core.exceptions import PermissionDenied
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import render, get_object_or_404
from django.contrib.contenttypes.models import ContentType
from pytz import timezone

from dojo.filters import ProductFilter, ProductFindingFilter
from dojo.forms import ProductForm, EngForm, DeleteProductForm, ProductMetaDataForm, JIRAPKeyForm, JIRAFindingForm
from dojo.models import Product_Type, Finding, Product, Engagement, ScanSettings, Risk_Acceptance, Test, JIRA_PKey
from dojo.utils import get_page_items, add_breadcrumb, get_punchcard_data
from custom_field.models import CustomFieldValue, CustomField
from  dojo.tasks import add_epic_task

localtz = timezone(settings.TIME_ZONE)

logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)d] %(message)s',
    datefmt='%d/%b/%Y %H:%M:%S',
    filename=settings.DOJO_ROOT + '/../django_app.log',
)
logger = logging.getLogger(__name__)


def product(request):
    if request.user.is_staff:
        initial_queryset = Product.objects.all()
        name_words = [product.name for product in
                      Product.objects.all()]
    else:
        initial_queryset = Product.objects.filter(
            authorized_users__in=[request.user])
        name_words = [word for product in
                      Product.objects.filter(
                          authorized_users__in=[request.user])
                      for word in product.name.split() if len(word) > 2]

    product_type = None
    if 'prod_type' in request.GET:
        p = request.GET.getlist('prod_type', [])
        if len(p) == 1:
            product_type = get_object_or_404(Product_Type, id=p[0])

    prods = ProductFilter(request.GET, queryset=initial_queryset, user=request.user)
    prod_list = get_page_items(request, prods, 25)
    add_breadcrumb(title="Product List", top_level=not len(request.GET), request=request)
    return render(request,
                  'dojo/product.html',
                  {'prod_list': prod_list,
                   'prods': prods,
                   'name_words': sorted(set(name_words)),
                   'user': request.user})


def iso_to_gregorian(iso_year, iso_week, iso_day):
    jan4 = date(iso_year, 1, 4)
    start = jan4 - timedelta(days=jan4.isoweekday() - 1)
    return start + timedelta(weeks=iso_week - 1, days=iso_day - 1)


def view_product(request, pid):
    prod = get_object_or_404(Product, id=pid)
    engs = Engagement.objects.filter(product=prod, active=True)
    i_engs = Engagement.objects.filter(product=prod, active=False)
    scan_sets = ScanSettings.objects.filter(product=prod)
    auth = request.user.is_staff or request.user in prod.authorized_users.all()
    if not auth:
        # will render 403
        raise PermissionDenied

    ct = ContentType.objects.get_for_model(prod)
    product_cf = CustomField.objects.filter(content_type=ct)
    product_metadata = {}

    for cf in product_cf:
        cfv = CustomFieldValue.objects.filter(field=cf, object_id=prod.id)
        if len(cfv):
            product_metadata[cf.name] = cfv[0].value

    try:
        start_date = Finding.objects.filter(test__engagement__product=prod).order_by('date')[:1][0].date
    except:
        start_date = localtz.localize(datetime.today())

    end_date = localtz.localize(datetime.today())

    tests = Test.objects.filter(engagement__product=prod)

    risk_acceptances = Risk_Acceptance.objects.filter(engagement__in=Engagement.objects.filter(product=prod))

    accepted_findings = [finding for ra in risk_acceptances
                         for finding in ra.accepted_findings.all()]

    verified_findings = Finding.objects.filter(test__engagement__product=prod,
                                               date__range=[start_date, end_date],
                                               false_p=False,
                                               verified=True,
                                               duplicate=False,
                                               out_of_scope=False).order_by("date")

    week_date = end_date - timedelta(days=7)  # seven days and /newnewer are considered "new"

    new_verified_findings = Finding.objects.filter(test__engagement__product=prod,
                                                   date__range=[week_date, end_date],
                                                   false_p=False,
                                                   verified=True,
                                                   duplicate=False,
                                                   out_of_scope=False).order_by("date")

    open_findings = Finding.objects.filter(test__engagement__product=prod,
                                           date__range=[start_date, end_date],
                                           false_p=False,
                                           verified=True,
                                           duplicate=False,
                                           out_of_scope=False,
                                           active=True,
                                           mitigated__isnull=True)

    closed_findings = Finding.objects.filter(test__engagement__product=prod,
                                             date__range=[start_date, end_date],
                                             false_p=False,
                                             verified=True,
                                             duplicate=False,
                                             out_of_scope=False,
                                             mitigated__isnull=False)

    start_date = localtz.localize(datetime.combine(start_date, datetime.min.time()))

    r = relativedelta(end_date, start_date)
    weeks_between = int(ceil((((r.years * 12) + r.months) * 4.33) + (r.days / 7)))
    if weeks_between <= 0:
        weeks_between += 2

    punchcard, ticks, highest_count = get_punchcard_data(verified_findings, weeks_between, start_date)
    add_breadcrumb(parent=prod, top_level=False, request=request)

    open_close_weekly = OrderedDict()
    new_weekly = OrderedDict()
    severity_weekly = OrderedDict()
    critical_weekly = OrderedDict()
    high_weekly = OrderedDict()
    medium_weekly = OrderedDict()

    for v in verified_findings:
        iso_cal = v.date.isocalendar()
        x = iso_to_gregorian(iso_cal[0], iso_cal[1], 1)
        y = x.strftime("<span class='small'>%m/%d<br/>%Y</span>")
        x = (tcalendar.timegm(x.timetuple()) * 1000)
        if x not in critical_weekly:
            critical_weekly[x] = {'count': 0, 'week': y}
        if x not in high_weekly:
            high_weekly[x] = {'count': 0, 'week': y}
        if x not in medium_weekly:
            medium_weekly[x] = {'count': 0, 'week': y}

        if x in open_close_weekly:
            if v.mitigated:
                open_close_weekly[x]['closed'] += 1
            else:
                open_close_weekly[x]['open'] += 1
        else:

            if v.mitigated:
                open_close_weekly[x] = {'closed': 1, 'open': 0, 'accepted': 0}
            else:
                open_close_weekly[x] = {'closed': 0, 'open': 1, 'accepted': 0}
            open_close_weekly[x]['week'] = y

        if x in severity_weekly:
            if v.severity in severity_weekly[x]:
                severity_weekly[x][v.severity] += 1
            else:
                severity_weekly[x][v.severity] = 1
        else:
            severity_weekly[x] = {'Critical': 0, 'High': 0,
                                  'Medium': 0, 'Low': 0, 'Info': 0}
            severity_weekly[x][v.severity] = 1
            severity_weekly[x]['week'] = y

        if v.severity == 'Critical':
            if x in critical_weekly:
                critical_weekly[x]['count'] += 1
            else:
                critical_weekly[x] = {'count': 1, 'week': y}
        elif v.severity == 'High':
            if x in high_weekly:
                high_weekly[x]['count'] += 1
            else:
                high_weekly[x] = {'count': 1, 'week': y}
        elif v.severity == 'Medium':
            if x in medium_weekly:
                medium_weekly[x]['count'] += 1
            else:
                medium_weekly[x] = {'count': 1, 'week': y}

    for a in accepted_findings:
        iso_cal = a.date.isocalendar()
        x = iso_to_gregorian(iso_cal[0], iso_cal[1], 1)
        y = x.strftime("<span class='small'>%m/%d<br/>%Y</span>")
        x = (tcalendar.timegm(x.timetuple()) * 1000)

        if x in open_close_weekly:
            open_close_weekly[x]['accepted'] += 1
        else:
            open_close_weekly[x] = {'closed': 0, 'open': 0, 'accepted': 1}
            open_close_weekly[x]['week'] = y

    test_data = {}
    for t in tests:
        if t.test_type.name in test_data:
            test_data[t.test_type.name] += t.verified_finding_count()
        else:
            test_data[t.test_type.name] = t.verified_finding_count()

    return render(request,
                  'dojo/view_product.html',
                  {'prod': prod,
                   'product_metadata': product_metadata,
                   'engs': engs,
                   'i_engs': i_engs,
                   'scan_sets': scan_sets,
                   'verified_findings': verified_findings,
                   'open_findings': open_findings,
                   'closed_findings': closed_findings,
                   'accepted_findings': accepted_findings,
                   'new_findings': new_verified_findings,
                   'start_date': start_date,
                   'punchcard': punchcard,
                   'ticks': ticks,
                   'highest_count': highest_count,
                   'open_close_weekly': open_close_weekly,
                   'severity_weekly': severity_weekly,
                   'critical_weekly': critical_weekly,
                   'high_weekly': high_weekly,
                   'medium_weekly': medium_weekly,
                   'test_data': test_data,
                   'user': request.user,
                   'authorized': auth})


@user_passes_test(lambda u: u.is_staff)
def new_product(request):
    if request.method == 'POST':
        form = ProductForm(request.POST, instance=Product())
        if hasattr(settings, 'ENABLE_JIRA'):
            if settings.ENABLE_JIRA:
                jform = JIRAPKeyForm(request.POST, instance=JIRA_PKey())
        if form.is_valid():
            product = form.save()
            tags = form.cleaned_data['tags']
            product.tags = tags
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Product added successfully.',
                                 extra_tags='alert-success')
            if hasattr(settings, 'ENABLE_JIRA'):
                if settings.ENABLE_JIRA:
                    if jform.is_valid():
                        jira_pkey = jform.save(commit=False)
                        if jira_pkey.conf is not None:
                            jira_pkey.product = product
                            jira_pkey.save()
                            messages.add_message(request,
                                                 messages.SUCCESS,
                                                 'JIRA information added successfully.',
                                                 extra_tags='alert-success')

            return HttpResponseRedirect(reverse('view_product', args=(product.id,)))
    else:
        form = ProductForm()
        if hasattr(settings, 'ENABLE_JIRA'):
            if settings.ENABLE_JIRA:
                jform = JIRAPKeyForm()
        else:
            jform = None
    add_breadcrumb(title="New Product", top_level=False, request=request)
    return render(request, 'dojo/new_product.html',
                  {'form': form,
                   'jform': jform})


@user_passes_test(lambda u: u.is_staff)
def edit_product(request, pid):
    prod = Product.objects.get(pk=pid)
    jira_enabled = True
    jira_inst = None
    try:
        jira_inst = JIRA_PKey.objects.get(product=prod)
    except:
        jira_enabled = False
        pass
    if request.method == 'POST':
        form = ProductForm(request.POST, instance=prod)
        if form.is_valid():
            form.save()
            tags = form.cleaned_data['tags']
            prod.tags = tags
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Product updated successfully.',
                                 extra_tags='alert-success')
            if hasattr(settings, 'ENABLE_JIRA'):
                if settings.ENABLE_JIRA:
                    if jira_enabled:
                        jform = JIRAPKeyForm(request.POST, instance=jira_inst)
                    else:
                        jform = JIRAPKeyForm(request.POST)
                        new_conf = jform.save(commit=False)
                        new_conf.product_id = pid
                        new_conf.save()
                        messages.add_message(request,
                                             messages.SUCCESS,
                                             'JIRA information updated successfully.',
                                             extra_tags='alert-success')

            return HttpResponseRedirect(reverse('view_product', args=(pid,)))
    else:
        form = ProductForm(instance=prod,
                           initial={'auth_users': prod.authorized_users.all()})
        form.initial['tags'] = ", ".join([tag.name for tag in prod.tags])
        if hasattr(settings, 'ENABLE_JIRA'):
            if settings.ENABLE_JIRA:
                if jira_enabled:
                    jform = JIRAPKeyForm(instance=jira_inst)
                else:
                    jform = JIRAPKeyForm()
        else:
            jform = None
    add_breadcrumb(parent=prod, title="Edit", top_level=False, request=request)

    return render(request,
                  'dojo/edit_product.html',
                  {'form': form,
                   'jform': jform,
                   'product': prod,
                   })


@user_passes_test(lambda u: u.is_staff)
def delete_product(request, pid):
    product = get_object_or_404(Product, pk=pid)
    form = DeleteProductForm(instance=product)

    from django.contrib.admin.util import NestedObjects
    from django.db import DEFAULT_DB_ALIAS

    collector = NestedObjects(using=DEFAULT_DB_ALIAS)
    collector.collect([product])
    rels = collector.nested()

    if request.method == 'POST':
        if 'id' in request.POST and str(product.id) == request.POST['id']:
            form = DeleteProductForm(request.POST, instance=product)
            if form.is_valid():
                if product.tags:
                    del product.tags
                product.delete()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'Product and relationships removed.',
                                     extra_tags='alert-success')
                return HttpResponseRedirect(reverse('product'))

    add_breadcrumb(parent=product, title="Delete", top_level=False, request=request)

    return render(request, 'dojo/delete_product.html',
                  {'product': product,
                   'form': form,
                   'rels': rels,
                   })


"""
Greg
Status: in production
"""


def all_product_findings(request, pid):
    p = get_object_or_404(Product, id=pid)
    result = ProductFindingFilter(
        request.GET,
        queryset=Finding.objects.filter(test__engagement__product=p,
                                        active=True,
                                        verified=True))
    page = get_page_items(request, result, 25)

    add_breadcrumb(title="Open findings", top_level=False, request=request)

    return render(request,
                  "dojo/all_product_findings.html",
                  {"findings": page,
                   "product": p,
                   "filtered": result,
                   "user": request.user,
                   })


@user_passes_test(lambda u: u.is_staff)
def new_eng_for_app(request, pid):
    prod = Product.objects.get(id=pid)
    if request.method == 'POST':
        form = EngForm(request.POST)
        if form.is_valid():
            new_eng = form.save(commit=False)
            new_eng.product = prod
            if new_eng.threat_model:
                new_eng.progress = 'threat_model'
            else:
                new_eng.progress = 'other'
            new_eng.save()
            #if 'jiraform' in request.POST:
            jform = JIRAFindingForm(request.POST, prefix='jiraform',
                                    enabled=JIRA_PKey.objects.get(product=prod).push_all_issues)
            if jform.is_valid():
                print >>sys.stderr, 'jira form is valid'
                add_epic_task.delay(new_eng, jform.cleaned_data.get('push_to_jira'))
            else:
                print >>sys.stderr, 'jira form is NOT valid'
            #else:
            #    print >>sys.stderr, 'no prefix is found'

            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Engagement added successfully.',
                                 extra_tags='alert-success')
            if "_Add Tests" in request.POST:
                return HttpResponseRedirect(reverse('add_tests', args=(new_eng.id,)))
            else:
                return HttpResponseRedirect(reverse('view_engagement', args=(new_eng.id,)))
    else:
        form = EngForm(initial={})
        if hasattr(settings, 'ENABLE_JIRA'):
            if settings.ENABLE_JIRA:
                if JIRA_PKey.objects.filter(product=prod).count() != 0:
                    jform = JIRAFindingForm(prefix='jiraform', enabled=JIRA_PKey.objects.get(product=prod).push_all_issues)

    add_breadcrumb(parent=prod, title="New Engagement", top_level=False, request=request)

    return render(request, 'dojo/new_eng.html',
                  {'form': form, 'pid': pid,
                   'jform': jform
                   })


@user_passes_test(lambda u: u.is_staff)
def add_meta_data(request, pid):
    prod = Product.objects.get(id=pid)
    ct = ContentType.objects.get_for_model(prod)
    if request.method == 'POST':
        form = ProductMetaDataForm(request.POST)
        if form.is_valid():
            cf, created = CustomField.objects.get_or_create(name=form.cleaned_data['name'],
                                                   content_type=ct,
                                                   field_type='a')
            cf.save()
            cfv, created = CustomFieldValue.objects.get_or_create(field=cf,
                                                         object_id=prod.id)
            cfv.value = form.cleaned_data['value']
            cfv.clean()
            cfv.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Metadata added successfully.',
                                 extra_tags='alert-success')
            if 'add_another' in request.POST:
                return HttpResponseRedirect(reverse('add_meta_data', args=(pid,)))
            else:
                return HttpResponseRedirect(reverse('view_product', args=(pid,)))
    else:
        form = ProductMetaDataForm(initial={'content_type': prod})

    add_breadcrumb(parent=prod, title="Add Metadata", top_level=False, request=request)

    return render(request,
                  'dojo/add_product_meta_data.html',
                  {'form': form,
                   'product': prod,
                   })


@user_passes_test(lambda u: u.is_staff)
def edit_meta_data(request, pid):
    prod = Product.objects.get(id=pid)
    ct = ContentType.objects.get_for_model(prod)

    product_cf = CustomField.objects.filter(content_type=ct)
    product_metadata = {}

    for cf in product_cf:
        cfv = CustomFieldValue.objects.filter(field=cf, object_id=prod.id)
        if len(cfv):
            product_metadata[cf] = cfv[0]

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
        return HttpResponseRedirect(reverse('view_product', args=(pid,)))

    add_breadcrumb(parent=prod, title="Edit Metadata", top_level=False, request=request)

    return render(request,
                  'dojo/edit_product_meta_data.html',
                  {'product': prod,
                   'product_metadata': product_metadata,
                   })
