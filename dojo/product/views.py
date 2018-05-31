# #  product
import calendar as tcalendar
import logging
from collections import OrderedDict
from datetime import datetime, date, timedelta
from math import ceil
from dateutil.relativedelta import relativedelta
from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.core.exceptions import PermissionDenied
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import render, get_object_or_404
from django.contrib.contenttypes.models import ContentType
from django.utils import timezone
from django.db.models import Sum, Count
from dojo.filters import ProductFilter, ProductFindingFilter, EngagementFilter
from dojo.forms import ProductForm, EngForm, DeleteProductForm, ProductMetaDataForm, JIRAPKeyForm, JIRAFindingForm, AdHocFindingForm
from dojo.models import Product_Type, Finding, Product, Engagement, ScanSettings, Risk_Acceptance, Test, JIRA_PKey, Finding_Template, \
    Tool_Product_Settings, Cred_Mapping, Test_Type, System_Settings, Languages, App_Analysis, Benchmark_Type, Benchmark_Product_Summary, Endpoint
from dojo.utils import get_page_items, add_breadcrumb, get_punchcard_data, get_system_setting, create_notification, tab_view_count
from custom_field.models import CustomFieldValue, CustomField
from dojo.tasks import add_epic_task, add_issue_task
from tagging.models import Tag
from tagging.utils import get_tag_list

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
    """
    if 'tags' in request.GET:
        tags = request.GET.getlist('tags', [])
        initial_queryset = TaggedItem.objects.get_by_model(initial_queryset, Tag.objects.filter(name__in=tags))
    """
    prods = ProductFilter(request.GET, queryset=initial_queryset, user=request.user)
    prod_list = get_page_items(request, prods.qs, 25)
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

    result = EngagementFilter(
        request.GET,
        queryset=Engagement.objects.filter(product=prod, active=False).order_by('-target_end'))

    i_engs_page = get_page_items(request, result.qs, 10)

    scan_sets = ScanSettings.objects.filter(product=prod)
    tools = Tool_Product_Settings.objects.filter(product=prod).order_by('name')
    auth = request.user.is_staff or request.user in prod.authorized_users.all()
    creds = Cred_Mapping.objects.filter(product=prod).select_related('cred_id').order_by('cred_id')
    langSummary = Languages.objects.filter(product=prod).aggregate(Sum('files'), Sum('code'), Count('files'))
    languages = Languages.objects.filter(product=prod).order_by('-code')
    app_analysis = App_Analysis.objects.filter(product=prod).order_by('name')
    benchmark_type = Benchmark_Type.objects.filter(enabled=True).order_by('name')
    benchmarks = Benchmark_Product_Summary.objects.filter(product=prod, publish=True, benchmark_type__enabled=True).order_by('benchmark_type__name')
    system_settings = System_Settings.objects.get()

    if not auth:
        # will render 403
        raise PermissionDenied

    ct = ContentType.objects.get_for_model(prod)
    product_cf = CustomField.objects.filter(content_type=ct).order_by('name')
    product_metadata = {}

    for cf in product_cf:
        cfv = CustomFieldValue.objects.filter(field=cf, object_id=prod.id)
        if len(cfv):
            product_metadata[cf.name] = cfv[0].value

    try:
        start_date = Finding.objects.filter(test__engagement__product=prod).order_by('date')[:1][0].date
    except:
        start_date = timezone.now()

    end_date = timezone.now()

    tests = Test.objects.filter(engagement__product=prod)

    risk_acceptances = Risk_Acceptance.objects.filter(engagement__in=Engagement.objects.filter(product=prod))

    accepted_findings = [finding for ra in risk_acceptances
                         for finding in ra.accepted_findings.all()]

    verified_findings = Finding.objects.filter(test__engagement__product=prod,
                                                date__range=[start_date, end_date],
                                                false_p=False,
                                                verified=True,
                                                duplicate=False,
                                                out_of_scope=False).order_by('numerical_severity').values('severity').annotate(count=Count('severity'))

    critical = 0
    high = 0
    medium = 0
    low = 0
    info = 0

    for v in verified_findings:
        if v["severity"] == "Critical":
            critical = v["count"]
        elif v["severity"] == "High":
            high = v["count"]
        elif v["severity"] == "Medium":
            medium = v["count"]
        elif v["severity"] == "Low":
            low = v["count"]
        elif v["severity"] == "Info":
            info = v["count"]

    total = critical + high + medium + low + info

    tab_product, tab_engagements, tab_findings, tab_endpoints, tab_benchmarks = tab_view_count(pid)
    return render(request, 'dojo/view_product_details.html', {
                  'prod': prod,
                  'tab_product': tab_product,
                  'tab_engagements': tab_engagements,
                  'tab_findings': tab_findings,
                  'tab_endpoints': tab_endpoints,
                  'tab_benchmarks': tab_benchmarks,
                  'active_tab': 'overview',
                  'product_metadata': product_metadata,
                  'tools': tools,
                  'creds': creds,
                  'critical': critical,
                  'high': high,
                  'medium': medium,
                  'low': low,
                  'info': info,
                  'total': total,
                  'user': request.user,
                  'languages': languages,
                  'langSummary': langSummary,
                  'app_analysis': app_analysis,
                  'system_settings': system_settings,
                  'authorized': auth})


def view_product_metrics(request, pid):
    prod = get_object_or_404(Product, id=pid)
    engs = Engagement.objects.filter(product=prod, active=True)

    result = EngagementFilter(
        request.GET,
        queryset=Engagement.objects.filter(product=prod, active=False).order_by('-target_end'))

    i_engs_page = get_page_items(request, result.qs, 10)

    scan_sets = ScanSettings.objects.filter(product=prod)
    tools = Tool_Product_Settings.objects.filter(product=prod).order_by('name')
    auth = request.user.is_staff or request.user in prod.authorized_users.all()
    creds = Cred_Mapping.objects.filter(product=prod).select_related('cred_id').order_by('cred_id')
    langSummary = Languages.objects.filter(product=prod).aggregate(Sum('files'), Sum('code'), Count('files'))
    languages = Languages.objects.filter(product=prod).order_by('-code')
    app_analysis = App_Analysis.objects.filter(product=prod).order_by('name')
    benchmark_type = Benchmark_Type.objects.filter(enabled=True).order_by('name')
    benchmarks = Benchmark_Product_Summary.objects.filter(product=prod, publish=True, benchmark_type__enabled=True).order_by('benchmark_type__name')
    system_settings = System_Settings.objects.get()

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
        start_date = timezone.now()

    end_date = timezone.now()

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

    start_date = timezone.make_aware(datetime.combine(start_date, datetime.min.time()))

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

    tab_product, tab_engagements, tab_findings, tab_endpoints, tab_benchmarks = tab_view_count(pid)
    return render(request,
                  'dojo/product_metrics.html',
                  {'prod': prod,
                   'active_tab': 'metrics',
                   'tab_product': tab_product,
                   'tab_engagements': tab_engagements,
                   'tab_findings': tab_findings,
                   'tab_endpoints': tab_endpoints,
                   'tab_benchmarks': tab_benchmarks,
                   'benchmark_type': benchmark_type,
                   'benchmarks': benchmarks,
                   'product_metadata': product_metadata,
                   'engs': engs,
                   'i_engs': i_engs_page,
                   'scan_sets': scan_sets,
                   'tools': tools,
                   'creds': creds,
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
                   'languages': languages,
                   'langSummary': langSummary,
                   'app_analysis': app_analysis,
                   'system_settings': system_settings,
                   'authorized': auth})


def view_engagements(request, pid):
    prod = get_object_or_404(Product, id=pid)
    engs = Engagement.objects.filter(product=prod, active=True)

    result = EngagementFilter(
        request.GET,
        queryset=Engagement.objects.filter(product=prod, active=False).order_by('-target_end'))

    i_engs_page = get_page_items(request, result.qs, 10)

    scan_sets = ScanSettings.objects.filter(product=prod)
    tools = Tool_Product_Settings.objects.filter(product=prod).order_by('name')
    auth = request.user.is_staff or request.user in prod.authorized_users.all()
    creds = Cred_Mapping.objects.filter(product=prod).select_related('cred_id').order_by('cred_id')
    langSummary = Languages.objects.filter(product=prod).aggregate(Sum('files'), Sum('code'), Count('files'))
    languages = Languages.objects.filter(product=prod).order_by('-code')
    app_analysis = App_Analysis.objects.filter(product=prod).order_by('name')
    benchmark_type = Benchmark_Type.objects.filter(enabled=True).order_by('name')
    benchmarks = Benchmark_Product_Summary.objects.filter(product=prod, publish=True, benchmark_type__enabled=True).order_by('benchmark_type__name')
    system_settings = System_Settings.objects.get()

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
        start_date = timezone.now()

    end_date = timezone.now()

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

    start_date = timezone.make_aware(datetime.combine(start_date, datetime.min.time()))

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

    tab_product, tab_engagements, tab_findings, tab_endpoints, tab_benchmarks = tab_view_count(pid)

    return render(request,
                  'dojo/view_engagements.html',
                  {'prod': prod,
                   'active_tab': 'engagements',
                   'tab_product': tab_product,
                   'tab_engagements': tab_engagements,
                   'tab_findings': tab_findings,
                   'tab_endpoints': tab_endpoints,
                   'tab_benchmarks': tab_benchmarks,
                   'benchmark_type': benchmark_type,
                   'benchmarks': benchmarks,
                   'product_metadata': product_metadata,
                   'engs': engs,
                   'i_engs': i_engs_page,
                   'scan_sets': scan_sets,
                   'tools': tools,
                   'creds': creds,
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
                   'languages': languages,
                   'langSummary': langSummary,
                   'app_analysis': app_analysis,
                   'system_settings': system_settings,
                   'authorized': auth})


def view_product_details(request, pid):
    prod = get_object_or_404(Product, id=pid)
    scan_sets = ScanSettings.objects.filter(product=prod)
    tools = Tool_Product_Settings.objects.filter(product=prod).order_by('name')
    auth = request.user.is_staff or request.user in prod.authorized_users.all()
    creds = Cred_Mapping.objects.filter(product=prod).select_related('cred_id').order_by('cred_id')
    langSummary = Languages.objects.filter(product=prod).aggregate(Sum('files'), Sum('code'), Count('files'))
    languages = Languages.objects.filter(product=prod).order_by('-code')
    app_analysis = App_Analysis.objects.filter(product=prod).order_by('name')
    benchmark_type = Benchmark_Type.objects.filter(enabled=True).order_by('name')
    benchmarks = Benchmark_Product_Summary.objects.filter(product=prod, publish=True, benchmark_type__enabled=True).order_by('benchmark_type__name')
    system_settings = System_Settings.objects.get()

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

    add_breadcrumb(parent=product, title="Details", top_level=False, request=request)
    return render(request,
                  'dojo/view_product_details.html',
                  {'prod': prod,
                   'benchmark_type': benchmark_type,
                   'benchmarks': benchmarks,
                   'product_metadata': product_metadata,
                   'scan_sets': scan_sets,
                   'tools': tools,
                   'creds': creds,
                   'user': request.user,
                   'languages': languages,
                   'langSummary': langSummary,
                   'app_analysis': app_analysis,
                   'system_settings': system_settings,
                   'authorized': auth})


@user_passes_test(lambda u: u.is_staff)
def new_product(request):
    jform = None
    if request.method == 'POST':
        form = ProductForm(request.POST, instance=Product())
        if get_system_setting('enable_jira'):
                jform = JIRAPKeyForm(request.POST, instance=JIRA_PKey())
        else:
            jform = None

        if form.is_valid():
            product = form.save()
            tags = request.POST.getlist('tags')
            t = ", ".join(tags)
            product.tags = t
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Product added successfully.',
                                 extra_tags='alert-success')
            if get_system_setting('enable_jira'):
                    if jform.is_valid():
                        jira_pkey = jform.save(commit=False)
                        if jira_pkey.conf is not None:
                            jira_pkey.product = product
                            jira_pkey.save()
                            messages.add_message(request,
                                                 messages.SUCCESS,
                                                 'JIRA information added successfully.',
                                                 extra_tags='alert-success')
            create_notification(event='product_added', title=product.name, url=request.build_absolute_uri(reverse('view_product', args=(product.id,))))
            return HttpResponseRedirect(reverse('view_product', args=(product.id,)))
    else:
        form = ProductForm()
        if get_system_setting('enable_jira'):
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
    system_settings = System_Settings.objects.get()
    jira_enabled = system_settings.enable_jira
    jira_inst = None
    jform = None
    try:
        jira_inst = JIRA_PKey.objects.get(product=prod)
    except:
        jira_inst = None
        pass
    if request.method == 'POST':
        form = ProductForm(request.POST, instance=prod)
        if form.is_valid():
            form.save()
            tags = request.POST.getlist('tags')
            t = ", ".join(tags)
            prod.tags = t
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Product updated successfully.',
                                 extra_tags='alert-success')

            if get_system_setting('enable_jira') and jira_inst:
                jform = JIRAPKeyForm(request.POST, instance=jira_inst)
                # need to handle delete
                try:
                    jform.save()
                except:
                    pass
            elif get_system_setting('enable_jira'):
                jform = JIRAPKeyForm(request.POST)
                if jform.is_valid():
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
                           initial={'auth_users': prod.authorized_users.all(),
                                    'tags': get_tag_list(Tag.objects.get_for_object(prod))})

        if jira_enabled and (jira_inst is not None):
            if jira_inst is not None:
                jform = JIRAPKeyForm(instance=jira_inst)
            else:
                jform = JIRAPKeyForm()
        elif jira_enabled:
            jform = JIRAPKeyForm()
        else:
            jform = None
    form.initial['tags'] = [tag.name for tag in prod.tags]
    add_breadcrumb(parent=prod, title="Edit", top_level=False, request=request)

    return render(request,
                  'dojo/edit_product.html',
                  {'form': form,
                   'jform': jform,
                   'product': prod
                   })


@user_passes_test(lambda u: u.is_staff)
def delete_product(request, pid):
    product = get_object_or_404(Product, pk=pid)
    form = DeleteProductForm(instance=product)

    from django.contrib.admin.utils import NestedObjects
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
    system_settings = System_Settings.objects.get()
    tab_product, tab_engagements, tab_findings, tab_endpoints, tab_benchmarks = tab_view_count(pid)
    return render(request, 'dojo/delete_product.html',
                  {'product': product,
                   'form': form,
                   'tab_product': tab_product,
                   'tab_engagements': tab_engagements,
                   'tab_findings': tab_findings,
                   'tab_endpoints': tab_endpoints,
                   'tab_benchmarks': tab_benchmarks,
                   'active_tab': 'findings',
                   'system_settings': system_settings,
                   'rels': rels,
                   })


"""
Greg
Status: in production
"""


def all_product_findings(request, pid):
    p = get_object_or_404(Product, id=pid)
    auth = request.user.is_staff or request.user in p.authorized_users.all()
    if not auth:
        # will render 403
        raise PermissionDenied
    result = ProductFindingFilter(
        request.GET,
        queryset=Finding.objects.filter(test__engagement__product=p,
                                        active=True,
                                        verified=True))
    page = get_page_items(request, result.qs, 25)

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
    jform = None
    prod = Product.objects.get(id=pid)
    if request.method == 'POST':
        form = EngForm(request.POST)
        if form.is_valid():
            new_eng = form.save(commit=False)
            new_eng.threat_model = False
            new_eng.api_test = False
            new_eng.pen_test = False
            new_eng.check_list = False

            new_eng.product = prod
            if new_eng.threat_model:
                new_eng.progress = 'threat_model'
            else:
                new_eng.progress = 'other'

            new_eng.save()
            tags = request.POST.getlist('tags')
            t = ", ".join(tags)
            new_eng.tags = t
            if get_system_setting('enable_jira'):
                    # Test to make sure there is a Jira project associated the product
                    try:
                        jform = JIRAFindingForm(request.POST, prefix='jiraform', enabled=JIRA_PKey.objects.get(product=prod).push_all_issues)
                        if jform.is_valid():
                            add_epic_task.delay(new_eng, jform.cleaned_data.get('push_to_jira'))
                    except JIRA_PKey.DoesNotExist:
                        pass

            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Engagement added successfully.',
                                 extra_tags='alert-success')

            create_notification(event='engagement_added', title=new_eng.name + " for " + prod.name, engagement=new_eng, url=request.build_absolute_uri(reverse('view_engagement', args=(new_eng.id,))), objowner=new_eng.lead)

            if "_Add Tests" in request.POST:
                return HttpResponseRedirect(reverse('add_tests', args=(new_eng.id,)))
            else:
                return HttpResponseRedirect(reverse('view_engagement', args=(new_eng.id,)))
    else:
        form = EngForm(initial={'lead': request.user, 'target_start': timezone.now().date(), 'target_end': timezone.now().date() + timedelta(days=7)})
        if(get_system_setting('enable_jira')):
                if JIRA_PKey.objects.filter(product=prod).count() != 0:
                    jform = JIRAFindingForm(prefix='jiraform', enabled=JIRA_PKey.objects.get(product=prod).push_all_issues)

    add_breadcrumb(parent=prod, title="New Engagement", top_level=False, request=request)
    tab_product, tab_engagements, tab_findings, tab_endpoints, tab_benchmarks = tab_view_count(pid)
    system_settings = System_Settings.objects.get()
    return render(request, 'dojo/new_eng.html',
                  {'form': form, 'pid': pid,
                   'tab_product': tab_product,
                   'tab_engagements': tab_engagements,
                   'tab_findings': tab_findings,
                   'tab_endpoints': tab_endpoints,
                   'tab_benchmarks': tab_benchmarks,
                   'active_tab': 'engagements',
                   'system_settings': system_settings,
                   'jform': jform
                   })


@user_passes_test(lambda u: u.is_staff)
def add_meta_data(request, pid):
    prod = Product.objects.get(id=pid)
    ct = ContentType.objects.get_for_model(prod)
    if request.method == 'POST':
        form = ProductMetaDataForm(request.POST)
        if form.is_valid():
            cf, created = CustomField.objects.get_or_create(name=form.cleaned_data['name'], content_type=ct, field_type='a')
            cf.save()
            cfv, created = CustomFieldValue.objects.get_or_create(field=cf, object_id=prod.id)
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


@user_passes_test(lambda u: u.is_staff)
def ad_hoc_finding(request, pid):
    prod = Product.objects.get(id=pid)
    test = None
    try:
        eng = Engagement.objects.get(product=prod, name="Ad Hoc Engagement")
        tests = Test.objects.filter(engagement=eng)

        if len(tests) != 0:
            test = tests[0]
        else:
            test = Test(engagement=eng, test_type=Test_Type.objects.get(name="Pen Test"),
                        target_start=timezone.now(), target_end=timezone.now())
            test.save()
    except:
        eng = Engagement(name="Ad Hoc Engagement", target_start=timezone.now(),
                         target_end=timezone.now(), active=False, product=prod)
        eng.save()
        test = Test(engagement=eng, test_type=Test_Type.objects.get(name="Pen Test"),
                    target_start=timezone.now(), target_end=timezone.now())
        test.save()
    form_error = False
    enabled = False
    jform = None
    form = AdHocFindingForm(initial={'date': timezone.now().date()})
    if get_system_setting('enable_jira'):
            if JIRA_PKey.objects.filter(product=test.engagement.product).count() != 0:
                enabled = JIRA_PKey.objects.get(product=test.engagement.product).push_all_issues
                jform = JIRAFindingForm(enabled=enabled, prefix='jiraform')
    else:
        jform = None
    if request.method == 'POST':
        form = AdHocFindingForm(request.POST)
        if form.is_valid():
            new_finding = form.save(commit=False)
            new_finding.test = test
            new_finding.reporter = request.user
            new_finding.numerical_severity = Finding.get_numerical_severity(
                new_finding.severity)
            if new_finding.false_p or new_finding.active is False:
                new_finding.mitigated = timezone.now()
                new_finding.mitigated_by = request.user
            create_template = new_finding.is_template
            # always false now since this will be deprecated soon in favor of new Finding_Template model
            new_finding.is_template = False
            new_finding.save()
            new_finding.endpoints = form.cleaned_data['endpoints']
            new_finding.save()
            if 'jiraform-push_to_jira' in request.POST:
                jform = JIRAFindingForm(request.POST, prefix='jiraform', enabled=enabled)
                if jform.is_valid():
                    add_issue_task.delay(new_finding, jform.cleaned_data.get('push_to_jira'))
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'Finding added successfully.',
                                     extra_tags='alert-success')
            if create_template:
                templates = Finding_Template.objects.filter(title=new_finding.title)
                if len(templates) > 0:
                    messages.add_message(request,
                                         messages.ERROR,
                                         'A finding template was not created.  A template with this title already '
                                         'exists.',
                                         extra_tags='alert-danger')
                else:
                    template = Finding_Template(title=new_finding.title,
                                                cwe=new_finding.cwe,
                                                severity=new_finding.severity,
                                                description=new_finding.description,
                                                mitigation=new_finding.mitigation,
                                                impact=new_finding.impact,
                                                references=new_finding.references,
                                                numerical_severity=new_finding.numerical_severity)
                    template.save()
                    messages.add_message(request,
                                         messages.SUCCESS,
                                         'A finding template was also created.',
                                         extra_tags='alert-success')
            if '_Finished' in request.POST:
                return HttpResponseRedirect(reverse('view_test', args=(test.id,)))
            else:
                return HttpResponseRedirect(reverse('add_findings', args=(test.id,)))
        else:
            if 'endpoints' in form.cleaned_data:
                form.fields['endpoints'].queryset = form.cleaned_data['endpoints']
            else:
                form.fields['endpoints'].queryset = Endpoint.objects.none()
            form_error = True
            messages.add_message(request,
                                 messages.ERROR,
                                 'The form has errors, please correct them below.',
                                 extra_tags='alert-danger')
    add_breadcrumb(parent=prod, title="Add Finding", top_level=False, request=request)
    system_settings = System_Settings.objects.get()
    tab_product, tab_engagements, tab_findings, tab_endpoints, tab_benchmarks = tab_view_count(pid)
    return render(request, 'dojo/ad_hoc_findings.html',
                  {'form': form,
                   'tab_product': tab_product,
                   'tab_engagements': tab_engagements,
                   'tab_findings': tab_findings,
                   'tab_endpoints': tab_endpoints,
                   'tab_benchmarks': tab_benchmarks,
                   'active_tab': 'findings',
                   'system_settings': system_settings,
                   'temp': False,
                   'tid': test.id,
                   'pid': pid,
                   'form_error': form_error,
                   'jform': jform,
                   })
