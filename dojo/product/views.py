# #  product
import calendar as tcalendar
import logging
from collections import OrderedDict
from datetime import datetime, date, timedelta
from math import ceil
from dateutil.relativedelta import relativedelta
from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.core.exceptions import PermissionDenied, ValidationError
from django.urls import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import render, get_object_or_404
from django.contrib.contenttypes.models import ContentType
from django.utils import timezone
from django.db.models import Sum, Count, Q, Max
from django.contrib.admin.utils import NestedObjects
from django.db import DEFAULT_DB_ALIAS
from dojo.templatetags.display_tags import get_level
from dojo.filters import ProductFilter, ProductFindingFilter, EngagementFilter
from dojo.forms import ProductForm, EngForm, DeleteProductForm, DojoMetaDataForm, JIRAPKeyForm, JIRAFindingForm, AdHocFindingForm, \
                       EngagementPresetsForm, DeleteEngagementPresetsForm, Sonarqube_ProductForm
from dojo.models import Product_Type, Note_Type, Finding, Product, Engagement, ScanSettings, Risk_Acceptance, Test, JIRA_PKey, Finding_Template, \
    Tool_Product_Settings, Cred_Mapping, Test_Type, System_Settings, Languages, App_Analysis, Benchmark_Type, Benchmark_Product_Summary, \
    Endpoint, Engagement_Presets, DojoMeta, Sonarqube_Product
from dojo.utils import get_page_items, add_breadcrumb, get_system_setting, create_notification, Product_Tab, get_punchcard_data
from custom_field.models import CustomFieldValue, CustomField
from dojo.tasks import add_epic_task, add_issue_task
from tagging.models import Tag
from tagging.utils import get_tag_list
from django.db.models import Prefetch
from django.db.models.query import QuerySet

logger = logging.getLogger(__name__)


def product(request):
    # validate prod_type param
    product_type = None
    if 'prod_type' in request.GET:
        p = request.GET.getlist('prod_type', [])
        if len(p) == 1:
            product_type = get_object_or_404(Product_Type, id=p[0])

    prods = Product.objects.all()

    if not request.user.is_staff:
        prods = prods.filter(authorized_users__in=[request.user])

    # perform all stuff for filtering and pagination first, before annotation/prefetching
    # otherwise the paginator will perform all the annotations/prefetching already only to count the total number of records
    # see https://code.djangoproject.com/ticket/23771 and https://code.djangoproject.com/ticket/25375
    name_words = [product.name for product in prods
                    for word in product.name.split() if len(word) > 2]

    prod_filter = ProductFilter(request.GET, queryset=prods, user=request.user)
    prod_list = get_page_items(request, prod_filter.qs, 25)

    # perform annotation/prefetching by replacing the queryset in the page with an annotated/prefetched queryset.
    prod_list.object_list = prefetch_for_product(prod_list.object_list)

    """
    if 'tags' in request.GET:
        tags = request.GET.getlist('tags', [])
        initial_queryset = TaggedItem.objects.get_by_model(initial_queryset, Tag.objects.filter(name__in=tags))
    """

    add_breadcrumb(title="Product List", top_level=not len(request.GET), request=request)
    return render(request,
                  'dojo/product.html',
                  {'prod_list': prod_list,
                   'prod_filter': prod_filter,
                   'name_words': sorted(set(name_words)),
                   'user': request.user})


def prefetch_for_product(prods):
    prefetched_prods = prods
    if isinstance(prods, QuerySet):  # old code can arrive here with prods being a list because the query was already executed
        prefetched_prods = prefetched_prods.select_related('technical_contact').select_related('product_manager').select_related('prod_type').select_related('team_manager')
        prefetched_prods = prefetched_prods.annotate(active_engagement_count=Count('engagement__id', filter=Q(engagement__active=True)))
        prefetched_prods = prefetched_prods.annotate(closed_engagement_count=Count('engagement__id', filter=Q(engagement__active=False)))
        prefetched_prods = prefetched_prods.annotate(last_engagement_date=Max('engagement__target_start'))
        prefetched_prods = prefetched_prods.annotate(active_finding_count=Count('engagement__test__finding__id', filter=Q(engagement__test__finding__active=True)))
        prefetched_prods = prefetched_prods.prefetch_related(Prefetch('jira_pkey_set', queryset=JIRA_PKey.objects.all().select_related('conf'), to_attr='jira_confs'))
        active_endpoint_query = Endpoint.objects.filter(
                finding__active=True,
                finding__verified=True,
                finding__mitigated__isnull=True)
        prefetched_prods = prefetched_prods.prefetch_related(Prefetch('endpoint_set', queryset=active_endpoint_query, to_attr='active_endpoints'))

    return prefetched_prods


def iso_to_gregorian(iso_year, iso_week, iso_day):
    jan4 = date(iso_year, 1, 4)
    start = jan4 - timedelta(days=jan4.isoweekday() - 1)
    return start + timedelta(weeks=iso_week - 1, days=iso_day - 1)


def view_product(request, pid):
    prod = get_object_or_404(Product, id=pid)
    auth = request.user.is_staff or request.user in prod.authorized_users.all()
    if not auth:
        # will render 403
        raise PermissionDenied
    langSummary = Languages.objects.filter(product=prod).aggregate(Sum('files'), Sum('code'), Count('files'))
    languages = Languages.objects.filter(product=prod).order_by('-code')
    app_analysis = App_Analysis.objects.filter(product=prod).order_by('name')
    benchmark_type = Benchmark_Type.objects.filter(enabled=True).order_by('name')
    benchmarks = Benchmark_Product_Summary.objects.filter(product=prod, publish=True, benchmark_type__enabled=True).order_by('benchmark_type__name')
    benchAndPercent = []
    for i in range(0, len(benchmarks)):
        benchAndPercent.append([benchmarks[i].benchmark_type, get_level(benchmarks[i])])

    system_settings = System_Settings.objects.get()

    product_metadata = dict(prod.product_meta.order_by('name').values_list('name', 'value'))

    open_findings = Finding.objects.filter(test__engagement__product=prod,
                                                false_p=False,
                                                active=True,
                                                duplicate=False,
                                                out_of_scope=False).order_by('numerical_severity').values('severity').annotate(count=Count('severity'))

    critical = 0
    high = 0
    medium = 0
    low = 0
    info = 0

    for v in open_findings:
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

    product_tab = Product_Tab(pid, title="Product", tab="overview")
    return render(request, 'dojo/view_product_details.html', {
                  'prod': prod,
                  'product_tab': product_tab,
                  'product_metadata': product_metadata,
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
                  'benchmarks_percents': benchAndPercent,
                  'benchmarks': benchmarks,
                  'authorized': auth})


def view_product_metrics(request, pid):
    prod = get_object_or_404(Product, id=pid)
    engs = Engagement.objects.filter(product=prod, active=True)

    result = EngagementFilter(
        request.GET,
        queryset=Engagement.objects.filter(product=prod, active=False).order_by('-target_end'))

    i_engs_page = get_page_items(request, result.qs, 10)

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
        start_date = timezone.now()

    end_date = timezone.now()

    tests = Test.objects.filter(engagement__product=prod).prefetch_related('finding_set')

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
                                                   active=True,
                                                   duplicate=False,
                                                   out_of_scope=False).order_by("date")

    open_findings = Finding.objects.filter(test__engagement__product=prod,
                                           date__range=[start_date, end_date],
                                           false_p=False,
                                           duplicate=False,
                                           out_of_scope=False,
                                           active=True,
                                           verified=False,
                                           mitigated__isnull=True)

    inactive_findings = Finding.objects.filter(test__engagement__product=prod,
                                           date__range=[start_date, end_date],
                                           false_p=False,
                                           duplicate=False,
                                           out_of_scope=False,
                                           active=False,
                                           mitigated__isnull=True)

    closed_findings = Finding.objects.filter(test__engagement__product=prod,
                                             date__range=[start_date, end_date],
                                             false_p=False,
                                             verified=False,
                                             duplicate=False,
                                             out_of_scope=False,
                                             active=False,
                                             mitigated__isnull=False)

    false_positive_findings = Finding.objects.filter(test__engagement__product=prod,
                                             date__range=[start_date, end_date],
                                             false_p=True,
                                             verified=False,
                                             duplicate=False,
                                             out_of_scope=False)

    out_of_scope_findings = Finding.objects.filter(test__engagement__product=prod,
                                             date__range=[start_date, end_date],
                                             duplicate=False,
                                             out_of_scope=True)

    open_vulnerabilities = Finding.objects.filter(
        test__engagement__product=prod,
        false_p=False,
        verified=False,
        duplicate=False,
        out_of_scope=False,
        active=True,
        mitigated__isnull=True,
        cwe__isnull=False,
    ).order_by('cwe').values(
        'cwe'
    ).annotate(
        count=Count('cwe')
    )

    all_vulnerabilities = Finding.objects.filter(
        test__engagement__product=prod,
        duplicate=False,
        cwe__isnull=False,
    ).order_by('cwe').values(
        'cwe'
    ).annotate(
        count=Count('cwe')
    )

    start_date = timezone.make_aware(datetime.combine(start_date, datetime.min.time()))
    r = relativedelta(end_date, start_date)
    weeks_between = int(ceil((((r.years * 12) + r.months) * 4.33) + (r.days / 7)))
    if weeks_between <= 0:
        weeks_between += 2

    punchcard, ticks = get_punchcard_data(open_findings, start_date, weeks_between)

    add_breadcrumb(parent=prod, top_level=False, request=request)

    open_close_weekly = OrderedDict()
    new_weekly = OrderedDict()
    severity_weekly = OrderedDict()
    critical_weekly = OrderedDict()
    high_weekly = OrderedDict()
    medium_weekly = OrderedDict()

    for v in open_findings:
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

    product_tab = Product_Tab(pid, title="Product", tab="metrics")
    return render(request,
                  'dojo/product_metrics.html',
                  {'prod': prod,
                   'product_tab': product_tab,
                   'product_metadata': product_metadata,
                   'engs': engs,
                   'i_engs': i_engs_page,
                   'scan_sets': scan_sets,
                   'verified_findings': verified_findings,
                   'open_findings': open_findings,
                   'inactive_findings': inactive_findings,
                   'closed_findings': closed_findings,
                   'false_positive_findings': false_positive_findings,
                   'out_of_scope_findings': out_of_scope_findings,
                   'accepted_findings': accepted_findings,
                   'new_findings': new_verified_findings,
                   'open_vulnerabilities': open_vulnerabilities,
                   'all_vulnerabilities': all_vulnerabilities,
                   'start_date': start_date,
                   'punchcard': punchcard,
                   'ticks': ticks,
                   'open_close_weekly': open_close_weekly,
                   'severity_weekly': severity_weekly,
                   'critical_weekly': critical_weekly,
                   'high_weekly': high_weekly,
                   'medium_weekly': medium_weekly,
                   'test_data': test_data,
                   'user': request.user,
                   'authorized': auth})


def view_engagements(request, pid, engagement_type="Interactive"):
    prod = get_object_or_404(Product, id=pid)
    auth = request.user.is_staff or request.user in prod.authorized_users.all()
    if not auth:
        raise PermissionDenied

    default_page_num = 10

    # In Progress Engagements
    engs = Engagement.objects.filter(product=prod, active=True, status="In Progress", engagement_type=engagement_type).order_by('-updated')
    active_engs = EngagementFilter(request.GET, queryset=engs)
    result_active_engs = get_page_items(request, active_engs.qs, default_page_num, param_name="engs")
    # prefetch only after creating the filters to avoid https://code.djangoproject.com/ticket/23771 and https://code.djangoproject.com/ticket/25375
    result_active_engs.object_list = prefetch_for_view_engagements(result_active_engs.object_list)

    # Engagements that are queued because they haven't started or paused
    engs = Engagement.objects.filter(~Q(status="In Progress"), product=prod, active=True, engagement_type=engagement_type).order_by('-updated')
    queued_engs = EngagementFilter(request.GET, queryset=engs)
    result_queued_engs = get_page_items(request, queued_engs.qs, default_page_num, param_name="queued_engs")
    result_queued_engs.object_list = prefetch_for_view_engagements(result_queued_engs.object_list)

    # Cancelled or Completed Engagements
    engs = Engagement.objects.filter(product=prod, active=False, engagement_type=engagement_type).order_by('-target_end')
    result_inactive = EngagementFilter(request.GET, queryset=engs)
    result_inactive_engs_page = get_page_items(request, result_inactive.qs, default_page_num, param_name="i_engs")
    result_inactive_engs_page.object_list = prefetch_for_view_engagements(result_inactive_engs_page.object_list)

    title = "All Engagements"
    if engagement_type == "CI/CD":
        title = "CI/CD Engagements"

    product_tab = Product_Tab(pid, title=title, tab="engagements")
    return render(request,
                  'dojo/view_engagements.html',
                  {'prod': prod,
                   'product_tab': product_tab,
                   'engagement_type': engagement_type,
                   'engs': result_active_engs,
                   'engs_count': result_active_engs.paginator.count,
                   'queued_engs': result_queued_engs,
                   'queued_engs_count': result_queued_engs.paginator.count,
                   'i_engs': result_inactive_engs_page,
                   'i_engs_count': result_inactive_engs_page.paginator.count,
                   'user': request.user,
                   'authorized': auth})


def prefetch_for_view_engagements(engs):
    prefetched_engs = engs.prefetch_related('test_set')
    prefetched_engs = prefetched_engs.annotate(count_findings_all=Count('test__finding__id'))
    prefetched_engs = prefetched_engs.annotate(count_findings_open=Count('test__finding__id', filter=Q(test__finding__active=True)))
    prefetched_engs = prefetched_engs.annotate(count_findings_duplicate=Count('test__finding__id', filter=Q(test__finding__duplicate=True)))
    return prefetched_engs


def view_engagements_cicd(request, pid):
    return view_engagements(request, pid, engagement_type="CI/CD")


@user_passes_test(lambda u: u.is_staff)
def import_scan_results_prod(request, pid=None):
    from dojo.engagement.views import import_scan_results
    return import_scan_results(request, pid=pid)


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

    product_metadata = dict(prod.product_meta.values_list('name', 'value'))

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
            t = ", ".join('"{0}"'.format(w) for w in tags)
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

            # SonarQube API Configuration
            sonarqube_form = Sonarqube_ProductForm(request.POST)
            if sonarqube_form.is_valid():
                sonarqube_product = sonarqube_form.save(commit=False)
                sonarqube_product.product = product
                sonarqube_product.save()

            create_notification(event='product_added', title=product.name, url=reverse('view_product', args=(product.id,)))
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
                   'jform': jform,
                   'sonarqube_form': Sonarqube_ProductForm()})


@user_passes_test(lambda u: u.is_staff)
def edit_product(request, pid):
    prod = Product.objects.get(pk=pid)
    system_settings = System_Settings.objects.get()
    jira_enabled = system_settings.enable_jira
    jira_inst = None
    jform = None
    sonarqube_form = None
    try:
        jira_inst = JIRA_PKey.objects.get(product=prod)
    except:
        jira_inst = None
        pass

    sonarqube_conf = Sonarqube_Product.objects.filter(product=prod).first()

    if request.method == 'POST':
        form = ProductForm(request.POST, instance=prod)
        if form.is_valid():
            form.save()
            tags = request.POST.getlist('tags')
            t = ", ".join('"{0}"'.format(w) for w in tags)
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

            # SonarQube API Configuration
            sonarqube_form = Sonarqube_ProductForm(request.POST, instance=sonarqube_conf)
            if sonarqube_form.is_valid():
                new_conf = sonarqube_form.save(commit=False)
                new_conf.product_id = pid
                new_conf.save()

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

        sonarqube_form = Sonarqube_ProductForm(instance=sonarqube_conf)

    form.initial['tags'] = [tag.name for tag in prod.tags]
    product_tab = Product_Tab(pid, title="Edit Product", tab="settings")
    return render(request,
                  'dojo/edit_product.html',
                  {'form': form,
                   'product_tab': product_tab,
                   'jform': jform,
                   'sonarqube_form': sonarqube_form,
                   'product': prod
                   })


@user_passes_test(lambda u: u.is_staff)
def delete_product(request, pid):
    product = get_object_or_404(Product, pk=pid)
    form = DeleteProductForm(instance=product)

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
                create_notification(event='other',
                                    title='Deletion of %s' % product.name,
                                    description='The product "%s" was deleted by %s' % (product.name, request.user),
                                    url=request.build_absolute_uri(reverse('product')),
                                    icon="exclamation-triangle")
                return HttpResponseRedirect(reverse('product'))

    collector = NestedObjects(using=DEFAULT_DB_ALIAS)
    collector.collect([product])
    rels = collector.nested()

    product_tab = Product_Tab(pid, title="Product", tab="settings")
    return render(request, 'dojo/delete_product.html',
                  {'product': product,
                   'form': form,
                   'product_tab': product_tab,
                   'rels': rels,
                   })


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
def new_eng_for_app(request, pid, cicd=False):
    jform = None
    prod = Product.objects.get(id=pid)
    if request.method == 'POST':
        form = EngForm(request.POST, cicd=cicd)
        if form.is_valid():
            new_eng = form.save(commit=False)
            if not new_eng.name:
                new_eng.name = str(new_eng.target_start)
            new_eng.threat_model = False
            new_eng.api_test = False
            new_eng.pen_test = False
            new_eng.check_list = False
            new_eng.product_id = form.cleaned_data.get('product').id
            if new_eng.threat_model:
                new_eng.progress = 'threat_model'
            else:
                new_eng.progress = 'other'
            if cicd:
                new_eng.engagement_type = 'CI/CD'
                new_eng.status = "In Progress"

            new_eng.save()
            tags = request.POST.getlist('tags')
            t = ", ".join('"{0}"'.format(w) for w in tags)
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

            create_notification(event='engagement_added', title=new_eng.name + " for " + prod.name, engagement=new_eng, url=reverse('view_engagement', args=(new_eng.id,)), objowner=new_eng.lead)

            if "_Add Tests" in request.POST:
                return HttpResponseRedirect(reverse('add_tests', args=(new_eng.id,)))
            elif "_Import Scan Results" in request.POST:
                return HttpResponseRedirect(reverse('import_scan_results', args=(new_eng.id,)))
            else:
                return HttpResponseRedirect(reverse('view_engagement', args=(new_eng.id,)))
    else:
        form = EngForm(initial={'lead': request.user, 'target_start': timezone.now().date(), 'target_end': timezone.now().date() + timedelta(days=7), 'product': prod.id}, cicd=cicd, product=prod.id)
        if(get_system_setting('enable_jira')):
            if JIRA_PKey.objects.filter(product=prod).count() != 0:
                jform = JIRAFindingForm(prefix='jiraform', enabled=JIRA_PKey.objects.get(product=prod).push_all_issues)

    product_tab = Product_Tab(pid, title="New Engagement", tab="engagements")
    return render(request, 'dojo/new_eng.html',
                  {'form': form, 'pid': pid,
                   'product_tab': product_tab,
                   'jform': jform
                   })


@user_passes_test(lambda u: u.is_staff)
def new_eng_for_app_cicd(request, pid):
    return new_eng_for_app(request, pid, True)


@user_passes_test(lambda u: u.is_staff)
def add_meta_data(request, pid):
    prod = Product.objects.get(id=pid)
    if request.method == 'POST':
        form = DojoMetaDataForm(request.POST, instance=DojoMeta(product=prod))
        if form.is_valid():
            form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Metadata added successfully.',
                                 extra_tags='alert-success')
            if 'add_another' in request.POST:
                return HttpResponseRedirect(reverse('add_meta_data', args=(pid,)))
            else:
                return HttpResponseRedirect(reverse('view_product', args=(pid,)))
    else:
        form = DojoMetaDataForm()

    product_tab = Product_Tab(pid, title="Add Metadata", tab="settings")

    return render(request,
                  'dojo/add_product_meta_data.html',
                  {'form': form,
                   'product_tab': product_tab,
                   'product': prod,
                   })


@user_passes_test(lambda u: u.is_staff)
def edit_meta_data(request, pid):
    prod = Product.objects.get(id=pid)
    if request.method == 'POST':
        for key, value in request.POST.items():
            if key.startswith('cfv_'):
                cfv_id = int(key.split('_')[1])
                cfv = get_object_or_404(DojoMeta, id=cfv_id)
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

    product_tab = Product_Tab(pid, title="Edit Metadata", tab="settings")
    return render(request,
                  'dojo/edit_product_meta_data.html',
                  {'product': prod,
                   'product_tab': product_tab,
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
        if (form['active'].value() is False or form['false_p'].value()) and form['duplicate'].value() is False:
            closing_disabled = Note_Type.objects.filter(is_mandatory=True, is_active=True).count()
            if closing_disabled != 0:
                error_inactive = ValidationError('Can not set a finding as inactive without adding all mandatory notes',
                                        code='inactive_without_mandatory_notes')
                error_false_p = ValidationError('Can not set a finding as false positive without adding all mandatory notes',
                                        code='false_p_without_mandatory_notes')
                if form['active'].value() is False:
                    form.add_error('active', error_inactive)
                if form['false_p'].value():
                    form.add_error('false_p', error_false_p)
                messages.add_message(request,
                                     messages.ERROR,
                                     'Can not set a finding as inactive or false positive without adding all mandatory notes',
                                     extra_tags='alert-danger')
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
            new_finding.endpoints.set(form.cleaned_data['endpoints'])
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
    product_tab = Product_Tab(pid, title="Add Finding", tab="engagements")
    product_tab.setEngagement(eng)
    return render(request, 'dojo/ad_hoc_findings.html',
                  {'form': form,
                   'product_tab': product_tab,
                   'temp': False,
                   'tid': test.id,
                   'pid': pid,
                   'form_error': form_error,
                   'jform': jform,
                   })


@user_passes_test(lambda u: u.is_staff)
def engagement_presets(request, pid):
    prod = get_object_or_404(Product, id=pid)
    presets = Engagement_Presets.objects.filter(product=prod).all()

    product_tab = Product_Tab(prod.id, title="Engagement Presets", tab="settings")

    return render(request, 'dojo/view_presets.html',
                  {'product_tab': product_tab,
                   'presets': presets,
                   'prod': prod})


@user_passes_test(lambda u: u.is_staff)
def edit_engagement_presets(request, pid, eid):
    prod = get_object_or_404(Product, id=pid)
    preset = get_object_or_404(Engagement_Presets, id=eid)

    product_tab = Product_Tab(prod.id, title="Edit Engagement Preset", tab="settings")

    if request.method == 'POST':
        tform = EngagementPresetsForm(request.POST, instance=preset)
        if tform.is_valid():
            tform.save()
            messages.add_message(
                request,
                messages.SUCCESS,
                'Engagement Preset Successfully Updated.',
                extra_tags='alert-success')
            return HttpResponseRedirect(reverse('engagement_presets', args=(pid,)))
    else:
        tform = EngagementPresetsForm(instance=preset)

    return render(request, 'dojo/edit_presets.html',
                  {'product_tab': product_tab,
                   'tform': tform,
                   'prod': prod})


@user_passes_test(lambda u: u.is_staff)
def add_engagement_presets(request, pid):
    prod = get_object_or_404(Product, id=pid)
    if request.method == 'POST':
        tform = EngagementPresetsForm(request.POST)
        if tform.is_valid():
            form_copy = tform.save(commit=False)
            form_copy.product = prod
            form_copy.save()
            tform.save_m2m()
            messages.add_message(
                request,
                messages.SUCCESS,
                'Engagement Preset Successfully Created.',
                extra_tags='alert-success')
            return HttpResponseRedirect(reverse('engagement_presets', args=(pid,)))
    else:
        tform = EngagementPresetsForm()

    product_tab = Product_Tab(pid, title="New Engagement Preset", tab="settings")
    return render(request, 'dojo/new_params.html', {'tform': tform, 'pid': pid, 'product_tab': product_tab})


@user_passes_test(lambda u: u.is_staff)
def delete_engagement_presets(request, pid, eid):
    prod = get_object_or_404(Product, id=pid)
    preset = get_object_or_404(Engagement_Presets, id=eid)
    form = DeleteEngagementPresetsForm(instance=preset)

    if request.method == 'POST':
        if 'id' in request.POST:
            form = DeleteEngagementPresetsForm(request.POST, instance=preset)
            if form.is_valid():
                preset.delete()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'Engagement presets and engagement relationships removed.',
                                     extra_tags='alert-success')
                return HttpResponseRedirect(reverse('engagement_presets', args=(pid,)))

    collector = NestedObjects(using=DEFAULT_DB_ALIAS)
    collector.collect([preset])
    rels = collector.nested()

    product_tab = Product_Tab(pid, title="Delete Engagement Preset", tab="settings")
    return render(request, 'dojo/delete_presets.html',
                  {'product': product,
                   'form': form,
                   'product_tab': product_tab,
                   'rels': rels,
                   })
