from calendar import monthrange
from collections import OrderedDict
import base64
import collections
import csv
from datetime import date, datetime, timedelta
from easy_pdf.rendering import render_to_pdf_response
import logging
from math import ceil, pi, sqrt
from operator import itemgetter
import operator
import os
import re
from threading import Thread
from xml.etree import ElementTree
from xml.dom import NamespaceErr
import time
import calendar as tcalendar
from urlparse import urlsplit
from xml.etree.ElementTree import ParseError

from dateutil.relativedelta import relativedelta, MO
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, logout
from django.contrib.auth.decorators import user_passes_test
from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.core.validators import validate_ipv46_address
from django.utils.html import escape
from django.db.models import Q
from django.http import HttpResponseRedirect, StreamingHttpResponse, HttpResponseForbidden, Http404, HttpResponse
from django.core.urlresolvers import reverse
from django.shortcuts import render, get_object_or_404
from pytz import timezone
from tastypie.models import ApiKey

from dojo.forms import VaForm, WeeklyMetricsForm, \
    SimpleMetricsForm, MetricsFilterForm, CheckForm, \
    ScanSettingsForm, UploadThreatForm, UploadFileForm, \
    UploadRiskForm, NoteForm, CloseFindingForm, DoneForm, \
    ProductForm, EngForm2, EngForm, TestForm, FindingForm, \
    SimpleSearchForm, Product_TypeForm, Product_TypeProductForm, \
    Test_TypeForm, ReplaceRiskAcceptanceForm, FINDING_STATUS, \
    AddFindingsRiskAcceptanceForm, Development_EnvironmentForm, DojoUserForm, \
    DeleteIPScanForm, DeleteTestForm, UploadVeracodeForm, UploadBurpForm, EditEndpointForm, \
    DeleteEndpointForm, AddEndpointForm, DeleteProductForm, DeleteEngagementForm, AddFindingForm
from dojo.management.commands.run_scan import run_on_deman_scan
from dojo.models import Product_Type, Finding, Product, Engagement, Test, \
    Check_List, Scan, IPScan, ScanSettings, Test_Type, Notes, \
    Risk_Acceptance, Dojo_User, Development_Environment, BurpRawRequestResponse, Endpoint
from dojo.filters import ProductFilter, OpenFindingFilter, \
    OpenFingingSuperFilter, AcceptedFingingSuperFilter, \
    AcceptedFindingFilter, ProductFindingFilter, EngagementFilter, \
    ClosedFingingSuperFilter, ClosedFindingFilter, MetricsFindingFilter, ReportFindingFilter, EndpointFilter, \
    ReportAuthedFindingFilter, EndpointReportFilter

localtz = timezone(settings.TIME_ZONE)

logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)d] %(message)s',
    datefmt='%d/%b/%Y %H:%M:%S',
    filename=settings.DOJO_ROOT + '/../django_app.log',
)
logger = logging.getLogger(__name__)

SEVERITIES = {'Info': 4, 'Low': 3, 'Medium': 2,
              'High': 1, 'Critical': 0}

"""
Greg
Status: in dev, on hold
Self service tool for launching nessus scans
"""


def launch_va(request, pid):
    if request.method == 'POST':
        form = VaForm(request.POST)
        if form.isValid():
            new_va = form.save(commit=False)
            new_va.user = request.user
            new_va.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'VA successfully created.',
                                 extra_tags='alert-success')
    else:
        form = VaForm()
    return render(request,
                  "dojo/launch_va.html",
                  {'form': form, 'pid': pid})


"""
Greg
Status: in production
name self explaintory, only Jim, senior mananger and root user have access to
view others metrics
"""


@user_passes_test(lambda u: u.is_staff)
def engineer_metrics(request):
    # checking if user is super_user
    if request.user.is_superuser:
        users = Dojo_User.objects.filter(is_staff=True).order_by('username')
    else:
        return HttpResponseRedirect(reverse('view_engineer', args=(request.user.id,)))

    return render(request,
                  'dojo/engineer_metrics.html',
                  {'users': users,
                   'breadcrumbs': get_breadcrumbs(title="Engineer Metrics", user=request.user)})


"""
Greg
Status: in prod
indvidual view of engineer metrics for a given month. Only superusers,
and root can view others metrics
"""


# noinspection DjangoOrm
@user_passes_test(lambda u: u.is_staff)
def view_engineer(request, eid):
    user = get_object_or_404(Dojo_User, pk=eid)
    if not (request.user.is_superuser
            or request.user.username == 'root'
            or request.user.username == user.username):
        return HttpResponseRedirect(reverse('engineer_metrics'))
    now = localtz.localize(datetime.today())

    findings = Finding.objects.filter(reporter=user, verified=True)

    open_findings = findings.exclude(mitigated__isnull=False)
    open_month = findings.filter(date__year=now.year, date__month=now.month)
    accepted_month = [finding for ra in Risk_Acceptance.objects.filter(
        created__range=[datetime(now.year,
                                 now.month, 1,
                                 tzinfo=localtz),
                        datetime(now.year,
                                 now.month,
                                 monthrange(now.year,
                                            now.month)[1],
                                 tzinfo=localtz)],
        reporter=user)
                      for finding in ra.accepted_findings.all()]
    closed_month = []
    for f in findings:
        if (f.mitigated
            and f.mitigated.year == now.year
            and f.mitigated.month == now.month):
            closed_month.append(f)

    o_dict, open_count = count_findings(open_month)
    c_dict, closed_count = count_findings(closed_month)
    a_dict, accepted_count = count_findings(accepted_month)
    day_list = [now - relativedelta(weeks=1,
                                    weekday=x,
                                    hour=0,
                                    minute=0,
                                    second=0)
                for x in range(now.weekday())]
    day_list.append(now)

    q_objects = (Q(date=d) for d in day_list)
    closed_week = []
    open_week = findings.filter(reduce(operator.or_, q_objects))

    accepted_week = [finding for ra in Risk_Acceptance.objects.filter(
        reporter=user, created__range=[day_list[0], day_list[-1]])
                     for finding in ra.accepted_findings.all()]

    q_objects = (Q(mitigated=d) for d in day_list)
    # closed_week= findings.filter(reduce(operator.or_, q_objects))
    for f in findings:
        if f.mitigated and f.mitigated >= day_list[0]:
            closed_week.append(f)

    o_week_dict, open_week_count = count_findings(open_week)
    c_week_dict, closed_week_count = count_findings(closed_week)
    a_week_dict, accepted_week_count = count_findings(accepted_week)

    stuff = []
    o_stuff = []
    a_stuff = []
    findings_this_period(findings, 1, stuff, o_stuff, a_stuff)
    # findings_this_period no longer fits the need for accepted findings
    # however will use its week finding output to use here
    for month in a_stuff:
        month_start = localtz.localize(datetime.strptime(
            month[0].strip(), "%b %Y"))
        month_end = datetime(month_start.year,
                             month_start.month,
                             monthrange(
                                 month_start.year,
                                 month_start.month)[1],
                             tzinfo=localtz)
        for finding in [finding for ra in Risk_Acceptance.objects.filter(
                created__range=[month_start, month_end], reporter=user)
                        for finding in ra.accepted_findings.all()]:
            if finding.severity == 'Critical':
                month[1] += 1
            if finding.severity == 'High':
                month[2] += 1
            if finding.severity == 'Medium':
                month[3] += 1
            if finding.severity == 'Low':
                month[4] += 1

        month[5] = sum(month[1:])
    week_stuff = []
    week_o_stuff = []
    week_a_stuff = []
    findings_this_period(findings, 0, week_stuff, week_o_stuff, week_a_stuff)

    # findings_this_period no longer fits the need for accepted findings
    # however will use its week finding output to use here
    for week in week_a_stuff:
        wk_range = week[0].split('-')
        week_start = localtz.localize(datetime.strptime(
            wk_range[0].strip() + " " + str(now.year), "%b %d %Y"))
        week_end = localtz.localize(datetime.strptime(
            wk_range[1].strip() + " " + str(now.year), "%b %d %Y"))

        for finding in [finding for ra in Risk_Acceptance.objects.filter(
                created__range=[week_start, week_end], reporter=user)
                        for finding in ra.accepted_findings.all()]:
            if finding.severity == 'Critical':
                week[1] += 1
            if finding.severity == 'High':
                week[2] += 1
            if finding.severity == 'Medium':
                week[3] += 1
            if finding.severity == 'Low':
                week[4] += 1

        week[5] = sum(week[1:])

    products = Product.objects.all()
    vulns = {}
    for product in products:
        f_count = 0
        engs = Engagement.objects.filter(product=product)
        for eng in engs:
            tests = Test.objects.filter(engagement=eng)
            for test in tests:
                f_count += findings.filter(test=test,
                                           mitigated__isnull=True,
                                           active=True).count()
        vulns[product.id] = f_count
    od = OrderedDict(sorted(vulns.items(), key=itemgetter(1)))
    items = od.items()
    items.reverse()
    top = items[: 10]
    update = []
    for t in top:
        product = t[0]
        z_count = 0
        o_count = 0
        t_count = 0
        h_count = 0
        engs = Engagement.objects.filter(
            product=Product.objects.get(id=product))
        for eng in engs:
            tests = Test.objects.filter(engagement=eng)
            for test in tests:
                z_count += findings.filter(
                    test=test,
                    mitigated__isnull=True,
                    severity='Critical'
                ).count()
                o_count += findings.filter(
                    test=test,
                    mitigated__isnull=True,
                    severity='High'
                ).count()
                t_count += findings.filter(
                    test=test,
                    mitigated__isnull=True,
                    severity='Medium'
                ).count()
                h_count += findings.filter(
                    test=test,
                    mitigated__isnull=True,
                    severity='Low'
                ).count()
        prod = Product.objects.get(id=product)
        all_findings_link = "<a href='%s'>%s</a>" % (
            reverse('view_product_findings', args=(prod.id,)), escape(prod.name))
        update.append([all_findings_link, z_count, o_count, t_count, h_count,
                       z_count + o_count + t_count + h_count])
    total_update = []
    for i in items:
        product = i[0]
        z_count = 0
        o_count = 0
        t_count = 0
        h_count = 0
        engs = Engagement.objects.filter(
            product=Product.objects.get(id=product))
        for eng in engs:
            tests = Test.objects.filter(engagement=eng)
            for test in tests:
                z_count += findings.filter(
                    test=test,
                    mitigated__isnull=True,
                    severity='Critical').count()
                o_count += findings.filter(
                    test=test,
                    mitigated__isnull=True,
                    severity='High').count()
                t_count += findings.filter(
                    test=test,
                    mitigated__isnull=True,
                    severity='Medium').count()
                h_count += findings.filter(
                    test=test,
                    mitigated__isnull=True,
                    severity='Low').count()
        prod = Product.objects.get(id=product)
        all_findings_link = "<a href='%s'>%s</a>" % (
            reverse('view_product_findings', args=(prod.id,)), escape(prod.name))
        total_update.append([all_findings_link, z_count, o_count, t_count,
                             h_count, z_count + o_count + t_count + h_count])

    neg_length = len(stuff)
    findz = findings.filter(mitigated__isnull=True, active=True,
                            test__engagement__risk_acceptance=None)
    findz = findz.filter(Q(severity="Critical") | Q(severity="High"))
    less_thirty = 0
    less_sixty = 0
    less_nine = 0
    more_nine = 0
    for finding in findz:
        elapsed = date.today() - finding.date
        if elapsed <= timedelta(days=30):
            less_thirty += 1
        elif elapsed <= timedelta(days=60):
            less_sixty += 1
        elif elapsed <= timedelta(days=90):
            less_nine += 1
        else:
            more_nine += 1

    # Data for the monthly charts
    chart_data = []
    chart_data.append(['Date', 'S0', 'S1', 'S2', 'S3', 'Total'])
    for thing in o_stuff:
        chart_data.insert(1, thing)

    a_chart_data = []
    a_chart_data.append(['Date', 'S0', 'S1', 'S2', 'S3', 'Total'])
    for thing in a_stuff:
        a_chart_data.insert(1, thing)

    # Data for the weekly charts
    week_chart_data = []
    week_chart_data.append(['Date', 'S0', 'S1', 'S2', 'S3', 'Total'])
    for thing in week_o_stuff:
        week_chart_data.insert(1, thing)

    week_a_chart_data = []
    week_a_chart_data.append(['Date', 'S0', 'S1', 'S2', 'S3', 'Total'])
    for thing in week_a_stuff:
        week_a_chart_data.insert(1, thing)

    details = []
    for find in open_findings:
        team = find.test.engagement.product.prod_type.name
        name = find.test.engagement.product.name
        severity = find.severity
        if severity == 'Critical':
            severity = 'S0'
        elif severity == 'High':
            severity = 'S1'
        elif severity == 'Medium':
            severity = 'S2'
        else:
            severity = 'S3'
        description = find.title
        life = date.today() - find.date
        life = life.days
        status = 'Active'
        if len(find.risk_acceptance_set.all()) > 0:
            status = 'Accepted'
        detail = []
        detail.append(team)
        detail.append(name)
        detail.append(severity)
        detail.append(description)
        detail.append(life)
        detail.append(status)
        detail.append(find.reporter)
        details.append(detail)

    details = sorted(details, key=lambda x: x[2])

    return render(request, 'dojo/view_engineer.html', {
        'open_month': open_month,
        'a_month': accepted_month,
        'low_a_month': accepted_count["low"],
        'medium_a_month': accepted_count["med"],
        'high_a_month': accepted_count["high"],
        'critical_a_month': accepted_count["crit"],
        'closed_month': closed_month,
        'low_open_month': open_count["low"],
        'medium_open_month': open_count["med"],
        'high_open_month': open_count["high"],
        'critical_open_month': open_count["crit"],
        'low_c_month': closed_count["low"],
        'medium_c_month': closed_count["med"],
        'high_c_month': closed_count["high"],
        'critical_c_month': closed_count["crit"],
        'week_stuff': week_stuff,
        'week_a_stuff': week_a_stuff,
        'a_total': a_stuff,
        'total': stuff,
        'sub': neg_length,
        'update': update,
        'lt': less_thirty,
        'ls': less_sixty,
        'ln': less_nine,
        'mn': more_nine,
        'chart_data': chart_data,
        'a_chart_data': a_chart_data,
        'week_chart_data': week_chart_data,
        'week_a_chart_data': week_a_chart_data,
        'name': '%s Metrics' % user.get_full_name(),
        'breadcrumbs': get_breadcrumbs(
            title="%s Metrics" % user.get_full_name(),
            user=request.user),
        'metric': True,
        'total_update': total_update,
        'details': details,
        'open_week': open_week,
        'closed_week': closed_week,
        'accepted_week': accepted_week,
        'a_dict': a_dict,
        'o_dict': o_dict,
        'c_dict': c_dict,
        'o_week_dict': o_week_dict,
        'a_week_dict': a_week_dict,
        'c_week_dict': c_week_dict,
        'open_week_count': open_week_count,
        'accepted_week_count': accepted_week_count,
        'closed_week_count': closed_week_count,
        'user': request.user,
    })


"""
Greg
Status: in prod
on the nav menu open findings returns all the open findings for a given
engineer
"""


def open_findings(request):
    findings = Finding.objects.filter(active=True,
                                      verified=True,
                                      mitigated__isnull=True)
    if request.user.is_staff:
        findings = OpenFingingSuperFilter(request.GET, queryset=findings, user=request.user)
    else:
        findings = findings.filter(test__engagement__product__authorized_users__in=[request.user])
        findings = OpenFindingFilter(request.GET, queryset=findings, user=request.user)

    title_words = [word
                   for finding in findings
                   for word in finding.title.split() if len(word) > 2]

    title_words = sorted(set(title_words))
    paged_findings = get_page_items(request, findings, 25)
    return render(request,
                  'dojo/open_findings.html',
                  {"findings": paged_findings,
                   "filtered": findings,
                   "title_words": title_words,
                   'breadcrumbs': get_breadcrumbs(title="Open findings",
                                                  user=request.user)})


"""
Greg, Jay
Status: in prod
on the nav menu accpted findings returns all the accepted findings for a given
engineer
"""


@user_passes_test(lambda u: u.is_staff)
def accepted_findings(request):
    user = request.user

    fids = [finding.id for ra in
            Risk_Acceptance.objects.all()
            for finding in ra.accepted_findings.all()]
    findings = Finding.objects.filter(id__in=fids)
    findings = AcceptedFingingSuperFilter(request.GET, queryset=findings)
    title_words = [word for ra in
                   Risk_Acceptance.objects.all()
                   for finding in ra.accepted_findings.order_by(
            'title').values('title').distinct()
                   for word in finding['title'].split() if len(word) > 2]

    title_words = sorted(set(title_words))
    paged_findings = get_page_items(request, findings, 25)

    return render(request,
                  'dojo/accepted_findings.html',
                  {"findings": paged_findings,
                   "filtered": findings,
                   "title_words": title_words,
                   'breadcrumbs': get_breadcrumbs(title="Accepted findings",
                                                  user=request.user)})


@user_passes_test(lambda u: u.is_staff)
def closed_findings(request):
    findings = Finding.objects.filter(mitigated__isnull=False)
    findings = ClosedFingingSuperFilter(request.GET, queryset=findings)
    title_words = [word
                   for finding in findings
                   for word in finding.title.split() if len(word) > 2]

    title_words = sorted(set(title_words))
    paged_findings = get_page_items(request, findings, 25)
    return render(request,
                  'dojo/closed_findings.html',
                  {"findings": paged_findings,
                   "filtered": findings,
                   "title_words": title_words,
                   'breadcrumbs': get_breadcrumbs(title="Closed findings",
                                                  user=request.user)})


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
    page = get_page_items(request, result, 20)
    return render(request,
                  "dojo/all_product_findings.html",
                  {"findings": page,
                   "pid": pid,
                   "filtered": result,
                   "user": request.user,
                   "breadcrumbs": get_breadcrumbs(obj=p, user=request.user)})


"""
Michael & Fatima:
Helper function for metrics
Counts the number of findings and the count for the products for each level of
severity for a given finding querySet
"""


def count_findings(findings):
    product_count = {}
    finding_count = {'low': 0, 'med': 0, 'high': 0, 'crit': 0}
    for f in findings:
        product = f.test.engagement.product
        if (product in product_count):
            product_count[product][4] = product_count[product][4] + 1
            if f.severity == 'Low':
                product_count[product][3] = product_count[product][3] + 1
                finding_count['low'] += 1
            if f.severity == 'Medium':
                product_count[product][2] = product_count[product][2] + 1
                finding_count['med'] += 1
            if f.severity == 'High':
                product_count[product][1] = product_count[product][1] + 1
                finding_count['high'] += 1
            if f.severity == 'Critical':
                product_count[product][0] = product_count[product][0] + 1
                finding_count['crit'] += 1
        else:
            product_count[product] = [0, 0, 0, 0, 0]
            product_count[product][4] = product_count[product][4] + 1
            if f.severity == 'Low':
                product_count[product][3] = product_count[product][3] + 1
                finding_count['low'] += 1
            if f.severity == 'Medium':
                product_count[product][2] = product_count[product][2] + 1
                finding_count['med'] += 1
            if f.severity == 'High':
                product_count[product][1] = product_count[product][1] + 1
                finding_count['high'] += 1
            if f.severity == 'Critical':
                product_count[product][0] = product_count[product][0] + 1
                finding_count['crit'] += 1
    return (product_count, finding_count)


def findings_this_period(findings, periodType, stuff, o_stuff, a_stuff):
    # periodType: 0 - weeks
    # 1 - months
    now = localtz.localize(datetime.today())
    for i in range(6):
        counts = []
        # Weeks start on Monday
        if periodType == 0:
            curr = now - relativedelta(weeks=i)
            start_of_period = curr - relativedelta(weeks=1, weekday=0,
                                                   hour=0, minute=0, second=0)
            end_of_period = curr + relativedelta(weeks=0, weekday=0, hour=0,
                                                 minute=0, second=0)
        else:
            curr = now - relativedelta(months=i)
            start_of_period = curr - relativedelta(day=1, hour=0,
                                                   minute=0, second=0)
            end_of_period = curr + relativedelta(day=31, hour=23,
                                                 minute=59, second=59)

        o_count = {'closed': 0, 'zero': 0, 'one': 0, 'two': 0,
                   'three': 0, 'total': 0}
        a_count = {'closed': 0, 'zero': 0, 'one': 0, 'two': 0,
                   'three': 0, 'total': 0}
        for f in findings:
            if (f.mitigated is not None
                and f.mitigated <= end_of_period
                and f.mitigated >= start_of_period):
                o_count['closed'] += 1
            elif (f.mitigated is not None
                  and f.mitigated > end_of_period
                  and f.date <= end_of_period.date()):
                if f.severity == 'Critical':
                    o_count['zero'] += 1
                elif f.severity == 'High':
                    o_count['one'] += 1
                elif f.severity == 'Medium':
                    o_count['two'] += 1
                elif f.severity == 'Low':
                    o_count['three'] += 1
            elif (f.mitigated is None
                  and f.date <= end_of_period.date()):
                if f.severity == 'Critical':
                    o_count['zero'] += 1
                elif f.severity == 'High':
                    o_count['one'] += 1
                elif f.severity == 'Medium':
                    o_count['two'] += 1
                elif f.severity == 'Low':
                    o_count['three'] += 1
            elif (f.mitigated is None
                  and f.date <= end_of_period.date()):
                if f.severity == 'Critical':
                    a_count['zero'] += 1
                elif f.severity == 'High':
                    a_count['one'] += 1
                elif f.severity == 'Medium':
                    a_count['two'] += 1
                elif f.severity == 'Low':
                    a_count['three'] += 1

        total = sum(o_count.values()) - o_count['closed']
        if periodType == 0:
            counts.append(
                start_of_period.strftime("%b %d") + " - " +
                end_of_period.strftime("%b %d"))
        else:
            counts.append(start_of_period.strftime("%b %Y"))
        counts.append(o_count['zero'])
        counts.append(o_count['one'])
        counts.append(o_count['two'])
        counts.append(o_count['three'])
        counts.append(total)
        counts.append(o_count['closed'])

        stuff.append(counts)
        o_stuff.append(counts[:-1])

        a_counts = []
        a_total = sum(a_count.values())
        if periodType == 0:
            a_counts.append(start_of_period.strftime("%b %d") + " - "
                            + end_of_period.strftime("%b %d"))
        else:
            a_counts.append(start_of_period.strftime("%b %Y"))
        a_counts.append(a_count['zero'])
        a_counts.append(a_count['one'])
        a_counts.append(a_count['two'])
        a_counts.append(a_count['three'])
        a_counts.append(a_total)
        a_stuff.append(a_counts)


"""
Greg
For tracking issues reported by SEC researchers.
"""


@user_passes_test(lambda u: u.is_staff)
def research_metrics(request):
    now = localtz.localize(datetime.today())
    findings = Finding.objects.filter(
        test__test_type__name='Security Research')
    findings = findings.filter(date__year=now.year, date__month=now.month)
    verified_month = findings.filter(verified=True)
    month_all_by_product, month_all_aggregate = count_findings(findings)
    month_verified_by_product, month_verified_aggregate = count_findings(
        verified_month)

    end_of_week = now + relativedelta(weekday=6, hour=23, minute=59, second=59)
    day_list = [end_of_week - relativedelta(weeks=1, weekday=x,
                                            hour=0, minute=0, second=0)
                for x in range(end_of_week.weekday())]
    q_objects = (Q(date=d) for d in day_list)
    week_findings = Finding.objects.filter(reduce(operator.or_, q_objects))
    open_week = week_findings.exclude(mitigated__isnull=False)
    verified_week = week_findings.filter(verified=True)
    week_all_by_product, week_all_aggregate = count_findings(week_findings)
    week_verified_by_product, week_verified_aggregate = count_findings(
        verified_week)
    week_remaining_by_product, week_remaining_aggregate = count_findings(
        open_week)

    remaining_by_product, remaining_aggregate = count_findings(
        Finding.objects.filter(mitigated__isnull=True,
                               test__test_type__name='Security Research'))

    closed_findings = Finding.objects.filter(
        mitigated__isnull=False,
        test__test_type__name='Security Research')
    closed_findings_dict = {}
    closed_findings_dict['S0'] = closed_findings.filter(severity='Critical')
    closed_findings_dict['S1'] = closed_findings.filter(severity='High')
    closed_findings_dict['S2'] = closed_findings.filter(severity='Medium')
    closed_findings_dict['S3'] = closed_findings.filter(severity='Low')

    time_to_close = {}
    for sev, finds in closed_findings_dict.items():
        total = 0
        for f in finds:
            total += (datetime.date(f.mitigated) - f.date).days
        if finds.count() != 0:
            time_to_close[sev] = total / finds.count()
        else:
            time_to_close[sev] = 'N/A'

    return render(request, 'dojo/research_metrics.html', {
        'user': request.user,
        'breadcrumbs': get_breadcrumbs(title="Security Research Metrics", user=request.user),
        'month_all_by_product': month_all_by_product,
        'month_verified_by_product': month_verified_by_product,
        'remaining_by_product': remaining_by_product,
        'remaining_aggregate': remaining_aggregate,
        'time_to_close': time_to_close,
    })


"""
Jay
status: in production
simple metrics for easy reporting
"""


def simple_metrics(request):
    now = localtz.localize(datetime.today())

    if request.method == 'POST':
        form = SimpleMetricsForm(request.POST)
        if form.is_valid():
            now = form.cleaned_data['date']
            form = SimpleMetricsForm({'date': now})
    else:
        form = SimpleMetricsForm({'date': now})

    findings_by_product_type = collections.OrderedDict()

    # for each product type find each product with open findings and
    # count the S0, S1, S2 and S3
    for pt in Product_Type.objects.order_by('name'):
        findings_broken_out = {}

        total = Finding.objects.filter(test__engagement__product__prod_type=pt,
                                       verified=True,
                                       false_p=False,
                                       duplicate=False,
                                       out_of_scope=False
                                       ).exclude(
            mitigated__isnull=False
        ).filter(
            Q(severity="Critical") |
            Q(severity="High") |
            Q(severity="Medium") |
            Q(severity="Low"))
        total_critical = Finding.objects.filter(
            test__engagement__product__prod_type=pt,
            verified=True,
            false_p=False,
            duplicate=False,
            out_of_scope=False
        ).exclude(mitigated__isnull=False).filter(Q(severity="Critical"))
        total_high = Finding.objects.filter(
            test__engagement__product__prod_type=pt,
            verified=True,
            false_p=False,
            duplicate=False,
            out_of_scope=False
        ).exclude(mitigated__isnull=False).filter(Q(severity="High"))
        total_medium = Finding.objects.filter(
            test__engagement__product__prod_type=pt,
            verified=True,
            false_p=False,
            duplicate=False,
            out_of_scope=False
        ).exclude(mitigated__isnull=False).filter(Q(severity="Medium"))
        total_low = Finding.objects.filter(
            test__engagement__product__prod_type=pt,
            verified=True,
            false_p=False,
            duplicate=False,
            out_of_scope=False
        ).exclude(mitigated__isnull=False).filter(Q(severity="Low"))

        total_month = Finding.objects.filter(
            test__engagement__product__prod_type=pt,
            verified=True,
            false_p=False,
            duplicate=False,
            out_of_scope=False
        ).exclude(
            mitigated__isnull=False).filter(Q(severity="Critical") |
                                            Q(severity="High") |
                                            Q(severity="Medium") |
                                            Q(severity="Low")
                                            ).filter(date__year=now.year,
                                                     date__month=now.month)

        findings_broken_out['Total'] = total
        findings_broken_out['S0'] = total_critical
        findings_broken_out['S1'] = total_high
        findings_broken_out['S2'] = total_medium
        findings_broken_out['S3'] = total_low

        findings_broken_out['Opened'] = total_month
        findings_broken_out['Closed'] = total_month

        findings_by_product_type[pt] = findings_broken_out

    return render(request, 'dojo/simple_metrics.html', {
        'findings': findings_by_product_type,
        'name': 'Simple Metrics',
        'breadcrumbs': get_breadcrumbs(title="Simple Metrics", user=request.user),
        'metric': True,
        'user': request.user,
        'form': form,
    })


def get_punchcard_data(findings, weeks_between, start_date):
    punchcard = list()
    ticks = list()
    highest_count = 0
    tick = 0
    week_count = 1

    # mon 0, tues 1, wed 2, thurs 3, fri 4, sat 5, sun 6
    # sat 0, sun 6, mon 5, tue 4, wed 3, thur 2, fri 1
    day_offset = {0: 5, 1: 4, 2: 3, 3: 2, 4: 1, 5: 0, 6: 6}
    for x in range(-1, weeks_between):
        # week starts the monday before
        new_date = start_date + relativedelta(weeks=x, weekday=MO(1))
        end_date = new_date + relativedelta(weeks=1)
        append_tick = True
        days = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0, 6: 0}
        for finding in findings:
            if new_date.date() < finding.date <= end_date.date():
                # [0,0,(20*.02)]
                # [week, day, weight]
                days[day_offset[finding.date.weekday()]] += 1
                if days[day_offset[finding.date.weekday()]] > highest_count:
                    highest_count = days[day_offset[finding.date.weekday()]]

        if sum(days.values()) > 0:
            for day, count in days.items():
                punchcard.append([tick, day, count])
                if append_tick:
                    ticks.append([tick, new_date.strftime("<span class='small'>%m/%d<br/>%Y</span>")])
                    append_tick = False
            tick += 1
        week_count += 1
    # adjust the size
    ratio = (sqrt(highest_count / pi))
    for punch in punchcard:
        punch[2] = (sqrt(punch[2] / pi)) / ratio

    return punchcard, ticks, highest_count


def get_period_counts(findings, findings_closed, period_interval, start_date, relative_delta='months'):
    opened_in_period = list()
    accepted_in_period = list()
    opened_in_period.append(['Timestamp', 'Date', 'S0', 'S1', 'S2',
                             'S3', 'Total', 'Closed'])
    accepted_in_period.append(['Timestamp', 'Date', 'S0', 'S1', 'S2',
                               'S3', 'Total', 'Closed'])
    for x in range(-1, period_interval):
        if relative_delta == 'months':
            new_date = start_date + relativedelta(months=x)
            end_date = new_date + relativedelta(months=1)
        else:
            # week starts the monday before
            new_date = start_date + relativedelta(weeks=x, weekday=MO(1))
            end_date = new_date + relativedelta(weeks=1, weekday=MO(1))

        closed_in_range = findings_closed.filter(mitigated__range=[new_date, end_date])
        risks_a = Risk_Acceptance.objects.filter(
            created__range=[datetime(new_date.year,
                                     new_date.month, 1,
                                     tzinfo=localtz),
                            datetime(new_date.year,
                                     new_date.month,
                                     monthrange(new_date.year,
                                                new_date.month)[1],
                                     tzinfo=localtz)])

        crit_count, high_count, med_count, low_count, closed_count = [0, 0, 0, 0, 0]
        for finding in findings:
            if new_date.date() <= finding.date <= end_date.date():
                if finding.severity == 'Critical':
                    crit_count += 1
                elif finding.severity == 'High':
                    high_count += 1
                elif finding.severity == 'Medium':
                    med_count += 1
                elif finding.severity == 'Low':
                    low_count += 1

        total = crit_count + high_count + med_count + low_count
        opened_in_period.append(
            [(tcalendar.timegm(new_date.timetuple()) * 1000), new_date, crit_count, high_count, med_count, low_count,
             total, closed_in_range.count()])
        crit_count, high_count, med_count, low_count, closed_count = [0, 0, 0, 0, 0]
        for ra in risks_a.all():
            for finding in ra.accepted_findings.all():
                if finding.severity == 'Critical':
                    crit_count += 1
                elif finding.severity == 'High':
                    high_count += 1
                elif finding.severity == 'Medium':
                    med_count += 1
                elif finding.severity == 'Low':
                    low_count += 1

        total = crit_count + high_count + med_count + low_count
        accepted_in_period.append(
            [(tcalendar.timegm(new_date.timetuple()) * 1000), new_date, crit_count, high_count, med_count, low_count,
             total])

    return {'opened_per_period': opened_in_period,
            'accepted_per_period': accepted_in_period}


"""
Greg, Jay
status: in production
generic metrics method
"""


def metrics(request, mtype):
    template = 'dojo/metrics.html'
    if mtype == 'All' or mtype == 'wiki':
        pt = Product_Type.objects.all()
        findings = Finding.objects.filter(test__engagement__product__prod_type__in=pt,
                                          verified=True).prefetch_related('test__engagement__product',
                                                                          'test__engagement__product__prod_type',
                                                                          'test__engagement__risk_acceptance',
                                                                          'reporter')
        page_name = "Metrics"
        if 'view' in request.GET and 'dashboard' == request.GET['view']:
            template = 'dojo/dashboard-metrics.html'
            page_name = getattr(settings, 'TEAM_NAME', '') + ' Metrics'
    else:
        pt = Product_Type.objects.filter(id=mtype)
        request.GET._mutable = True
        request.GET.appendlist('test__engagement__product__prod_type', mtype)
        request.GET._mutable = False
        mtype = pt[0].name
        findings = Finding.objects.filter(test__engagement__product__prod_type=pt,
                                          verified=True)
        page_name = '%s Metrics' % mtype

    findings = MetricsFindingFilter(request.GET, queryset=findings)
    findings.qs  # this is needed to load details from filter since it is lazy

    start_date = findings.filters['date'].start_date
    end_date = findings.filters['date'].end_date

    # capture the accepted findings in period
    accepted_findings = [finding for ra in Risk_Acceptance.objects.filter(
        created__range=[start_date, end_date]).prefetch_related(
        'accepted_findings__test__engagement__product')
                         for finding in ra.accepted_findings.all()]
    prod_type = findings.form.cleaned_data['test__engagement__product__prod_type']
    if len(prod_type) > 0:
        findings_closed = Finding.objects.filter(mitigated__range=[start_date, end_date],
                                                 test__engagement__product__prod_type__in=prod_type)
    else:
        findings_closed = Finding.objects.filter(mitigated__range=[start_date, end_date])

    r = relativedelta(end_date, start_date)
    months_between = (r.years * 12) + r.months
    # include current month
    months_between += 1

    weeks_between = int(ceil((((r.years * 12) + r.months) * 4.33) + (r.days / 7)))
    if weeks_between <= 0:
        weeks_between += 2

    monthly_counts = get_period_counts(findings, findings_closed, months_between, start_date, relative_delta='months')
    weekly_counts = get_period_counts(findings, findings_closed, weeks_between, start_date, relative_delta='weeks')

    top_ten_products = sorted(
        Product.objects.filter(
            engagement__test__finding__in=findings
        ).distinct().all(),
        key=lambda t: t.findings_count, reverse=True)[: 10]

    update = []
    for p in top_ten_products:
        open_finds = p.open_findings(start_date, end_date)
        update.append(
            ["<a href='%s'>%s</a>" % (reverse('view_product_findings', args=(p.id,)), escape(p.name)),
             open_finds['Critical'],
             open_finds['High'],
             open_finds['Medium'],
             open_finds['Low'],
             open_finds['Total']])

    update = sorted(update, key=lambda s: s[5], reverse=True)

    details = []

    age_detail = [0, 0, 0, 0]

    in_period_counts = {"Critical": 0, "High": 0, "Medium": 0,
                        "Low": 0, "Info": 0, "Total": 0}
    in_period_details = {}

    closed_in_period_counts = {"Critical": 0, "High": 0, "Medium": 0,
                               "Low": 0, "Info": 0, "Total": 0}
    closed_in_period_details = {}

    accepted_in_period_counts = {"Critical": 0, "High": 0, "Medium": 0,
                                 "Low": 0, "Info": 0, "Total": 0}
    accepted_in_period_details = {}

    for finding in findings:
        if finding.mitigated:
            age = (finding.mitigated.date() - finding.date).days
        else:
            age = (datetime.now().date() - finding.date).days
        if age >= 0 and age <= 30:
            age_detail[0] += 1
        elif age > 30 and age <= 60:
            age_detail[1] += 1
        elif age > 60 and age <= 90:
            age_detail[2] += 1
        elif age > 90:
            age_detail[3] += 1

        in_period_counts[finding.severity] += 1
        in_period_counts['Total'] += 1

        if finding.test.engagement.product.name not in in_period_details:
            in_period_details[finding.test.engagement.product.name] = {
                'path': reverse('view_product_findings', args=(finding.test.engagement.product.id,)),
                'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0, 'Total': 0}
        in_period_details[
            finding.test.engagement.product.name
        ][finding.severity] += 1
        in_period_details[finding.test.engagement.product.name]['Total'] += 1

        team = finding.test.engagement.product.prod_type.name
        name = finding.test.engagement.product.name
        severity = finding.severity
        if severity == 'Critical':
            severity = 'S0'
        elif severity == 'High':
            severity = 'S1'
        elif severity == 'Medium':
            severity = 'S2'
        else:
            severity = 'S3'
        description = finding.title
        life = date.today() - finding.date
        life = life.days
        status = 'Accepted'
        if len(finding.risk_acceptance_set.all()) == 0:
            status = 'Active'
        if finding.mitigated is not None:
            status = 'Closed'
        detail = list()
        detail.append(team)
        detail.append(name)
        detail.append(severity)
        detail.append(description)
        detail.append(life)
        detail.append(status)
        detail.append(finding.reporter)
        detail.append(finding.id)
        details.append(detail)

    for finding in accepted_findings:
        accepted_in_period_counts[finding.severity] += 1
        accepted_in_period_counts['Total'] += 1
        if finding.test.engagement.product.name not in accepted_in_period_details:
            accepted_in_period_details[finding.test.engagement.product.name] = {
                'path': reverse('view_product_findings', args=(finding.test.engagement.product.id,)),
                'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0, 'Total': 0}
        accepted_in_period_details[
            finding.test.engagement.product.name
        ][finding.severity] += 1
        accepted_in_period_details[finding.test.engagement.product.name]['Total'] += 1

    for f in findings_closed:
        closed_in_period_counts[f.severity] += 1
        closed_in_period_counts['Total'] += 1

        if f.test.engagement.product.name not in closed_in_period_details:
            closed_in_period_details[f.test.engagement.product.name] = {
                'path': reverse('view_product_findings', args=(f.test.engagement.product.id,)),
                'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0, 'Total': 0}
        closed_in_period_details[
            f.test.engagement.product.name
        ][f.severity] += 1
        closed_in_period_details[f.test.engagement.product.name]['Total'] += 1

    punchcard = list()
    ticks = list()
    highest_count = 0

    if 'view' in request.GET and 'dashboard' == request.GET['view']:
        punchcard, ticks, highest_count = get_punchcard_data(findings, weeks_between, start_date)

    return render(request, template, {
        'name': page_name,
        'breadcrumbs': get_breadcrumbs(title="%s Metrics" % mtype, user=request.user),
        'start_date': start_date,
        'end_date': end_date,
        'findings': findings,
        'detailed_breakdown': sorted(details, key=lambda x: x[2]),
        'opened_per_month': monthly_counts['opened_per_period'],
        'opened_per_week': weekly_counts['opened_per_period'],
        'accepted_per_month': monthly_counts['accepted_per_period'],
        'accepted_per_week': weekly_counts['accepted_per_period'],
        'top_ten_products': update,
        'age_detail': age_detail,
        'in_period_counts': in_period_counts,
        'in_period_details': in_period_details,
        'accepted_in_period_counts': accepted_in_period_counts,
        'accepted_in_period_details': accepted_in_period_details,
        'closed_in_period_counts': closed_in_period_counts,
        'closed_in_period_details': closed_in_period_details,
        'punchcard': punchcard,
        'ticks': ticks,
        'highest_count': highest_count
    })


"""
status: deprecated see metrics above
generic metrics method
"""


def old_metrics(request, mtype):
    oldest_finding_date = Finding.objects.all().order_by('date')[:1][0].date
    page_name = 'Metrics'
    template = 'dojo/metrics.html'
    now = localtz.localize(datetime.today())
    # start on the first of the current month
    start_date = date(now.year, now.month, 1)
    # end on the last day of the current month
    end_date = date(now.year, now.month, monthrange(now.year, now.month)[1])
    # save the original start date
    r = relativedelta(end_date, start_date)
    months_between = (r.years * 12) + r.months
    orig_date = localtz.localize(datetime.combine(start_date,
                                                  datetime.min.time()))
    exclude_pt = False

    exclude = Q()
    filters = Q()
    date_range = Q()

    if mtype == 'All' or mtype == 'wiki':
        pt = Product_Type.objects.all()
        filters.add(Q(test__engagement__product__prod_type__in=pt), Q.AND)
        if 'view' in request.GET and 'dashboard' == request.GET['view']:
            template = 'dojo/dashboard-metrics.html'
            page_name = getattr(settings, 'TEAM_NAME', '') + ' Metrics'
            start_date = start_date - relativedelta(months=6)
    else:
        pt = Product_Type.objects.filter(id=mtype)
        mtype = pt[0].name
        filters.add(Q(test__engagement__product__prod_type=pt), Q.AND)
        exclude_pt = True
        page_name = '%s Metrics' % mtype

    if 'filters' in request.GET:
        # apply filters
        filter_form = MetricsFilterForm(request.GET,
                                        exclude_product_types=exclude_pt)
        if filter_form.is_valid():
            start_date = filter_form.cleaned_data['start_date']
            if start_date < oldest_finding_date:
                start_date = oldest_finding_date
                messages.add_message(
                    request,
                    messages.INFO,
                    "Start date was adjusted to date of oldest finding (%s)." % start_date,
                    extra_tags='alert-info')
            end_date = filter_form.cleaned_data['end_date']
            date_range.add(
                Q(date__range=[filter_form.cleaned_data['start_date'],
                               filter_form.cleaned_data['end_date']]), Q.AND)
            for key, value in FINDING_STATUS:
                filters.add(Q(**{key: key in
                                      filter_form.cleaned_data['finding_status']}),
                            Q.AND)
            if len(filter_form.cleaned_data['severity']) > 0:
                filters.add(
                    Q(severity__in=filter_form.cleaned_data['severity']),
                    Q.AND)
            if ('exclude_product_types' in filter_form.cleaned_data
                and len(
                    filter_form.cleaned_data['exclude_product_types']) > 0):
                exclude.add(
                    Q(test__engagement__product__prod_type__in=filter_form.
                      cleaned_data['exclude_product_types']),
                    Q.AND)
    else:
        # use defaults
        filter_form = MetricsFilterForm(
            {'finding_status': ['verified'],
             'severity': ['Critical', 'High',
                          'Medium', 'Low'],
             'start_date': start_date.strftime("%m/%d/%Y"),
             'end_date': end_date.strftime("%m/%d/%Y")},
            exclude_product_types=exclude_pt)
        filters.add(Q(severity__in=['Critical', 'High', 'Medium', 'Low']),
                    Q.AND)
        date_range.add(Q(date__range=[start_date, end_date]), Q.AND)
        filters.add(Q(verified=True), Q.AND)

    # these are all findings in the period based on filters added
    # or the defaults
    findings = Finding.objects.filter(filters) \
        .filter(date_range) \
        .exclude(exclude)

    # Data for the monthly charts
    chart_data = []
    trending_open_bug_count = []
    trending_open_bug_count.append(['Date', 'S0', 'S1', 'S2',
                                    'S3', 'Total', 'Closed'])
    a_chart_data = []
    a_chart_data_trend = []
    a_chart_data_trend.append(['Date', 0, 0, 0, 0, 0])

    r = relativedelta(end_date, start_date)
    months_between = (r.years * 12) + r.months
    orig_date = localtz.localize(datetime.combine(start_date,
                                                  datetime.min.time()))
    # step through all the months in the range provided
    for x in range(0, months_between):
        new_date = start_date + relativedelta(months=x)
        risks_a = Risk_Acceptance.objects.filter(
            created__range=[datetime(new_date.year,
                                     new_date.month, 1,
                                     tzinfo=localtz),
                            datetime(new_date.year,
                                     new_date.month,
                                     monthrange(new_date.year,
                                                new_date.month)[1],
                                     tzinfo=localtz)])

        crit_findings = findings.filter(
            severity="Critical",
            date__year=new_date.year,
            date__month=new_date.month
        ).count()
        high_findings = findings.filter(
            severity="High",
            date__year=new_date.year,
            date__month=new_date.month
        ).count()
        med_findings = findings.filter(
            severity="Medium",
            date__year=new_date.year,
            date__month=new_date.month
        ).count()
        low_findings = findings.filter(
            severity="Low",
            date__year=new_date.year,
            date__month=new_date.month
        ).count()
        closed_findings = findings.filter(
            mitigated__range=[datetime(
                new_date.year,
                new_date.month, 1,
                tzinfo=localtz),
                datetime(new_date.year,
                         new_date.month,
                         monthrange(new_date.year,
                                    new_date.month)[1],
                         tzinfo=localtz)]).count()

        a_crit_findings = len([finding for ra in risks_a
                               for finding in ra.accepted_findings.filter(
                severity="Critical")])
        a_high_findings = len([finding for ra in risks_a
                               for finding in ra.accepted_findings.filter(
                severity="High")])
        a_med_findings = len([finding for ra in risks_a
                              for finding in ra.accepted_findings.filter(
                severity="Medium")])
        a_low_findings = len([finding for ra in risks_a
                              for finding in ra.accepted_findings.filter(
                severity="Low")])

        chart_data.append({'y': new_date.strftime("%Y-%m"),
                           'a': crit_findings,
                           'b': high_findings,
                           'c': med_findings,
                           'd': low_findings})
        trending_open_bug_count.append([new_date.strftime("%b %Y"),
                                        crit_findings,
                                        high_findings,
                                        med_findings,
                                        low_findings,
                                        (crit_findings +
                                         high_findings +
                                         med_findings +
                                         low_findings),
                                        closed_findings])
        a_chart_data.append({'y': new_date.strftime("%Y-%m"),
                             'a': a_crit_findings,
                             'b': a_high_findings,
                             'c': a_med_findings,
                             'd': a_low_findings})
    week_chart_data = []
    trending_week_chart_data = []
    trending_week_chart_data.append(['Date', 'S0', 'S1', 'S2',
                                     'S3', 'Total', 'Closed'])
    week_a_chart_data = []
    in_period = True
    add_week = 1
    week_start_date = datetime(start_date.year, start_date.month,
                               start_date.day, tzinfo=localtz)
    # step through all weeks in given period
    while in_period:
        new_date = start_date + relativedelta(weeks=add_week)
        new_date = datetime(new_date.year, new_date.month,
                            new_date.day, tzinfo=localtz)
        risks_a = Risk_Acceptance.objects.filter(
            created__range=[week_start_date, new_date])

        weekly_findings = findings.filter(
            date__range=[week_start_date, new_date]
        )

        crit_findings = weekly_findings.filter(
            severity="Critical")
        high_findings = weekly_findings.filter(
            severity="High", )
        med_findings = weekly_findings.filter(
            severity="Medium")
        low_findings = weekly_findings.filter(
            severity="Low")
        closed_findings = weekly_findings.filter(
            mitigated__range=[week_start_date, new_date])

        a_crit_findings = len([finding for ra in risks_a
                               for finding in ra.accepted_findings.filter(
                severity="Critical")])
        a_high_findings = len([finding for ra in risks_a
                               for finding in ra.accepted_findings.filter(
                severity="High")])
        a_med_findings = len([finding for ra in risks_a
                              for finding in ra.accepted_findings.filter(
                severity="Medium")])
        a_low_findings = len([finding for ra in risks_a
                              for finding in ra.accepted_findings.filter(
                severity="Low")])

        label = week_start_date.strftime("%b %d") + '-' \
                + new_date.strftime("%b %d, %Y")
        week_chart_data.append({'y': label,
                                'a': crit_findings.count(),
                                'b': high_findings.count(),
                                'c': med_findings.count(),
                                'd': low_findings.count()})
        trending_week_chart_data.append(
            [week_start_date.strftime("%b %d") + ' - ' +
             new_date.strftime("%b %d"),
             crit_findings.count(),
             high_findings.count(),
             med_findings.count(),
             low_findings.count(),
             (crit_findings.count() + high_findings.count() +
              med_findings.count() + low_findings.count()),
             closed_findings.count()])

        week_a_chart_data.append({'y': label,
                                  'a': a_crit_findings,
                                  'b': a_high_findings,
                                  'c': a_med_findings,
                                  'd': a_low_findings})
        week_start_date = new_date + relativedelta(days=1)
        if new_date.date() > end_date:
            in_period = False
        else:
            add_week = add_week + 1

    top_ten_products = sorted(
        Product.objects.filter(
            engagement__test__finding__in=findings
        ).distinct().all(),
        key=lambda t: t.findings_count, reverse=True)[: 10]

    update = []
    for p in top_ten_products:
        open_finds = p.open_findings(start_date, end_date)
        update.append(
            ["<a href='%s'>%s</a>" % (reverse('view_product_findings', args=(p.id,)), escape(p.name)),
             open_finds['Critical'],
             open_finds['High'],
             open_finds['Medium'],
             open_finds['Low'],
             open_finds['Total']])

    update = sorted(update, key=lambda s: s[5], reverse=True)

    details = []
    for find in findings:
        team = find.test.engagement.product.prod_type.name
        name = find.test.engagement.product.name
        severity = find.severity
        if severity == 'Critical':
            severity = 'S0'
        elif severity == 'High':
            severity = 'S1'
        elif severity == 'Medium':
            severity = 'S2'
        else:
            severity = 'S3'
        description = find.title
        life = date.today() - find.date
        life = life.days
        status = 'Accepted'
        if len(find.risk_acceptance_set.all()) == 0:
            status = 'Active'
        detail = []
        detail.append(team)
        detail.append(name)
        detail.append(severity)
        detail.append(description)
        detail.append(life)
        detail.append(status)
        detail.append(find.reporter)
        detail.append(find.id)
        details.append(detail)

    details = sorted(details, key=lambda x: x[2])

    in_period_counts = {
        "critical": findings.filter(severity="Critical").count(),
        "high": findings.filter(severity="High").count(),
        "medium": findings.filter(severity="Medium").count(),
        "low": findings.filter(severity="Low").count(),
        "total": len(findings)}
    in_period_details = {}
    age_detail = [0, 0, 0, 0]
    for finding in findings:
        if finding.test.engagement.product.name not in in_period_details:
            in_period_details[finding.test.engagement.product.name] = {
                'path': reverse('view_product_findings', args=(finding.test.engagement.product.id,)),
                'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Total': 0}
        in_period_details[
            finding.test.engagement.product.name
        ][finding.severity] += 1
        in_period_details[finding.test.engagement.product.name]['Total'] += 1

        age = 0
        if finding.mitigated:
            age = (finding.mitigated.date() - finding.date).days
        else:
            age = (datetime.now().date() - finding.date).days
        if age >= 0 and age <= 30:
            age_detail[0] += 1
        elif age > 30 and age <= 60:
            age_detail[1] += 1
        elif age > 60 and age <= 90:
            age_detail[2] += 1
        elif age > 90:
            age_detail[3] += 1

    end_date = localtz.localize(
        datetime.combine(end_date, datetime.min.time()))

    accepted_findings = [finding for ra in Risk_Acceptance.objects.filter(
        created__range=[orig_date, end_date])
                         for finding in ra.accepted_findings.filter(~Q(severity='Info'))]
    accepted_in_period_counts = {
        "critical": sum(f.severity == "Critical" for f in accepted_findings),
        "high": sum(f.severity == "High" for f in accepted_findings),
        "medium": sum(f.severity == "Medium" for f in accepted_findings),
        "low": sum(f.severity == "Low" for f in accepted_findings),
        "total": len(accepted_findings)}

    accepted_in_pd_deets = {}
    for finding in accepted_findings:
        if finding.test.engagement.product.name not in accepted_in_pd_deets:
            accepted_in_pd_deets[
                finding.test.engagement.product.name
            ] = {'path': reverse('view_product_findings', args=(finding.test.engagement.product.id,)),
                 'Critical': 0, 'High': 0, 'Medium': 0,
                 'Low': 0, 'Total': 0}
        accepted_in_pd_deets[
            finding.test.engagement.product.name][finding.severity] += 1
        accepted_in_pd_deets[
            finding.test.engagement.product.name]['Total'] += 1
    closed_findings = Finding.objects.filter(
        mitigated__range=[orig_date, end_date]) \
        .filter(filters).exclude(exclude)

    closed_in_period_counts = {
        "critical": closed_findings.filter(severity="Critical").count(),
        "high": closed_findings.filter(severity="High").count(),
        "medium": closed_findings.filter(severity="Medium").count(),
        "low": closed_findings.filter(severity="Low").count(),
        "total": len(closed_findings)}

    closed_in_pd_details = {}
    for finding in closed_findings:
        if finding.test.engagement.product.name not in closed_in_pd_details:
            closed_in_pd_details[finding.test.engagement.product.name] = {
                'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Total': 0}
        closed_in_pd_details[
            finding.test.engagement.product.name][finding.severity] += 1
        closed_in_pd_details[
            finding.test.engagement.product.name]['Total'] += 1
    return render(request, template, {
        'name': page_name,
        'breadcrumbs': get_breadcrumbs(title="%s Metrics" % mtype, user=request.user),
        'metric': True,
        'user': request.user,
        'mtype': mtype,
        'wmform': WeeklyMetricsForm(),
        'filter_form': filter_form,
        'start_date': start_date,
        'end_date': end_date,
        'update': update,
        'details': details,
        'chart_data': chart_data,
        'a_chart_data': a_chart_data,
        'week_chart_data': week_chart_data,
        'week_a_chart_data': week_a_chart_data,
        'top_ten_products': top_ten_products,
        'in_period_counts': in_period_counts,
        'in_period_details': in_period_details,
        'accepted_in_period_counts': accepted_in_period_counts,
        'accepted_in_pd_deets': accepted_in_pd_deets,
        'closed_in_period_counts': closed_in_period_counts,
        'closed_in_pd_details': closed_in_pd_details,
        'trending_open_bug_count': trending_open_bug_count,
        'trending_week_chart_data': trending_week_chart_data,
        'age_detail': age_detail,

    })


def home(request):
    if request.user.is_authenticated() and request.user.is_staff:
        return HttpResponseRedirect(reverse('dashboard'))

    return HttpResponseRedirect(reverse('metrics'))


"""
Greg:
status: in production
method to complete checklists from the engagement view
"""


@user_passes_test(lambda u: u.is_staff)
def complete_checklist(request, eid):
    eng = get_object_or_404(Engagement, id=eid)
    breadcrumbs = get_breadcrumbs(title="Complete checklist", obj=eng, user=request.user)
    if request.method == 'POST':
        tests = Test.objects.filter(engagement=eng)
        findings = Finding.objects.filter(test__in=tests).all()
        form = CheckForm(request.POST, findings=findings)
        if (form.is_valid()):
            cl = form.save(commit=False)
            try:
                check_l = Check_List.objects.get(engagement=eng)
                cl.id = check_l.id
                cl.save()
                form.save_m2m()
            except:

                cl.engagement = eng
                cl.save()
                form.save_m2m()
                pass
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Checklist saved.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_engagement', args=(eid,)))
    else:
        tests = Test.objects.filter(engagement=eng)
        findings = Finding.objects.filter(test__in=tests).all()
        form = CheckForm(findings=findings)

    return render(request,
                  'dojo/checklist.html',
                  {'form': form,
                   'eid': eng.id,
                   'findings': findings,
                   'breadcrumbs': breadcrumbs})


"""
Greg
status: in prod, completed by interns not enabled by default
Self-service port scanning tool found at the product level
"""


def gmap(request, pid):
    prod = get_object_or_404(Product, id=pid)
    if request.user.is_staff or request.user in prod.authorized_users.all():
        pass  # user is authorized for this product
    else:
        raise PermissionDenied

    form = ScanSettingsForm()
    if request.method == 'POST':
        form = ScanSettingsForm(data=request.POST)
        if form.is_valid():
            new_scan = form.save(commit=False)
            new_scan.product = prod
            new_scan.user = request.user
            new_scan.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Scan settings saved.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_product', args=(pid,)))
        else:
            messages.add_message(request,
                                 messages.ERROR,
                                 'Scan settings not saved.',
                                 extra_tags='alert-danger')
    return render(request,
                  'dojo/gmap.html',
                  {'form': form,
                   'breadcrumbs': get_breadcrumbs(title="Scan", user=request.user),
                   'pid': pid})


"""
Greg:
status: completed in use
"""


def view_scan(request, sid):
    scan = get_object_or_404(Scan, id=sid)
    prod = get_object_or_404(Product, id=scan.scan_settings.product.id)
    scan_settings_id = scan.scan_settings.id
    if request.user.is_staff or request.user in prod.authorized_users.all():
        pass  # user is authorized for this product
    else:
        raise PermissionDenied

    if request.method == "POST":
        form = DeleteIPScanForm(request.POST, instance=scan)
        if form.is_valid():
            scan.delete()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Scan results deleted successfully.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(
                reverse('view_scan_settings', args=(prod.id, scan_settings_id,)))
        else:
            messages.add_message(
                request,
                messages.ERROR,
                'There was a problem deleting scan, please try again.',
                extra_tags='alert-danger')
    ipScans = []
    ipScan_objects = IPScan.objects.filter(scan=scan)
    for i in ipScan_objects:
        service_list = eval(i.services)
        row = [i.address]
        for (port, protocol, status, service) in service_list:
            row.append(port)
            row.append(protocol)
            row.append(status)
            row.append(service)
            ipScans.append(row)
            row = [""]

    form = DeleteIPScanForm(instance=scan)
    return render(
        request,
        'dojo/view_scan.html',
        {'scan': scan,
         'ipScans': ipScans,
         'form': form,
         'breadcrumbs': get_breadcrumbs(obj=scan, user=request.user)})


"""
Greg:
status: completed in use
"""


def view_scan_settings(request, pid, sid):
    scan_settings = get_object_or_404(ScanSettings, id=sid)
    user = request.user
    if (user.is_staff or user in scan_settings.product.authorized_users.all()):
        pass
    else:
        raise PermissionDenied

    scan_is_running = False

    if request.method == 'POST':
        if 'baseline' in request.POST:
            baseline_scan = get_object_or_404(Scan,
                                              id=request.POST['baseline'])
            for scan in scan_settings.scan_set.all():
                if scan.id == baseline_scan.id:
                    scan.baseline = True
                else:
                    scan.baseline = False
                scan.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Base line successfully saved.',
                                 extra_tags='alert-success')
        elif 'scan_now' in request.POST:
            t = Thread(target=run_on_deman_scan, args=(str(sid),))
            t.start()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Scan successfully started.',
                                 extra_tags='alert-success')
            # need to redirect else reload will kick off new scans
            return HttpResponseRedirect(reverse('view_scan_settings', args=(scan_settings.product.id, sid,)))

    for scan in scan_settings.scan_set.all():
        if scan.status in ["Running", "Pending"]:
            scan_is_running = True

    return render(
        request,
        'dojo/view_scan_settings.html',
        {'scan_settings': scan_settings,
         'scans': scan_settings.scan_set.order_by('id'),
         'scan_is_running': scan_is_running,
         'breadcrumbs': get_breadcrumbs(obj=scan_settings, user=request.user)})


"""
Greg:
status: in Prod
view scan settings for self-service scan
"""


def edit_scan_settings(request, pid, sid):
    old_scan = ScanSettings.objects.get(id=sid)
    pid = old_scan.product.id
    user = request.user
    if (user.is_staff or user in old_scan.product.authorized_users.all()):
        pass
    else:
        raise PermissionDenied

    if request.method == 'POST':
        if request.POST.get('edit'):
            form = ScanSettingsForm(data=request.POST, instance=old_scan)
            if form.is_valid():
                form.save()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'Scan settings saved.',
                                     extra_tags='alert-success')
                return HttpResponseRedirect(reverse('view_scan_settings', args=(old_scan.product.id, sid,)))
            else:
                messages.add_message(request,
                                     messages.ERROR,
                                     'Scan settings not saved.',
                                     extra_tags='alert-danger')
                return render(request,
                              'dojo/edit_scan_settings.html',
                              {'form': form,
                               'breadcrumbs': get_breadcrumbs(title="Scan", user=request.user),
                               'sid': sid,
                               'pid': pid})
        elif request.POST.get('delete'):
            pid = old_scan.product.id
            old_scan.delete()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Scan settings deleted.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_product', args=(pid,)))
    try:
        form = ScanSettingsForm(instance=old_scan)
    except:
        form = ScanSettingsForm()
    return render(request,
                  'dojo/edit_scan_settings.html',
                  {'form': form,
                   'breadcrumbs': get_breadcrumbs(obj=old_scan, user=request.user),
                   'sid': sid,
                   'pid': pid})


"""
Greg
status: in production
Upload a threat model at the engagement level. Threat models are stored
under media folder
"""


@user_passes_test(lambda u: u.is_staff)
def upload_threatmodel(request, eid):
    eng = Engagement.objects.get(id=eid)
    breadcrumbs = get_breadcrumbs(title="Upload a threat model", obj=eng, user=request.user)
    if request.method == 'POST':
        form = UploadThreatForm(request.POST, request.FILES)
        if form.is_valid():
            handle_uploaded_threat(request.FILES['file'], eng)
            eng.progress = 'other'
            eng.threat_model = True
            eng.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Threat model saved.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_engagement', args=(eid,)))
    else:
        form = UploadThreatForm()
    return render(request,
                  'dojo/up_threat.html',
                  {'form': form,
                   'eng': eng,
                   'breadcrumbs': breadcrumbs})


@user_passes_test(lambda u: u.is_staff)
def add_veracode_scan(request, eid):
    eng = get_object_or_404(Engagement, id=eid)

    if request.method == 'POST':
        form = UploadVeracodeForm(request.POST, request.FILES)
        if form.is_valid():
            scan_date = form.cleaned_data['scan_date']
            min_sev = form.cleaned_data['minimum_severity']
            try:
                count = handle_veracode_file(request.FILES['file'],
                                             eid,
                                             request.user,
                                             scan_date,
                                             min_sev)
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'Veracode scan processed, a total of %d findings were imported.' % count,
                                     extra_tags='alert-success')
                return HttpResponseRedirect(reverse('view_engagement', args=(eid,)))
            except NamespaceErr as nse:
                messages.add_message(request,
                                     messages.ERROR,
                                     nse.message,
                                     extra_tags='alert-danger')
    else:
        form = UploadVeracodeForm()

    return render(request,
                  'dojo/add_veracode_scan.html',
                  {'form': form,
                   'eid': eng.id,
                   'breadcrumbs': get_breadcrumbs(title="Upload a Veracode scan",
                                                  obj=eng,
                                                  user=request.user)})


@user_passes_test(lambda u: u.is_staff)
def add_burp_scan(request, eid):
    eng = get_object_or_404(Engagement, id=eid)

    if request.method == 'POST':
        form = UploadBurpForm(request.POST, request.FILES)
        if form.is_valid():
            scan_date = form.cleaned_data['scan_date']
            min_sev = form.cleaned_data['minimum_severity']
            try:
                count = handle_burp_file(request.FILES['file'],
                                         eid,
                                         request.user,
                                         scan_date,
                                         min_sev)
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'Burp scan processed, a total of %d findings were imported.' % count,
                                     extra_tags='alert-success')
                return HttpResponseRedirect(reverse('view_engagement', args=(eid,)))
            except NamespaceErr as nse:
                messages.add_message(request,
                                     messages.ERROR,
                                     nse.message,
                                     extra_tags='alert-danger')
    else:
        form = UploadBurpForm()

    return render(request,
                  'dojo/add_burp_scan.html',
                  {'form': form,
                   'eid': eng.id,
                   'breadcrumbs': get_breadcrumbs(title="Upload a Burp scan",
                                                  obj=eng,
                                                  user=request.user)})


"""
Greg
status: in production
Upload a nessus scan at the engagement level
"""


@user_passes_test(lambda u: u.is_staff)
def add_nessus_scan(request, eid):
    eng = Engagement.objects.get(id=eid)

    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            scan_date = form.cleaned_data['scan_date']
            min_sev = form.cleaned_data['minimum_severity']
            handle_uploaded_file(request.FILES['file'],
                                 eid,
                                 request.user,
                                 scan_date,
                                 min_sev)
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Nessus scan saved.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_engagement', args=(eid,)))
    else:
        form = UploadFileForm()

    return render(request,
                  'dojo/add_nessus_scan.html',
                  {'form': form,
                   'eid': eng.id,
                   'breadcrumbs': get_breadcrumbs(title="Upload a Nessus scan",
                                                  obj=eng,
                                                  user=request.user)})


"""
Greg
status: in production
Charles magic.
"""


def process_nessus_scan_file(filename, eid, user, scan_date, min_sev):
    first = True
    dat = {}

    e = Engagement.objects.get(id=eid)
    time = scan_date

    try:
        tt = Test_Type.objects.get(name="Nessus Scan")
    except Test_Type.DoesNotExist, e:
        tt = Test_Type(name="Nessus Scan")
        tt.full_clean()
        tt.save()
    # will save in development environment
    try:
        environment = Development_Environment.objects.get(name="Development")
    except Development_Environment.DoesNotExist, e:
        environment = Development_Environment(name="Development")
        environment.full_clean()
        environment.save()
    t = Test(engagement=e, test_type=tt, target_start=time,
             target_end=time, environment=environment)
    t.full_clean()
    t.save()

    content = open(filename, "rb").read().replace("\r", "\n")
    # content = re.sub("\"(.*?)\n(.*?)\"", "\"\1\2\"", content)
    # content = re.sub("(?<=\")\n", "\\\\n", content)
    with open("%s-filtered" % filename, "wb") as out:
        out.write(content)
        out.close()

    with open("%s-filtered" % filename, "rb") as scan_file:
        reader = csv.reader(scan_file,
                            lineterminator="\n",
                            quoting=csv.QUOTE_ALL)
        for row in reader:
            if first:
                heading = row
                first = False
                continue

            dat = {}
            for h in ["severity", "endpoint",
                      "title", "description",
                      "mitigation", "references",
                      "impact", "plugin_output", "port"]:
                dat[h] = None

            for i, var in enumerate(row):
                if not var:
                    continue

                var = re.sub("(\A(\\n)+|(\\n)+\Z|\\r)", "", var)
                var = re.sub("(\\n)+", "\n", var)

                if heading[i] == "CVE":
                    if re.search("(CVE|CWE)", var) is None:
                        var = "CVE-%s" % str(var)
                    if dat['references'] is not None:
                        dat['references'] = var + "\n" + dat['references']
                    else:
                        dat['references'] = var + "\n"
                elif heading[i] == "Risk":
                    if re.match("None", var) or not var:
                        dat['severity'] = "Info"
                    else:
                        dat['severity'] = var
                elif heading[i] == "Host":
                    dat['endpoint'] = var
                    endpoint, created = Endpoint.objects.get_or_create(host=var,
                                                                       product=e.product,
                                                                       protocol=None,
                                                                       path=None,
                                                                       query=None,
                                                                       fragment=None)
                elif heading[i] == "Port":
                    if var is not "None":
                        if dat['description'] is not None:
                            dat['description'] = "Ports:"
                            + var + "\n" + dat['description']
                        else:
                            dat['description'] = "Ports:" + var + "\n"

                        dat['port'] = var
                    else:
                        dat['port'] = 'n/a'

                elif heading[i] == "Name":
                    dat['title'] = var
                elif heading[i] == "Synopsis":
                    dat['description'] = var
                elif heading[i] == "Description":
                    dat['impact'] = var
                elif heading[i] == "Solution":
                    dat['mitigation'] = var
                elif heading[i] == "See Also":
                    if dat['references'] is not None:
                        dat['references'] += var
                    else:
                        dat['references'] = var
                elif heading[i] == "Plugin Output":
                    dat['plugin_output'] = "\nPlugin output(" + \
                                           dat['endpoint'] + "):" + str(var) + "\n"

            if not dat['severity']:
                dat['severity'] = "Info"
            if not dat['title']:
                continue

            if SEVERITIES[dat['severity']] > SEVERITIES[min_sev]:
                continue

            dup_find = Finding.objects.filter(test=t, title=dat['title'])
            if dup_find:
                find = dup_find[0]
                if not re.search(dat['endpoint'], find.endpoint):
                    find.endpoint += "\n" + dat['endpoint'] + ":" + dat['port']
                if (dat['plugin_output'] is not None
                    and find.description.find(dat['plugin_output']) == -1):
                    find.description += "\n" + dat['plugin_output']

            else:
                if dat['plugin_output'] is not None:
                    dat['description'] = dat['description'] + \
                                         dat['plugin_output']
                find = Finding(title=dat['title'],
                               test=t,
                               active=False,
                               verified=False, description=dat['description'],
                               severity=dat['severity'],
                               numerical_severity=get_numerical_severity(dat[
                                                                             'severity']),
                               mitigation=dat['mitigation'],
                               impact=dat['impact'],
                               references=dat['references'],
                               url=dat['endpoint'], endpoint=dat['endpoint'],
                               date=time, reporter=user)

            find.clean()
            find.save()
            if endpoint:
                find.endpoints.add(endpoint)
    os.unlink(filename)
    os.unlink("%s-filtered" % filename)


def process_veracode_file(filename, eid, user, scan_date, min_sev):
    vscan = ElementTree.parse(filename)
    root = vscan.getroot()

    if 'https://www.veracode.com/schema/reports/export/1.0' not in str(root):
        # version not supported
        os.unlink(filename)
        raise NamespaceErr('This version of Veracode report is not supported.  '
                           'Please make sure the export is formatted using the '
                           'https://www.veracode.com/schema/reports/export/1.0 schema.')

    e = Engagement.objects.get(id=eid)

    time = scan_date

    tt, t_created = Test_Type.objects.get_or_create(name="Veracode Scan")
    # will save in development environment
    environment, env_created = Development_Environment.objects.get_or_create(name="Development")

    t = Test(engagement=e, test_type=tt, target_start=time,
             target_end=time, environment=environment)
    t.full_clean()
    t.save()

    dupes = {}
    finding_count = 0

    for severity in root.iter('{https://www.veracode.com/schema/reports/export/1.0}severity'):
        if severity.attrib['level'] == '5':
            sev = 'Critical'
            if SEVERITIES[min_sev] < 0:
                continue
        elif severity.attrib['level'] == '4':
            sev = 'High'
            if SEVERITIES[min_sev] < 1:
                continue
        elif severity.attrib['level'] == '3':
            sev = 'Medium'
            if SEVERITIES[min_sev] < 2:
                continue
        elif severity.attrib['level'] == '2':
            sev = 'Low'
            if SEVERITIES[min_sev] < 3:
                continue
        else:
            sev = 'Info'
            if SEVERITIES[min_sev] < 4:
                continue

        for category in severity.iter('{https://www.veracode.com/schema/reports/export/1.0}category'):
            recommendations = category.find('{https://www.veracode.com/schema/reports/export/1.0}recommendations')
            mitigation = ''
            for para in recommendations.iter('{https://www.veracode.com/schema/reports/export/1.0}para'):
                mitigation += para.attrib['text'] + '\n\n'
                for bullet in para.iter('{https://www.veracode.com/schema/reports/export/1.0}bulletitem'):
                    mitigation += "    - " + bullet.attrib['text'] + '\n'

                for flaw in category.iter('{https://www.veracode.com/schema/reports/export/1.0}flaw'):
                    dupe_key = sev + flaw.attrib['cweid'] + flaw.attrib['module'] + flaw.attrib['type']

                    if dupe_key in dupes:
                        pass
                    else:
                        dupes[dupe_key] = True
                        description = flaw.attrib['description'].replace('. ', '.\n')
                        if 'References:' in description:
                            references = description[description.index('References:') + 13:].replace(')  ', ')\n')
                        else:
                            references = 'None'

                        if 'date_first_occurrence' in flaw.attrib:
                            find_date = datetime.strptime(flaw.attrib['date_first_occurrence'], '%Y-%m-%d %H:%M:%S %Z')
                        else:
                            find_date = scan_date

                        find = Finding(title=flaw.attrib['categoryname'],
                                       cwe=int(flaw.attrib['cweid']),
                                       test=t,
                                       active=False,
                                       verified=False,
                                       description=description + "\n\nVulnerable Module: " + flaw.attrib[
                                           'module'] + ' Type: ' + flaw.attrib['type'],
                                       severity=sev,
                                       numerical_severity=get_numerical_severity(sev),
                                       mitigation=mitigation,
                                       impact='CIA Impact: ' + flaw.attrib['cia_impact'].upper(),
                                       references=references,
                                       url='N/A',
                                       endpoint=None,
                                       date=find_date,
                                       reporter=user)

                        find.clean()
                        find.save()
                        finding_count += 1

    os.unlink(filename)
    return finding_count


def process_burp_file(filename, eid, user, scan_date, min_sev):
    finding_count = 0
    try:
        vscan = ElementTree.parse(filename)
    except ParseError as pe:
        raise NamespaceErr('The XML report is not valid.  Please make sure the request and response values '
                           'have been Base 64 encoded.')

    root = vscan.getroot()

    issues = root.iter('issue')

    if not sum(1 for e in issues):
        # no issues to import
        os.unlink(filename)
        raise NamespaceErr('There appears to be no issues to import.  Verify report and try again.')

    e = Engagement.objects.get(id=eid)

    time = scan_date

    tt, t_created = Test_Type.objects.get_or_create(name="Burp Scan")
    # will save in development environment
    environment, env_created = Development_Environment.objects.get_or_create(name="Development")

    t = Test(engagement=e, test_type=tt, target_start=time,
             target_end=time, environment=environment)
    t.full_clean()
    t.save()

    dupes = {}

    for issue in root.iter('issue'):
        sev = issue.find('severity').text
        if issue.find('severity').text == 'Information':
            sev = 'Info'

        if SEVERITIES[sev] > SEVERITIES[min_sev]:
            continue

        dupe_key = sev + issue.find('name').text + issue.find('path').text

        if dupe_key in dupes:
            pass
        else:
            dupes[dupe_key] = True
            description = issue.find('issueBackground').text + '\n\n' + issue.find('issueDetail').text if issue.find(
                'issueDetail') is not None else ''
            find_date = scan_date
            mitigation = issue.find('remediationBackground').text if issue.find(
                'remediationBackground') is not None else 'N/A'
            url = issue.find('host').text if issue.find('host') is not None else '' + issue.find(
                'location').text if issue.find('location') is not None else ''

            if issue.find('requestresponse') is not None and issue.find('requestresponse').find(
                    'request[@base64="true"]') is not None:
                req = issue.find('requestresponse').find('request[@base64="true"]').text
            else:
                req = None

            if issue.find('requestresponse') is not None and issue.find('requestresponse').find(
                    'response[@base64="true"]') is not None:
                res = issue.find('requestresponse').find('response[@base64="true"]').text
            else:
                res = None

            if issue.find('host') is not None:
                protocol, host, path, query, fragment = urlsplit(issue.find('host').text)
                path = issue.find('path').text if issue.find('path') is not None else None
                endpoint, created = Endpoint.objects.get_or_create(protocol=protocol,
                                                                   host=host,
                                                                   path=path,
                                                                   query=query,
                                                                   fragment=fragment,
                                                                   product=e.product)

            find = Finding(title=issue.find('name').text,
                           test=t,
                           active=False,
                           verified=False,
                           description=description,
                           severity=sev,
                           numerical_severity=get_numerical_severity(sev),
                           mitigation=mitigation,
                           impact='N/A',
                           references='N/A',
                           url=url,
                           endpoint=issue.find('host').text if issue.find('host') is not None else 'N/A',
                           date=find_date,
                           reporter=user)

            find.clean()
            find.save()

            if req is not None and res is not None:
                burp_rr = BurpRawRequestResponse(finding=find,
                                                 burpRequestBase64=req,
                                                 burpResponseBase64=res,
                                                 )
                burp_rr.clean()
                burp_rr.save()

            if endpoint:
                find.endpoints.add(endpoint)

        finding_count += 1

    os.unlink(filename)
    return finding_count


"""
Greg
status: in produciton
upload accepted risk at the engagement
"""


@user_passes_test(lambda u: u.is_staff)
def upload_risk(request, eid):
    eng = Engagement.objects.get(id=eid)
    # exclude the findings already accepted
    exclude_findings = [finding.id for ra in eng.risk_acceptance.all()
                        for finding in ra.accepted_findings.all()]
    eng_findings = Finding.objects.filter(test__in=eng.test_set.all()) \
        .exclude(id__in=exclude_findings).order_by('title')

    if request.method == 'POST':
        form = UploadRiskForm(request.POST, request.FILES)
        if form.is_valid():
            findings = form.cleaned_data['accepted_findings']
            for finding in findings:
                finding.active = False
                finding.save()
            risk = form.save(commit=False)
            risk.reporter = form.cleaned_data['reporter']
            risk.path = form.cleaned_data['path']
            risk.save()  # have to save before findings can be added
            risk.accepted_findings = findings
            if form.cleaned_data['notes']:
                notes = Notes(entry=form.cleaned_data['notes'],
                              author=request.user,
                              date=localtz.localize(datetime.today()))
                notes.save()
                risk.notes.add(notes)

            risk.save()  # saving notes and findings
            eng.risk_acceptance.add(risk)
            eng.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Risk acceptance saved.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_engagement', args=(eid,)))
    else:
        form = UploadRiskForm(initial={'reporter': request.user})

    form.fields["accepted_findings"].queryset = eng_findings
    return render(request, 'dojo/up_risk.html',
                  {'eng': eng, 'form': form,
                   'breadcrumbs': get_breadcrumbs(
                       title="Upload Risk Acceptance",
                       obj=eng,
                       user=request.user)})


"""
Greg
status: in produciton
file upload
"""


def handle_uploaded_file(f, eid, user, scan_date, min_sev):
    t = int(time.time())
    fname = settings.DOJO_ROOT + '/scans/scan-%s-%d' % (eid, t)
    with open(fname, 'wb+') as destination:
        for chunk in f.chunks():
            destination.write(chunk)
        destination.close()
    process_nessus_scan_file(fname, eid, user, scan_date, min_sev)


def handle_veracode_file(f, eid, user, scan_date, min_sev):
    t = int(time.time())
    fname = settings.DOJO_ROOT + '/scans/scan-%s-%d' % (eid, t)
    with open(fname, 'wb+') as destination:
        for chunk in f.chunks():
            destination.write(chunk)
        destination.close()
    return process_veracode_file(fname, eid, user, scan_date, min_sev)


def handle_burp_file(f, eid, user, scan_date, min_sev):
    t = int(time.time())
    fname = settings.DOJO_ROOT + '/scans/scan-%s-%d' % (eid, t)
    with open(fname, 'wb+') as destination:
        for chunk in f.chunks():
            destination.write(chunk)
        destination.close()
    return process_burp_file(fname, eid, user, scan_date, min_sev)


def handle_uploaded_threat(f, eng):
    name, extension = os.path.splitext(f.name)
    with open(settings.MEDIA_ROOT + '/threat/%s%s' % (eng.id, extension),
              'wb+') as destination:
        for chunk in f.chunks():
            destination.write(chunk)
    eng.tmodel_path = settings.MEDIA_ROOT + '/threat/%s%s' % (eng.id, extension)
    eng.save()


def change_password(request):
    if request.method == 'POST':
        current_pwd = request.POST['current_password']
        new_pwd = request.POST['new_password']
        user = authenticate(username=request.user.username,
                            password=current_pwd)
        if user is not None:
            if user.is_active:
                user.set_password(new_pwd)
                user.save()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'Your password has been changed.',
                                     extra_tags='alert-success')
                return HttpResponseRedirect(reverse('view_profile'))

        messages.add_message(request,
                             messages.ERROR,
                             'Your password has not been changed.',
                             extra_tags='alert-danger')

    return render(request, 'dojo/change_pwd.html',
                  {'error': ''})


def logout_view(request):
    logout(request)
    messages.add_message(request,
                         messages.SUCCESS,
                         'You have logged out successfully.',
                         extra_tags='alert-success')
    return HttpResponseRedirect(reverse('login'))


def template_search(request):
    return render(request, 'dojo/template_search.html')


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

    prods = ProductFilter(request.GET, queryset=initial_queryset, user=request.user)
    prod_list = get_page_items(request, prods, 15)

    return render(request,
                  'dojo/product.html',
                  {'prod_list': prod_list,
                   'prods': prods,
                   'name_words': sorted(set(name_words)),
                   'breadcrumbs': get_breadcrumbs(
                       title="Product list",
                       user=request.user),
                   'user': request.user})


def view_product(request, pid):
    prod = get_object_or_404(Product, id=pid)
    engs = Engagement.objects.filter(product=prod, active=True)
    i_engs = Engagement.objects.filter(product=prod, active=False)
    scan_sets = ScanSettings.objects.filter(product=prod)
    auth = request.user.is_staff or request.user in prod.authorized_users.all()
    if not auth:
        # will render 403
        raise PermissionDenied

    try:
        start_date = Finding.objects.filter(test__engagement__product=prod).order_by('date')[:1][0].date
    except:
        start_date = localtz.localize(datetime.today())

    end_date = localtz.localize(datetime.today())

    risk_acceptances = Risk_Acceptance.objects.filter(engagement__in=Engagement.objects.filter(product=prod))

    accepted_findings = [finding for ra in risk_acceptances
                         for finding in ra.accepted_findings.all()]

    verified_findings = Finding.objects.filter(test__engagement__product=prod,
                                               date__range=[start_date, end_date],
                                               false_p=False,
                                               is_template=False,
                                               verified=True,
                                               duplicate=False,
                                               out_of_scope=False)

    open_findings = Finding.objects.filter(test__engagement__product=prod,
                                           date__range=[start_date, end_date],
                                           false_p=False,
                                           is_template=False,
                                           verified=True,
                                           duplicate=False,
                                           out_of_scope=False,
                                           active=True,
                                           mitigated__isnull=True)

    closed_findings = Finding.objects.filter(test__engagement__product=prod,
                                             date__range=[start_date, end_date],
                                             false_p=False,
                                             is_template=False,
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

    return render(request,
                  'dojo/view_product.html',
                  {'prod': prod,
                   'engs': engs,
                   'i_engs': i_engs,
                   'scan_sets': scan_sets,
                   'verified_findings': verified_findings,
                   'open_findings': open_findings,
                   'closed_findings': closed_findings,
                   'accepted_findings': accepted_findings,
                   'punchcard': punchcard,
                   'ticks': ticks,
                   'highest_count': highest_count,
                   'breadcrumbs': get_breadcrumbs(obj=prod, user=request.user),
                   'user': request.user,
                   'authorized': auth})


@user_passes_test(lambda u: u.is_staff)
def view_test(request, tid):
    test = Test.objects.get(id=tid)
    notes = test.notes.all()
    person = request.user.username
    findings = Finding.objects.filter(test=test).filter(
        Q(severity="Critical") |
        Q(severity="High") |
        Q(severity="Medium") |
        Q(severity="Low") |
        Q(severity="Info")).order_by("numerical_severity", "-active")
    if request.method == 'POST':
        form = NoteForm(request.POST)
        if (form.is_valid()):
            new_note = form.save(commit=False)
            new_note.author = request.user
            new_note.date = datetime.now(tz=localtz)
            new_note.save()
            test.notes.add(new_note)
            form = NoteForm()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Note added successfully.',
                                 extra_tags='alert-success')
    else:
        form = NoteForm()

    fpage = get_page_items(request, findings, 20)
    return render(request, 'dojo/view_test.html',
                  {'test': test, 'findings': fpage,
                   'form': form, 'notes': notes,
                   'person': person, 'request': request,
                   'breadcrumbs': get_breadcrumbs(obj=test, user=request.user)})


@user_passes_test(lambda u: u.is_staff)
def edit_test(request, tid):
    test = get_object_or_404(Test, pk=tid)
    form = TestForm(instance=test)
    if request.method == 'POST':
        form = TestForm(request.POST, instance=test)
        if form.is_valid():
            form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Test saved.',
                                 extra_tags='alert-success')

    form.initial['target_start'] = test.target_start.date()
    form.initial['target_end'] = test.target_end.date()
    return render(request, 'dojo/edit_test.html',
                  {'test': test,
                   'form': form,
                   'breadcrumbs': get_breadcrumbs(obj=test, user=request.user)})


@user_passes_test(lambda u: u.is_staff)
def delete_test(request, tid):
    test = get_object_or_404(Test, pk=tid)
    eng = test.engagement
    form = DeleteTestForm(instance=test)

    from django.contrib.admin.util import NestedObjects
    from django.db import DEFAULT_DB_ALIAS

    collector = NestedObjects(using=DEFAULT_DB_ALIAS)
    collector.collect([test])
    rels = collector.nested()

    if request.method == 'POST':
        if 'id' in request.POST and str(test.id) == request.POST['id']:
            form = DeleteTestForm(request.POST, instance=test)
            if form.is_valid():
                test.delete()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'Test and relationships removed.',
                                     extra_tags='alert-success')
                return HttpResponseRedirect(reverse('view_engagement', args=(eng.id,)))

    return render(request, 'dojo/delete_test.html',
                  {'test': test,
                   'form': form,
                   'rels': rels,
                   'breadcrumbs': get_breadcrumbs(obj=test, user=request.user)})


@user_passes_test(lambda u: u.is_staff)
def delete_test_note(request, tid, nid):
    note = Notes.objects.get(id=nid)
    test = Test.objects.get(id=tid)
    if note.author == request.user:
        test.notes.remove(note)
        note.delete()
        messages.add_message(request,
                             messages.SUCCESS,
                             'Note removed.',
                             extra_tags='alert-success')
        return view_test(request, tid)
    return HttpResponseForbidden()


@user_passes_test(lambda u: u.is_staff)
def delete_finding_note(request, tid, nid):
    note = get_object_or_404(Notes, id=nid)
    if note.author == request.user:
        finding = get_object_or_404(Finding, id=tid)
        finding.notes.remove(note)
        note.delete()
        messages.add_message(request,
                             messages.SUCCESS,
                             'Note removed.',
                             extra_tags='alert-success')
        return view_finding(request, tid)
    return HttpResponseForbidden()


def view_finding(request, fid):
    finding = get_object_or_404(Finding, id=fid)
    user = request.user
    if (user.is_staff
        or user in finding.test.engagement.product.authorized_users.all()):
        pass  # user is authorized for this product
    else:
        raise PermissionDenied

    notes = finding.notes.all()

    if request.method == 'POST':
        form = NoteForm(request.POST)
        if form.is_valid():
            new_note = form.save(commit=False)
            new_note.author = request.user
            new_note.date = datetime.now(tz=localtz)
            new_note.save()
            finding.notes.add(new_note)
            form = NoteForm()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Note saved.',
                                 extra_tags='alert-success')
    else:
        form = NoteForm()

    try:
        reqres = BurpRawRequestResponse.objects.get(finding=finding)
        burp_request = base64.b64decode(reqres.burpRequestBase64)
        burp_response = base64.b64decode(reqres.burpResponseBase64)
    except:
        reqres = None
        burp_request = None
        burp_response = None

    return render(request, 'dojo/view_finding.html',
                  {'finding': finding,
                   'burp_request': burp_request,
                   'burp_response': burp_response,
                   'breadcrumbs': get_breadcrumbs(obj=finding, user=request.user),
                   'user': user, 'notes': notes, 'form': form})


@user_passes_test(lambda u: u.is_staff)
def close_finding(request, fid):
    finding = get_object_or_404(Finding, id=fid)
    # in order to close a finding, we need to capture why it was closed
    # we can do this with a Note
    if request.method == 'POST':
        form = CloseFindingForm(request.POST)

        if form.is_valid():
            now = datetime.now(tz=localtz)
            new_note = form.save(commit=False)
            new_note.author = request.user
            new_note.date = now
            new_note.save()
            finding.notes.add(new_note)
            finding.active = False
            finding.mitigated = now
            finding.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Finding closed.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_test', args=(finding.test.id,)))

    else:
        form = CloseFindingForm()

    return render(request, 'dojo/close_finding.html',
                  {'finding': finding,
                   'breadcrumbs': get_breadcrumbs(obj=finding, user=request.user),
                   'user': request.user, 'form': form})


@user_passes_test(lambda u: u.is_staff)
def delete_finding(request, fid):
    finding = get_object_or_404(Finding, id=fid)
    tid = finding.test.id
    finding.delete()
    messages.add_message(request,
                         messages.SUCCESS,
                         'Finding deleted successfully.',
                         extra_tags='alert-success')
    return HttpResponseRedirect(reverse('view_test', args=(tid,)))


@user_passes_test(lambda u: u.is_staff)
def close_eng(request, eid):
    eng = Engagement.objects.get(id=eid)
    eng.active = False
    eng.status = 'Completed'
    eng.save()
    messages.add_message(request,
                         messages.SUCCESS,
                         'Engagement closed successfully.',
                         extra_tags='alert-success')
    return HttpResponseRedirect(reverse('view_product', args=(eng.product.id,)))


@user_passes_test(lambda u: u.is_staff)
def reopen_eng(request, eid):
    eng = Engagement.objects.get(id=eid)
    eng.active = True
    eng.status = 'In Progress'
    eng.save()
    messages.add_message(request,
                         messages.SUCCESS,
                         'Engagement reopened successfully.',
                         extra_tags='alert-success')
    return HttpResponseRedirect(reverse('view_engagement', args=(eid,)))


@user_passes_test(lambda u: u.is_staff)
def view_threatmodel(request, eid):
    import mimetypes

    mimetypes.init()
    eng = get_object_or_404(Engagement, pk=eid)
    mimetype, encoding = mimetypes.guess_type(eng.tmodel_path)
    response = StreamingHttpResponse(
        FileIterWrapper(open(eng.tmodel_path)))
    fileName, fileExtension = os.path.splitext(eng.tmodel_path)
    response['Content-Disposition'] = 'attachment; filename=threatmodel' + fileExtension
    response['Content-Type'] = mimetype

    return response


def view_risk(request, eid, raid):
    risk_approval = get_object_or_404(Risk_Acceptance, pk=raid)
    eng = get_object_or_404(Engagement, pk=eid)
    if (request.user.is_staff or
                request.user in eng.product.authorized_users.all()):
        pass
    else:
        raise PermissionDenied

    a_file = risk_approval.path

    if request.method == 'POST':
        note_form = NoteForm(request.POST)
        if (note_form.is_valid()):
            new_note = note_form.save(commit=False)
            new_note.author = request.user
            new_note.date = datetime.now(tz=localtz)
            new_note.save()
            risk_approval.notes.add(new_note)
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Note added successfully.',
                                 extra_tags='alert-success')

        if 'delete_note' in request.POST:
            note = get_object_or_404(Notes, pk=request.POST['delete_note_id'])
            if note.author.username == request.user.username:
                risk_approval.notes.remove(note)
                note.delete()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'Note deleted successfully.',
                                     extra_tags='alert-success')
            else:
                messages.add_message(
                    request,
                    messages.ERROR,
                    "Since you are not the note's author, it was not deleted.",
                    extra_tags='alert-danger')

        if 'remove_finding' in request.POST:
            finding = get_object_or_404(Finding,
                                        pk=request.POST['remove_finding_id'])
            risk_approval.accepted_findings.remove(finding)
            finding.active = True
            finding.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Finding removed successfully.',
                                 extra_tags='alert-success')
        if 'replace_file' in request.POST:
            replace_form = ReplaceRiskAcceptanceForm(
                request.POST,
                request.FILES,
                instance=risk_approval)
            if replace_form.is_valid():
                risk_approval.path.delete(save=False)
                risk_approval.path = replace_form.cleaned_data['path']
                risk_approval.save()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'File replaced successfully.',
                                     extra_tags='alert-success')
        if 'add_findings' in request.POST:
            add_findings_form = AddFindingsRiskAcceptanceForm(
                request.POST,
                request.FILES,
                instance=risk_approval)
            if add_findings_form.is_valid():
                findings = add_findings_form.cleaned_data[
                    'accepted_findings']
                for finding in findings:
                    finding.active = False
                    finding.save()
                    risk_approval.accepted_findings.add(finding)
                risk_approval.save()
                messages.add_message(
                    request,
                    messages.SUCCESS,
                    'Finding%s added successfully.' % ('s'
                                                       if len(findings) > 1 else ''),
                    extra_tags='alert-success')

    note_form = NoteForm()
    replace_form = ReplaceRiskAcceptanceForm()
    add_findings_form = AddFindingsRiskAcceptanceForm()
    exclude_findings = [finding.id for ra in eng.risk_acceptance.all()
                        for finding in ra.accepted_findings.all()]
    findings = Finding.objects.filter(test__in=eng.test_set.all()) \
        .exclude(id__in=exclude_findings).order_by("title")

    add_fpage = get_page_items(request, findings, 10, 'apage')
    add_findings_form.fields[
        "accepted_findings"].queryset = add_fpage.object_list

    fpage = get_page_items(request, risk_approval.accepted_findings.order_by(
        'numerical_severity'), 15)

    authorized = (request.user == risk_approval.reporter.username
                  or request.user.is_staff)
    return render(request, 'dojo/view_risk.html',
                  {'risk_approval': risk_approval,
                   'accepted_findings': fpage,
                   'notes': risk_approval.notes.all(),
                   'a_file': a_file,
                   'eng': eng,
                   'note_form': note_form,
                   'replace_form': replace_form,
                   'add_findings_form': add_findings_form,
                   'show_add_findings_form': len(findings),
                   'request': request,
                   'add_findings': add_fpage,
                   'authorized': authorized,
                   'breadcrumbs': get_breadcrumbs(title="View Risk Acceptance",
                                                  obj=eng,
                                                  user=request.user)})


@user_passes_test(lambda u: u.is_staff)
def delete_risk(request, eid, raid):
    risk_approval = get_object_or_404(Risk_Acceptance, pk=raid)
    eng = get_object_or_404(Engagement, pk=eid)

    for finding in risk_approval.accepted_findings.all():
        finding.active = True
        finding.save()

    risk_approval.accepted_findings.clear()
    eng.risk_acceptance.remove(risk_approval)
    eng.save()

    for note in risk_approval.notes.all():
        note.delete()

    risk_approval.path.delete()
    risk_approval.delete()
    messages.add_message(request,
                         messages.SUCCESS,
                         'Risk acceptance deleted successfully.',
                         extra_tags='alert-success')
    return HttpResponseRedirect(reverse("view_engagement", args=(eng.id,)))


class FileIterWrapper(object):
    def __init__(self, flo, chunk_size=1024 ** 2):
        self.flo = flo
        self.chunk_size = chunk_size

    def next(self):
        data = self.flo.read(self.chunk_size)
        if data:
            return data
        else:
            raise StopIteration

    def __iter__(self):
        return self


def download_risk(request, eid, raid):
    import mimetypes

    mimetypes.init()

    risk_approval = get_object_or_404(Risk_Acceptance, pk=raid)
    en = get_object_or_404(Engagement, pk=eid)
    if (request.user.is_staff
        or request.user in en.product.authorized_users.all()):
        pass
    else:
        raise PermissionDenied

    response = StreamingHttpResponse(
        FileIterWrapper(open(
            settings.MEDIA_ROOT + "/" + risk_approval.path.name)))
    response['Content-Disposition'] = 'attachment; filename="%s"' \
                                      % risk_approval.filename()
    mimetype, encoding = mimetypes.guess_type(risk_approval.path.name)
    response['Content-Type'] = mimetype
    return response


@user_passes_test(lambda u: u.is_staff)
def view_engagement(request, eid):
    eng = Engagement.objects.get(id=eid)
    tests = Test.objects.filter(engagement=eng)
    risks_accepted = eng.risk_acceptance.all()

    exclude_findings = [finding.id for ra in eng.risk_acceptance.all()
                        for finding in ra.accepted_findings.all()]
    eng_findings = Finding.objects.filter(test__in=eng.test_set.all()) \
        .exclude(id__in=exclude_findings).order_by('title')

    try:
        check = Check_List.objects.get(engagement=eng)
    except:
        check = None
        pass
    form = DoneForm()
    if request.method == 'POST':
        eng.progress = 'check_list'
        eng.save()
    return render(request, 'dojo/view_eng.html',
                  {'eng': eng, 'tests': tests,
                   'check': check, 'threat': eng.tmodel_path,
                   'risk': eng.risk_path, 'form': form,
                   'risks_accepted': risks_accepted,
                   'can_add_risk': len(eng_findings),
                   'breadcrumbs': get_breadcrumbs(obj=eng, user=request.user)})


@user_passes_test(lambda u: u.is_staff)
def new_product(request):
    if request.method == 'POST':
        form = ProductForm(request.POST)
        if (form.is_valid()):
            form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Product added successfully.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('product'))
    else:
        form = ProductForm()
    return render(request, 'dojo/new_product.html',
                  {'form': form,
                   'breadcrumbs': get_breadcrumbs(title="New Product", user=request.user)})


@user_passes_test(lambda u: u.is_staff)
def edit_product(request, pid):
    prod = Product.objects.get(pk=pid)
    if request.method == 'POST':
        form = ProductForm(request.POST, instance=prod)
        if (form.is_valid()):
            form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Product updated successfully.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_product', args=(pid,)))
    else:
        form = ProductForm(instance=prod,
                           initial={'auth_users': prod.authorized_users.all()})
    return render(request,
                  'dojo/edit_product.html',
                  {'form': form,
                   'product': prod,
                   'breadcrumbs': get_breadcrumbs(title="Edit product",
                                                  obj=prod,
                                                  user=request.user)})


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
                product.delete()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'Product and relationships removed.',
                                     extra_tags='alert-success')
                return HttpResponseRedirect(reverse('product'))

    return render(request, 'dojo/delete_product.html',
                  {'product': product,
                   'form': form,
                   'rels': rels,
                   'breadcrumbs': get_breadcrumbs(title="Delete Product", obj=product, user=request.user)})


@user_passes_test(lambda u: u.is_staff)
def engagement(request):
    filtered = EngagementFilter(request.GET, queryset=Product.objects.filter(
        ~Q(engagement=None),
        engagement__active=True, ).distinct())
    prods = get_page_items(request, filtered, 15)
    name_words = [product.name for product in
                  Product.objects.filter(
                      ~Q(engagement=None),
                      engagement__active=True, ).distinct()]
    eng_words = [engagement.name for product in
                 Product.objects.filter(
                     ~Q(engagement=None),
                     engagement__active=True, ).distinct()
                 for engagement in product.engagement_set.all()]
    return render(request, 'dojo/engagement.html',
                  {'products': prods,
                   'filtered': filtered,
                   'name_words': sorted(set(name_words)),
                   'eng_words': sorted(set(eng_words)),
                   'breadcrumbs': get_breadcrumbs(title="Active engagements", user=request.user)})


@user_passes_test(lambda u: u.is_staff)
def new_engagement(request):
    if request.method == 'POST':
        form = EngForm2(request.POST)
        if (form.is_valid()):
            new_eng = form.save()
            new_eng.lead = request.user
            new_eng.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Engagement added successfully.',
                                 extra_tags='alert-success')
            if "_Add Tests" in request.POST:
                return HttpResponseRedirect(reverse('add_tests', args=(new_eng.id,)))
            else:
                return HttpResponseRedirect(reverse('view_engagement', args=(new_eng.id,)))
    else:
        form = EngForm2()

    return render(request, 'dojo/new_eng.html',
                  {'form': form,
                   'breadcrumbs': get_breadcrumbs(title="New Engagement", user=request.user)})


@user_passes_test(lambda u: u.is_staff)
def edit_engagement(request, eid):
    eng = Engagement.objects.get(pk=eid)
    if request.method == 'POST':
        form = EngForm2(request.POST, instance=eng)
        if (form.is_valid()):
            form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Engagement updated successfully.',
                                 extra_tags='alert-success')
            if '_Add Tests' in request.POST:
                return HttpResponseRedirect(reverse('add_tests', args=(eng.id,)))
            else:
                return HttpResponseRedirect(reverse('view_engagement', args=(eng.id,)))
    else:
        form = EngForm2(instance=eng)
    return render(request, 'dojo/new_eng.html',
                  {'form': form, 'edit': True,
                   'breadcrumbs': get_breadcrumbs(title="Edit Engagement",
                                                  obj=eng,
                                                  user=request.user)})


@user_passes_test(lambda u: u.is_staff)
def delete_engagement(request, eid):
    engagement = get_object_or_404(Engagement, pk=eid)
    product = engagement.product
    form = DeleteEngagementForm(instance=engagement)

    from django.contrib.admin.util import NestedObjects
    from django.db import DEFAULT_DB_ALIAS

    collector = NestedObjects(using=DEFAULT_DB_ALIAS)
    collector.collect([engagement])
    rels = collector.nested()

    if request.method == 'POST':
        if 'id' in request.POST and str(engagement.id) == request.POST['id']:
            form = DeleteEngagementForm(request.POST, instance=engagement)
            if form.is_valid():
                engagement.delete()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'Engagement and relationships removed.',
                                     extra_tags='alert-success')
                return HttpResponseRedirect(reverse('view_product', args=(product.id,)))

    return render(request, 'dojo/delete_engagement.html',
                  {'engagement': engagement,
                   'form': form,
                   'rels': rels,
                   'breadcrumbs': get_breadcrumbs(title="Delete Engagement", obj=engagement, user=request.user)})


@user_passes_test(lambda u: u.is_staff)
def new_eng_for_app(request, pid):
    prod = Product.objects.get(id=pid)
    if request.method == 'POST':
        form = EngForm(request.POST)
        if (form.is_valid()):
            new_eng = form.save(commit=False)
            new_eng.product = prod
            if new_eng.threat_model:
                new_eng.progress = 'threat_model'
            else:
                new_eng.progress = 'other'
            new_eng.save()
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
    return render(request, 'dojo/new_eng.html',
                  {'form': form, 'pid': pid,
                   'breadcrumbs': get_breadcrumbs(title="New Engagement",
                                                  obj=prod,
                                                  user=request.user)})


@user_passes_test(lambda u: u.is_staff)
def add_tests(request, eid):
    eng = Engagement.objects.get(id=eid)
    if request.method == 'POST':
        form = TestForm(request.POST)
        if (form.is_valid()):
            new_test = form.save(commit=False)
            new_test.engagement = eng
            new_test.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Test added successfully.',
                                 extra_tags='alert-success')
            if '_Add Another Test' in request.POST:
                return HttpResponseRedirect(reverse('add_tests', args=(eng.id,)))
            elif '_Add Findings' in request.POST:
                return HttpResponseRedirect(reverse('add_findings', args=(new_test.id,)))
            elif '_Finished' in request.POST:
                return HttpResponseRedirect(reverse('view_engagement', args=(eng.id,)))
    else:
        form = TestForm()
    return render(request, 'dojo/add_tests.html',
                  {'form': form, 'eid': eid,
                   'breadcrumbs': get_breadcrumbs(title="Add Tests", obj=eng, user=request.user)})


def calc(request, last_month):
    last_month = int(last_month)
    findings = Finding.objects.filter(
        active=True, verified=True, mitigated__isnull=True)
    findings = findings.filter(Q(severity="Critical")
                               | Q(severity="High")
                               | Q(severity="Medium")
                               | Q(severity="Low"))
    count = 0
    for find in findings:
        count = count + 1
        if count >= last_month:
            find.date = datetime.now(tz=localtz).date()
            find.save()
    return HttpResponseRedirect(reverse('login'))


def get_numerical_severity(s):
    if s == 'Critical':
        return 'S0'
    elif s == 'High':
        return 'S1'
    elif s == 'Medium':
        return 'S2'
    elif s == 'Low':
        return 'S3'
    else:
        return 'S4'


@user_passes_test(lambda u: u.is_staff)
def add_findings(request, tid):
    test = Test.objects.get(id=tid)
    findings = Finding.objects.filter(is_template=True).distinct()
    form = AddFindingForm()

    if request.method == 'POST':
        form = AddFindingForm(request.POST)
        if form.is_valid():
            new_finding = form.save(commit=False)
            new_finding.test = test
            new_finding.reporter = request.user
            new_finding.numerical_severity = get_numerical_severity(
                new_finding.severity)
            if new_finding.false_p or new_finding.active is False:
                new_finding.mitigated = datetime.now(tz=localtz)

            new_finding.save()

            new_finding.endpoints = form.cleaned_data['endpoints']

            new_finding.save()

            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Finding added successfully.',
                                 extra_tags='alert-success')
            if '_Finished' in request.POST:
                return HttpResponseRedirect(reverse('view_test', args=(test.id,)))
            else:
                return HttpResponseRedirect(reverse('add_findings', args=(test.id,)))

    return render(request, 'dojo/add_findings.html',
                  {'form': form, 'findings': findings,
                   'test': test,
                   'temp': False, 'tid': tid,
                   'breadcrumbs': get_breadcrumbs(title="Add finding",
                                                  obj=test,
                                                  user=request.user)})


@user_passes_test(lambda u: u.is_staff)
def add_temp_finding(request, tid, fid):
    test = get_object_or_404(Test, id=tid)
    finding = get_object_or_404(Finding, id=fid)
    findings = Finding.objects.all()
    if request.method == 'POST':
        form = FindingForm(request.POST)
        new_finding = form.save(commit=False)
        new_finding.test = test
        new_finding.reporter = request.user
        new_finding.numerical_severity = get_numerical_severity(
            new_finding.severity)
        new_finding.date = datetime.today()
        if new_finding.false_p or new_finding.active is False:
            new_finding.mitigated = datetime.now(tz=localtz)
        # new_finding.pk = None
        new_finding.save()
        messages.add_message(request,
                             messages.SUCCESS,
                             'Temp finding added successfully.',
                             extra_tags='alert-success')
        return HttpResponseRedirect(reverse('view_test', args=(test.id,)))

    else:
        form = FindingForm(instance=finding)
    return render(request, 'dojo/add_findings.html',
                  {'form': form, 'findings': findings,
                   'temp': True, 'fid': finding.id,
                   'tid': test.id,
                   'breadcrumbs': get_breadcrumbs(title="Add finding",
                                                  obj=test,
                                                  user=request.user)})


@user_passes_test(lambda u: u.is_staff)
def edit_finding(request, fid):
    finding = get_object_or_404(Finding, id=fid)
    form = FindingForm(instance=finding)
    if request.method == 'POST':
        form = FindingForm(request.POST, instance=finding)
        if form.is_valid():
            new_finding = form.save(commit=False)
            new_finding.test = finding.test
            new_finding.numerical_severity = get_numerical_severity(
                new_finding.severity)
            if new_finding.false_p or new_finding.active is False:
                new_finding.mitigated = datetime.now(tz=localtz)
            if new_finding.active is True:
                new_finding.false_p = False
                new_finding.mitigated = None

            new_finding.endpoints = form.cleaned_data['endpoints']
            new_finding.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Finding saved successfully.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_test', args=(new_finding.test.id,)))

    form.fields['endpoints'].queryset = finding.endpoints.all()

    return render(request, 'dojo/edit_findings.html',
                  {'form': form,
                   'finding': finding,
                   'breadcrumbs': get_breadcrumbs(title="Edit finding",
                                                  obj=finding,
                                                  user=request.user)})


@user_passes_test(lambda u: u.is_staff)
def product_type_report(request, ptid):
    product_type = get_object_or_404(Product_Type, id=ptid)
    return generate_report(request, product_type)


def product_report(request, pid):
    product = get_object_or_404(Product, id=pid)
    if request.user.is_staff or request.user in product.authorized_users.all():
        pass  # user is authorized for this product
    else:
        raise PermissionDenied
    return generate_report(request, product)


def product_findings_report(request):
    if request.user.is_staff:
        findings = Finding.objects.filter(is_template=False).distinct()
    else:
        findings = Finding.objects.filter(is_template=False,
                                          test__engagement__product__authorized_users__in=[request.user]).distinct()

    return generate_report(request, findings)


@user_passes_test(lambda u: u.is_staff)
def engagement_report(request, eid):
    engagement = get_object_or_404(Engagement, id=eid)
    return generate_report(request, engagement)


@user_passes_test(lambda u: u.is_staff)
def test_report(request, tid):
    test = get_object_or_404(Test, id=tid)
    return generate_report(request, test)


def endpoint_report(request, eid):
    endpoint = get_object_or_404(Endpoint, id=eid)
    if request.user.is_staff or request.user in endpoint.product.authorized_users.all():
        pass  # user is authorized for this product
    else:
        raise PermissionDenied

    return generate_report(request, endpoint)


def product_endpoint_report(request, pid):
    product = get_object_or_404(Product, id=pid)
    endpoints = Endpoint.objects.filter(product=product,
                                        finding__active=True,
                                        finding__verified=True,
                                        finding__false_p=False,
                                        finding__duplicate=False,
                                        finding__out_of_scope=False,
                                        finding__is_template=False)

    if request.user.is_staff or request.user in product.authorized_users.all():
        pass  # user is authorized for this product
    else:
        raise PermissionDenied
    breadcrumbs = get_breadcrumbs(obj=product, title="Vulnerable Product Endpoints Report", user=request.user)
    endpoints = EndpointReportFilter(request.GET, queryset=endpoints)
    paged_endpoints = get_page_items(request, endpoints, 30)
    report_format = request.GET.get('report_type', 'AsciiDoc')
    include_finding_notes = int(request.GET.get('include_finding_notes', 0))
    include_executive_summary = int(request.GET.get('include_executive_summary', 0))
    include_table_of_contents = int(request.GET.get('include_table_of_contents', 0))
    generate = "_generate" in request.GET

    if generate:
        if report_format == 'AsciiDoc':
            return render(request,
                          'dojo/asciidoc_report.html',
                          {'product_type': None,
                           'product': product,
                           'engagement': None,
                           'test': None,
                           'endpoints': endpoints,
                           'endpoint': None,
                           'findings': None,
                           'include_finding_notes': include_finding_notes,
                           'include_executive_summary': include_executive_summary,
                           'include_table_of_contents': include_table_of_contents,
                           'user': request.user,
                           'title': 'Generate Report',
                           'breadcrumbs': breadcrumbs})
        elif report_format == 'PDF':
            if len(endpoints) <= 50:
                return render_to_pdf_response(request,
                                              'dojo/pdf_report.html',
                                              {'product_type': None,
                                               'product': product,
                                               'engagement': None,
                                               'test': None,
                                               'endpoints': endpoints,
                                               'endpoint': None,
                                               'findings': None,
                                               'include_finding_notes': include_finding_notes,
                                               'include_executive_summary': include_executive_summary,
                                               'include_table_of_contents': include_table_of_contents,
                                               'user': request.user,
                                               'title': 'Generate Report', },
                                              filename='product_endpoint_report', )
            else:
                messages.add_message(request,
                                     messages.ERROR,
                                     'PDF reports are limited to endpoint counts of 50 or less. Please use the '
                                     'filters below to reduce the number of endpoints.',
                                     extra_tags='alert-danger')
        else:
            raise Http404()

    return render(request,
                  'dojo/request_endpoint_report.html',
                  {"endpoints": paged_endpoints,
                   "filtered": endpoints,
                   "name": "Vulnerable Product Endpoints",
                   'breadcrumbs': breadcrumbs})


def generate_report(request, obj):
    product_type = None
    product = None
    engagement = None
    test = None
    endpoint = None
    user = Dojo_User.objects.get(id=request.user.id)
    if type(obj).__name__ == "Product":
        if request.user.is_staff or request.user in obj.authorized_users.all():
            pass  # user is authorized for this product
        else:
            raise PermissionDenied
    elif type(obj).__name__ == "Endpoint":
        if request.user.is_staff or request.user in obj.product.authorized_users.all():
            pass  # user is authorized for this product
        else:
            raise PermissionDenied
    elif type(obj).__name__ == "QuerySet":
        # authorization taken care of by only selecting findings from product user is authed to see
        pass
    else:
        if not request.user.is_staff:
            raise PermissionDenied

    report_format = request.GET.get('report_type', 'AsciiDoc')
    include_finding_notes = int(request.GET.get('include_finding_notes', 0))
    include_executive_summary = int(request.GET.get('include_executive_summary', 0))
    include_table_of_contents = int(request.GET.get('include_table_of_contents', 0))
    generate = "_generate" in request.GET

    breadcrumbs = get_breadcrumbs(obj=obj, title="Generate Report", user=request.user)
    if type(obj).__name__ == "Product_Type":
        product_type = obj
        findings = ReportFindingFilter(request.GET, queryset=Finding.objects.filter(
            test__engagement__product__prod_type=product_type, is_template=False).distinct())
        filename = "product_type_finding_report.pdf"
    elif type(obj).__name__ == "Product":
        product = obj
        findings = ReportFindingFilter(request.GET, queryset=Finding.objects.filter(test__engagement__product=product,
                                                                                    is_template=False).distinct())
        filename = "product_finding_report.pdf"
    elif type(obj).__name__ == "Engagement":
        engagement = obj
        findings = ReportFindingFilter(request.GET, queryset=Finding.objects.filter(test__engagement=engagement,
                                                                                    is_template=False).distinct())
        filename = "engagement_finding_report.pdf"
    elif type(obj).__name__ == "Test":
        test = obj
        findings = ReportFindingFilter(request.GET, queryset=Finding.objects.filter(test=test,
                                                                                    is_template=False).distinct())
        filename = "test_finding_report.pdf"
    elif type(obj).__name__ == "Endpoint":
        endpoint = obj
        findings = ReportFindingFilter(request.GET, queryset=Finding.objects.filter(endpoints__in=[endpoint],
                                                                                    is_template=False).distinct())
        filename = "endpoint_finding_report.pdf"
    elif type(obj).__name__ == "QuerySet":
        findings = ReportAuthedFindingFilter(request.GET, queryset=obj.distinct(), user=request.user)
        filename = "finding_report.pdf"
        breadcrumbs = get_breadcrumbs(title="Generate Report", user=request.user)
    else:
        raise Http404()

    if generate:
        if report_format == 'AsciiDoc':
            return render(request,
                          'dojo/asciidoc_report.html',
                          {'product_type': product_type,
                           'product': product,
                           'engagement': engagement,
                           'test': test,
                           'endpoint': endpoint,
                           'findings': findings,
                           'include_finding_notes': include_finding_notes,
                           'include_executive_summary': include_executive_summary,
                           'include_table_of_contents': include_table_of_contents,
                           'user': user,
                           'title': 'Generate Report',
                           'breadcrumbs': breadcrumbs})
        elif report_format == 'PDF':
            if len(findings) <= 150:
                return render_to_pdf_response(request,
                                              'dojo/pdf_report.html',
                                              {'product_type': product_type,
                                               'product': product,
                                               'engagement': engagement,
                                               'test': test,
                                               'endpoint': endpoint,
                                               'findings': findings,
                                               'include_finding_notes': include_finding_notes,
                                               'include_executive_summary': include_executive_summary,
                                               'include_table_of_contents': include_table_of_contents,
                                               'user': user,
                                               'title': 'Generate Report'},
                                              filename=filename, )
            else:
                messages.add_message(request,
                                     messages.ERROR,
                                     'PDF reports are limited to finding counts of 150 or less. Please use the '
                                     'filters below to reduce the number of findings.',
                                     extra_tags='alert-danger')
        else:
            raise Http404()
    paged_findings = get_page_items(request, findings, 30)
    return render(request, 'dojo/request_report.html',
                  {'product_type': product_type,
                   'product': product,
                   'engagement': engagement,
                   'test': test,
                   'endpoint': endpoint,
                   'findings': findings,
                   'paged_findings': paged_findings,
                   'breadcrumbs': breadcrumbs})


@user_passes_test(lambda u: u.is_staff)
def mktemplate(request, fid):
    finding = get_object_or_404(Finding, id=fid)
    finding.is_template = True
    finding.save()
    messages.add_message(request,
                         messages.SUCCESS,
                         'Finding template added successfully.',
                         extra_tags='alert-success')
    return HttpResponseRedirect(reverse('view_finding', args=(finding.id,)))


def named_month(month_number):
    """
    Return the name of the month, given the number.
    """
    return date(1900, month_number, 1).strftime("%B")


@user_passes_test(lambda u: u.is_staff)
def calendar(request):
    engagements = Engagement.objects.all()
    return render(request, 'dojo/calendar.html', {
        'engagements': engagements,
        'breadcrumbs': get_breadcrumbs(title="Calendar", user=request.user)})


def normalize_query(query_string,
                    findterms=re.compile(r'"([^"]+)"|(\S+)').findall,
                    normspace=re.compile(r'\s{2,}').sub):
    return [normspace(' ',
                      (t[0] or t[1]).strip()) for t in findterms(query_string)]


def build_query(query_string, search_fields):
    ''' Returns a query, that is a combination of Q objects. That combination
    aims to search keywords within a model by testing the given search fields.

    '''
    query = None  # Query to search for every search term
    terms = normalize_query(query_string)
    for term in terms:
        or_query = None  # Query to search for a given term in each field
        for field_name in search_fields:
            q = Q(**{"%s__icontains" % field_name: term})

            if or_query:
                or_query = or_query | q
            else:
                or_query = q

        if query:
            query = query & or_query
        else:
            query = or_query
    return query


def template_search_helper(
        fields=['title', 'description', ], query_string=None):
    findings = Finding.objects.filter(is_template=True).distinct()

    if not query_string:
        return findings

    entry_query = build_query(query_string, fields)
    found_entries = findings.filter(entry_query)

    return found_entries


def search(request, tid):
    query_string = ''
    found_entries = Finding.objects.filter(is_template=True).distinct()
    if ('q' in request.GET) and request.GET['q'].strip():
        query_string = request.GET['q']
        found_entries = template_search_helper(
            fields=['title', 'description', ],
            query_string=query_string)
    else:
        found_entries = template_search_helper(
            fields=['title', 'description', ])

    return render(request,
                  'dojo/search_results.html',
                  {'query_string': query_string,
                   'found_entries': found_entries,
                   'tid': tid})


def get_breadcrumbs(obj=None, active=True, title=None, user=None):
    """Breadcrumb structure
    active: T/F
    title
    link
    """
    result = [{"active": False,
               "title": "Home",
               "link": reverse('home')}]

    if title is None:
        if type(obj).__name__ == "Product_Type":
            p = Product_Type.objects.get(id=obj.id)
            result.append({"active": False,
                           "title": p.name,
                           "link": reverse('product_type') if user and user.is_staff else None})
        elif type(obj).__name__ == "Product":
            p = Product.objects.get(id=obj.id)
            result = get_breadcrumbs(p.prod_type, True, user=user)
            result.append({"active": False,
                           "title": "Product",
                           "link": reverse('product')})
            result.append({"active": active,
                           "title": obj.name,
                           "link": reverse("view_product", args=(obj.id,))})

        elif type(obj).__name__ == "Engagement":
            p = Product.objects.get(id=obj.product_id)
            result = get_breadcrumbs(p, False, user=user)
            result.append({"active": active,
                           "title": obj,
                           "link": reverse('view_engagement', args=(obj.id,)) if user and user.is_staff else None})
        elif type(obj).__name__ == "Endpoint":
            p = Product.objects.get(id=obj.product.id)
            result = get_breadcrumbs(p, False, user=user)
            result.append({"active": False,
                           "title": "Endpoint",
                           "link": reverse('endpoints') + "?product=" + str(p.id)})
            result.append({"active": active,
                           "title": str(obj)[:70],
                           "link": reverse('view_endpoint', args=(obj.id,))})
        elif type(obj).__name__ == "Test":
            e = Engagement.objects.get(id=obj.engagement_id)
            result = get_breadcrumbs(e, False, user=user)
            result.append({"active": active,
                           "title": obj,
                           "link": reverse('view_test', args=(obj.id,)) if user and user.is_staff else None})

        elif type(obj).__name__ == "Finding":
            t = Test.objects.get(id=obj.test_id)
            result = get_breadcrumbs(t, False, user=user)
            result.append({"active": True,
                           "title": obj.title,
                           "link": reverse('view_finding', args=(obj.id,))})
        elif type(obj).__name__ == "ScanSettings":
            result = get_breadcrumbs(obj.product, False, user=user)
            result.append({"active": active,
                           "title": "%s Scan Settings" % obj.frequency,
                           "link": reverse('view_scan_settings', args=(obj.product.id, obj.id,))})
        elif type(obj).__name__ == "Scan":
            result = get_breadcrumbs(obj.scan_settings, False, user=user)
            result.append({"active": active,
                           "title": "%s Scan on %s" % (
                               obj.protocol,
                               obj.date.astimezone(localtz).strftime(
                                   "%b. %d, %Y, %I:%M %p")),
                           "link": reverse('view_scan', args=(obj.id,))})
        else:
            result.append({"active": True,
                           "title": title,
                           "link": ""})
    else:
        if obj:
            result = get_breadcrumbs(obj, False, user=user)
        result.append({"active": True,
                       "title": title,
                       "link": ""})
    return result


"""
Jay
status: in development, testing in prod
simple search with special consideration for IP addresses and CVEs
"""


def simple_search(request):
    ip_addresses = []
    dashes = []
    query = []
    tests = None
    findings = None
    products = None
    clean_query = ''
    cookie = False
    terms = ''
    if request.method == 'GET' and "query" in request.GET:
        form = SimpleSearchForm(request.GET)
        if form.is_valid():
            cookie = True
            clean_query = request.GET['query']
            terms = form.cleaned_data['query'].split()
            if request.user.is_staff:
                q = Q()
                for term in terms:
                    try:
                        validate_ipv46_address(term)
                        ip_addresses.append(term)
                    except:
                        if "-" in term:
                            dashes.append(term)
                        else:
                            query.append(term)

                for qy in query:
                    q.add((Q(notes__entry__icontains=qy) |
                           Q(finding__title__icontains=qy) |
                           Q(finding__url__icontains=qy) |
                           Q(finding__description__icontains=qy) |
                           Q(finding__references__icontains=qy) |
                           Q(finding__mitigation__icontains=qy) |
                           Q(finding__impact__icontains=qy) |
                           Q(finding__endpoint__icontains=qy)), Q.OR)

                for ip in ip_addresses:
                    q.add(Q(finding__endpoint__icontains=ip), Q.OR)
                dash_query = ''
                for dash in dashes:
                    dash_query = dash
                    q.add(Q(finding__title__icontains=dash_query) |
                          Q(finding__url__icontains=dash_query) |
                          Q(finding__description__icontains=dash_query) |
                          Q(finding__endpoint__icontains=dash_query) |
                          Q(finding__references__icontains=dash_query) |
                          Q(finding__mitigation__icontains=dash_query) |
                          Q(finding__impact__icontains=dash_query) |
                          Q(notes__entry__icontains=dash_query), Q.OR)

                tests = Test.objects.filter(q).order_by("-target_start")

            q = Q()
            for qy in query:
                q.add((Q(notes__entry__icontains=qy) |
                       Q(title__icontains=qy) |
                       Q(url__icontains=qy) |
                       Q(description__icontains=qy) |
                       Q(references__icontains=qy) |
                       Q(mitigation__icontains=qy) |
                       Q(impact__icontains=qy) |
                       Q(endpoint__icontains=qy)), Q.OR)
            for ip in ip_addresses:
                q.add(Q(endpoint__icontains=ip) | Q(references__icontains=ip),
                      Q.OR)

            dash_query = ''
            for dash in dashes:
                dash_query = dash
                q.add(Q(title__icontains=dash_query) |
                      Q(url__icontains=dash_query) |
                      Q(description__icontains=dash_query) |
                      Q(endpoint__icontains=dash_query) |
                      Q(references__icontains=dash_query) |
                      Q(mitigation__icontains=dash_query) |
                      Q(impact__icontains=dash_query) |
                      Q(notes__entry__icontains=dash_query), Q.OR)

            findings = Finding.objects.filter(q).order_by("-date")

            if not request.user.is_staff:
                findings = findings.filter(
                    test__engagement__product__authorized_users__in=[
                        request.user])

            q = Q()
            for qy in query:
                q.add((Q(name__icontains=qy) |
                       Q(description__icontains=qy)), Q.OR)
            dash_query = ''
            for dash in dashes:
                dash_query = dash
                q.add(Q(name=dash_query) |
                      Q(description=dash_query), Q.OR)
            products = Product.objects.filter(q).order_by('name')
            if not request.user.is_staff:
                products = products.filter(
                    authorized_users__in=[
                        request.user])
        else:
            form = SimpleSearchForm()

        response = render(request, 'dojo/simple_search.html', {
            'clean_query': clean_query,
            'tests': tests,
            'findings': findings,
            'products': products,
            'name': 'Simple Search',
            'breadcrumbs': get_breadcrumbs(title="Simple Search", user=request.user),
            'metric': False,
            'user': request.user,
            'form': form})

    if cookie:
        response.set_cookie("highlight", value=clean_query,
                            max_age=None, expires=None,
                            path='/', secure=True, httponly=False)
    else:
        response.delete_cookie("highlight", path='/')
    return response


def api_key(request):
    api_key = ''
    if request.method == 'POST':  # new key requested
        try:
            api_key = ApiKey.objects.get(user=request.user)
            api_key.key = None
            api_key.save()
        except ApiKey.DoesNotExist:
            api_key = ApiKey.objects.create(user=request.user)
        messages.add_message(request,
                             messages.SUCCESS,
                             'API Key generated successfully.',
                             extra_tags='alert-success')
    else:
        try:
            api_key = ApiKey.objects.get(user=request.user)
        except ApiKey.DoesNotExist:
            api_key = ApiKey.objects.create(user=request.user)
    return render(request, 'dojo/api_key.html',
                  {'name': 'API Key',
                   'breadcrumbs': get_breadcrumbs(title="API Key", user=request.user),
                   'metric': False,
                   'user': request.user,
                   'key': api_key,
                   })


"""
Jay
Status: in prod
Product Type views
"""


def product_type(request):
    ptl = Product_Type.objects.all().order_by('name')
    pts = get_page_items(request, ptl, 15)
    return render(request, 'dojo/product_type.html', {
        'name': 'Product Type List',
        'breadcrumbs': get_breadcrumbs(title="Product Type List", user=request.user),
        'metric': False,
        'user': request.user,
        'pts': pts})


@user_passes_test(lambda u: u.is_staff)
def add_product_type(request):
    form = Product_TypeForm()
    if request.method == 'POST':
        form = Product_TypeForm(request.POST)
        if form.is_valid():
            form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Product type added successfully.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('product_type'))

    return render(request, 'dojo/new_product_type.html', {
        'name': 'Add Product Type',
        'breadcrumbs': get_breadcrumbs(title="Add Product Type", user=request.user),
        'metric': False,
        'user': request.user,
        'form': form,
    })


@user_passes_test(lambda u: u.is_staff)
def edit_product_type(request, ptid):
    pt = get_object_or_404(Product_Type, pk=ptid)
    form = Product_TypeForm(instance=pt)
    if request.method == 'POST':
        form = Product_TypeForm(request.POST, instance=pt)
        if form.is_valid():
            pt = form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Product type updated successfully.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('product_type'))

    return render(request, 'dojo/edit_product_type.html', {
        'name': 'Edit Product Type',
        'breadcrumbs': get_breadcrumbs(title="Edit Product Type", user=request.user),
        'metric': False,
        'user': request.user,
        'form': form,
        'pt': pt})


@user_passes_test(lambda u: u.is_staff)
def add_product_to_product_type(request, ptid):
    pt = get_object_or_404(Product_Type, pk=ptid)
    form = Product_TypeProductForm(initial={'prod_type': pt})
    return render(request, 'dojo/new_product.html',
                  {'form': form,
                   'breadcrumbs': get_breadcrumbs(
                       title="New %s Product" % (pt.name),
                       user=request.user)})


"""
Jay
Status: in prod
Test Type views
"""


@user_passes_test(lambda u: u.is_staff)
def test_type(request):
    test_types = Test_Type.objects.all().order_by('name')
    tts = get_page_items(request, test_types, 15)
    return render(request, 'dojo/test_type.html', {
        'name': 'Test Type List',
        'breadcrumbs': get_breadcrumbs(title="Test Type List", user=request.user),
        'metric': False,
        'user': request.user,
        'tts': tts})


@user_passes_test(lambda u: u.is_staff)
def add_test_type(request):
    form = Test_TypeForm()
    if request.method == 'POST':
        form = Test_TypeForm(request.POST)
        if form.is_valid():
            form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Test type added successfully.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('test_type'))

    return render(request, 'dojo/new_test_type.html', {
        'name': 'Add Test Type',
        'breadcrumbs': get_breadcrumbs(title="Add Test Type", user=request.user),
        'metric': False,
        'user': request.user,
        'form': form,
    })


@user_passes_test(lambda u: u.is_staff)
def edit_test_type(request, ptid):
    tt = get_object_or_404(Test_Type, pk=ptid)
    form = Test_TypeForm(instance=tt)
    if request.method == 'POST':
        form = Test_TypeForm(request.POST, instance=tt)
        if form.is_valid():
            tt = form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Test type updated successfully.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('test_type'))

    return render(request, 'dojo/edit_test_type.html', {
        'name': 'Edit Test Type',
        'breadcrumbs': get_breadcrumbs(title="Edit Test Type", user=request.user),
        'metric': False,
        'user': request.user,
        'form': form,
        'pt': tt})


@user_passes_test(lambda u: u.is_staff)
def dev_env(request):
    devs = Development_Environment.objects.all().order_by('name')
    dev_page = get_page_items(request, devs, 15)
    return render(request, 'dojo/dev_env.html', {
        'name': 'Development Environment List',
        'breadcrumbs': get_breadcrumbs(title="Development Environment List", user=request.user),
        'metric': False,
        'user': request.user,
        'devs': dev_page})


@user_passes_test(lambda u: u.is_staff)
def add_dev_env(request):
    form = Development_EnvironmentForm()
    if request.method == 'POST':
        form = Development_EnvironmentForm(request.POST)
        if form.is_valid():
            form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Development environment added successfully.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('dev_env'))

    return render(request, 'dojo/new_dev_env.html', {
        'name': 'Add Development Environment',
        'breadcrumbs': get_breadcrumbs(title="Add Development Environment", user=request.user),
        'metric': False,
        'user': request.user,
        'form': form,
    })


@user_passes_test(lambda u: u.is_staff)
def edit_dev_env(request, deid):
    de = get_object_or_404(Development_Environment, pk=deid)
    form = Development_EnvironmentForm(instance=de)
    if request.method == 'POST':
        form = Development_EnvironmentForm(request.POST, instance=de)
        if form.is_valid():
            de = form.save()
            messages.add_message(
                request,
                messages.SUCCESS,
                'Development environment updated successfully.',
                extra_tags='alert-success')
            return HttpResponseRedirect(reverse('dev_env'))

    return render(request, 'dojo/edit_dev_env.html', {
        'name': 'Edit Development Environment',
        'breadcrumbs': get_breadcrumbs(title="Edit Development Environment", user=request.user),
        'metric': False,
        'user': request.user,
        'form': form,
        'de': de})


def view_profile(request):
    user = get_object_or_404(Dojo_User, pk=request.user.id)
    form = DojoUserForm(instance=user)
    if request.method == 'POST':
        form = DojoUserForm(request.POST, instance=user)
        if form.is_valid():
            form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Profile updated successfully.',
                                 extra_tags='alert-success')

    return render(request, 'dojo/profile.html', {
        'name': 'Engineer Profile',
        'breadcrumbs': get_breadcrumbs(
            title="Engineer Profile - " + user.get_full_name(), user=request.user),
        'metric': False,
        'user': user,
        'form': form})


@user_passes_test(lambda u: u.is_staff)
def dashboard(request):
    now = localtz.localize(datetime.today())
    seven_days_ago = now - timedelta(days=7)
    engagement_count = Engagement.objects.filter(lead=request.user,
                                                 active=True).count()
    finding_count = Finding.objects.filter(reporter=request.user,
                                           verified=True,
                                           mitigated=None,
                                           date__range=[seven_days_ago,
                                                        now]).count()
    mitigated_count = Finding.objects.filter(reporter=request.user,
                                             mitigated__range=[seven_days_ago,
                                                               now]).count()

    accepted_count = len([finding for ra in Risk_Acceptance.objects.filter(
        reporter=request.user, created__range=[seven_days_ago, now])
                          for finding in ra.accepted_findings.all()])

    # forever counts
    findings = Finding.objects.filter(reporter=request.user,
                                      verified=True)

    sev_counts = {'Critical': 0,
                  'High': 0,
                  'Medium': 0,
                  'Low': 0,
                  'Info': 0}

    for finding in findings:
        sev_counts[finding.severity] += 1

    by_month = list()

    dates_to_use = [now,
                    now - relativedelta(months=1),
                    now - relativedelta(months=2),
                    now - relativedelta(months=3),
                    now - relativedelta(months=4),
                    now - relativedelta(months=5),
                    now - relativedelta(months=6)]

    for date_to_use in dates_to_use:
        sourcedata = {'y': date_to_use.strftime("%Y-%m"), 'a': 0, 'b': 0,
                      'c': 0, 'd': 0, 'e': 0}

        for finding in Finding.objects.filter(
                reporter=request.user,
                verified=True,
                date__range=[datetime(date_to_use.year,
                                      date_to_use.month, 1,
                                      tzinfo=localtz),
                             datetime(date_to_use.year,
                                      date_to_use.month,
                                      monthrange(date_to_use.year,
                                                 date_to_use.month)[1],
                                      tzinfo=localtz)]):
            if finding.severity == 'Critical':
                sourcedata['a'] += 1
            elif finding.severity == 'High':
                sourcedata['b'] += 1
            elif finding.severity == 'Medium':
                sourcedata['c'] += 1
            elif finding.severity == 'Low':
                sourcedata['d'] += 1
            elif finding.severity == 'Info':
                sourcedata['e'] += 1
        by_month.append(sourcedata)

    start_date = now - timedelta(days=180)

    r = relativedelta(now, start_date)
    weeks_between = int(ceil((((r.years * 12) + r.months) * 4.33) + (r.days / 7)))
    if weeks_between <= 0:
        weeks_between += 2

    punchcard, ticks, highest_count = get_punchcard_data(findings, weeks_between, start_date)

    return render(request,
                  'dojo/dashboard.html',
                  {'engagement_count': engagement_count,
                   'finding_count': finding_count,
                   'mitigated_count': mitigated_count,
                   'accepted_count': accepted_count,
                   'critical': sev_counts['Critical'],
                   'high': sev_counts['High'],
                   'medium': sev_counts['Medium'],
                   'low': sev_counts['Low'],
                   'info': sev_counts['Info'],
                   'by_month': by_month,
                   'punchcard': punchcard,
                   'ticks': ticks,
                   'highest_count': highest_count})


@user_passes_test(lambda u: u.is_staff)
def alerts(request):
    alerts = get_alerts(request.user)
    paged_alerts = get_page_items(request, alerts, 25)
    return render(request,
                  'dojo/alerts.html',
                  {'alerts': paged_alerts,
                   'breadcrumbs': get_breadcrumbs(
                       title="Alerts for " + request.user.get_full_name(), user=request.user)})


def get_page_items(request, items, page_size, param_name='page'):
    paginator = Paginator(items, page_size)
    page = request.GET.get(param_name)
    try:
        page = paginator.page(page)
    except PageNotAnInteger:
        # If page is not an integer, deliver first page.
        page = paginator.page(1)
    except EmptyPage:
        # If page is out of range (e.g. 9999), deliver last page of results.
        page = paginator.page(paginator.num_pages)

    return page


def get_alerts(user):
    import humanize

    alerts = []
    now = localtz.localize(datetime.today())
    start = now - timedelta(days=7)
    # scans completed in last 7 days
    completed_scans = Scan.objects.filter(
        date__range=[start, now],
        scan_settings__user=user).order_by('-date')
    running_scans = Scan.objects.filter(date__range=[start, now],
                                        status='Running').order_by('-date')
    for scan in completed_scans:
        alerts.append(['Scan Completed',
                       humanize.naturaltime(localtz.normalize(now) - localtz.normalize(scan.date)),
                       'crosshairs',
                       reverse('view_scan', args=(scan.id,))])
    for scan in running_scans:
        alerts.append(['Scan Running',
                       humanize.naturaltime(localtz.normalize(now) - localtz.normalize(scan.date)),
                       'crosshairs',
                       reverse('view_scan_settings', args=(scan.scan_settings.product.id, scan.scan_settings.id,))])

    upcoming_tests = Test.objects.filter(
        target_start__gt=now,
        engagement__lead=user).order_by('target_start')
    for test in upcoming_tests:
        alerts.append([
            'Upcomming ' + (
                test.test_type.name if test.test_type is not None else 'Test'),
            'Target Start ' + test.target_start.strftime("%b. %d, %Y"),
            'user-secret',
            reverse('view_test', args=(test.id,))])

    outstanding_engagements = Engagement.objects.filter(
        target_end__lt=now,
        status='In Progress',
        lead=user).order_by('-target_end')
    for eng in outstanding_engagements:
        alerts.append([
            'Stale Engagement: ' + (
                eng.name if eng.name is not None else 'Engagement'),
            'Target End ' + eng.target_end.strftime("%b. %d, %Y"),
            'bullseye',
            reverse('view_engagement', args=(eng.id,))])

    twenty_four_hours_ago = now - timedelta(hours=24)
    outstanding_s0_findings = Finding.objects.filter(
        severity='Critical',
        reporter=user,
        mitigated=None,
        verified=True,
        false_p=False,
        date__lt=twenty_four_hours_ago).order_by('-date')
    for finding in outstanding_s0_findings:
        alerts.append([
            'S0 Finding: ' + (
                finding.title if finding.title is not None else 'Finding'),
            'Reported On ' + finding.date.strftime("%b. %d, %Y"),
            'bug',
            reverse('view_finding', args=(finding.id,))])

    seven_days_ago = now - timedelta(days=7)
    outstanding_s1_findings = Finding.objects.filter(
        severity='High',
        reporter=user,
        mitigated=None,
        verified=True,
        false_p=False,
        date__lt=seven_days_ago).order_by('-date')
    for finding in outstanding_s1_findings:
        alerts.append([
            'S1 Finding: ' + (
                finding.title if finding.title is not None else 'Finding'),
            'Reported On ' + finding.date.strftime("%b. %d, %Y"),
            'bug',
            reverse('view_finding', args=(finding.id,))])

    fourteen_days_ago = now - timedelta(days=14)
    outstanding_s2_findings = Finding.objects.filter(
        severity='Medium',
        reporter=user,
        mitigated=None,
        verified=True,
        false_p=False,
        date__lt=fourteen_days_ago).order_by('-date')
    for finding in outstanding_s2_findings:
        alerts.append([
            'S2 Finding: ' + (
                finding.title if finding.title is not None else 'Finding'),
            'Reported On ' + finding.date.strftime("%b. %d, %Y"),
            'bug',
            reverse('view_finding', args=(finding.id,))])
    return alerts


@user_passes_test(lambda u: u.is_staff)
def vulnerable_endpoints(request):
    endpoints = Endpoint.objects.filter(finding__active=True,
                                        finding__verified=True,
                                        finding__mitigated__isnull=True).distinct()
    endpoints = EndpointFilter(request.GET, queryset=endpoints)

    paged_endpoints = get_page_items(request, endpoints, 25)

    return render(request,
                  'dojo/endpoints.html',
                  {"endpoints": paged_endpoints,
                   "filtered": endpoints,
                   "name": "Vulnerable Endpoints",
                   'breadcrumbs': get_breadcrumbs(title="Vulnerable Endpoints", user=request.user)})


def all_endpoints(request):
    endpoints = Endpoint.objects.all()
    # are they authorized
    if request.user.is_staff:
        pass
    else:
        products = Product.objects.filter(authorized_users__in=[request.user])
        if len(products) > 0:
            endpoints = endpoints.filter(product__in=products.all())
        else:
            raise PermissionDenied
    endpoints = EndpointFilter(request.GET, queryset=endpoints, user=request.user)
    paged_endpoints = get_page_items(request, endpoints, 25)

    return render(request,
                  'dojo/endpoints.html',
                  {"endpoints": paged_endpoints,
                   "filtered": endpoints,
                   "name": "All Endpoints",
                   'breadcrumbs': get_breadcrumbs(title="All Endpoints", user=request.user)})


def view_endpoint(request, eid):
    endpoint = get_object_or_404(Endpoint, id=eid)
    product = endpoint.product
    if (request.user in product.authorized_users.all()) or request.user.is_staff:
        pass
    else:
        raise PermissionDenied

    findings = endpoint.finding_set.order_by('-date')
    if findings:
        start_date = localtz.localize(datetime.combine(findings.last().date, datetime.min.time()))
    else:
        start_date = localtz.localize(datetime.today())
    end_date = localtz.localize(datetime.today())

    r = relativedelta(end_date, start_date)
    months_between = (r.years * 12) + r.months
    # include current month
    months_between += 1

    monthly_counts = get_period_counts(findings, findings, months_between, start_date, relative_delta='months')
    paged_findings = get_page_items(request, findings, 25)
    return render(request,
                  "dojo/view_endpoint.html",
                  {"endpoint": endpoint,
                   "findings": paged_findings,
                   'all_findings': findings,
                   'opened_per_month': monthly_counts['opened_per_period'],
                   'breadcrumbs': get_breadcrumbs(obj=endpoint, title="View Endpoint", user=request.user)})


@user_passes_test(lambda u: u.is_staff)
def edit_endpoint(request, eid):
    endpoint = get_object_or_404(Endpoint, id=eid)
    form = EditEndpointForm(instance=endpoint)
    if request.method == 'POST':
        form = EditEndpointForm(request.POST, instance=endpoint)
        if form.is_valid():
            form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Endpoint updated successfully.',
                                 extra_tags='alert-success')

    return render(request,
                  "dojo/edit_endpoint.html",
                  {"endpoint": endpoint,
                   "form": form,
                   'breadcrumbs': get_breadcrumbs(obj=endpoint, title="Edit Endpoint", user=request.user)})


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
                endpoint.delete()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'Endpoint and relationships removed.',
                                     extra_tags='alert-success')
                return HttpResponseRedirect(reverse('view_product', args=(product.id,)))

    return render(request, 'dojo/delete_endpoint.html',
                  {'endpoint': endpoint,
                   'form': form,
                   'rels': rels,
                   'breadcrumbs': get_breadcrumbs(obj=endpoint, title="Delete Endpoint", user=request.user)})


@user_passes_test(lambda u: u.is_staff)
def add_endpoint(request, pid):
    product = get_object_or_404(Product, id=pid)
    error = False
    template = 'dojo/add_endpoint.html'
    if '_popup' in request.GET:
        template = 'dojo/add_related.html'

    form = AddEndpointForm(product=product)

    if request.method == 'POST':
        form = AddEndpointForm(request.POST, product=product)
        if form.is_valid():
            endpoints = form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Endpoint added successfully.',
                                 extra_tags='alert-success')
            if '_popup' in request.GET:
                resp = ''
                for endpoint in endpoints:
                    resp += '<script type="text/javascript">opener.dismissAddAnotherPopup(window, "%s", "%s");</script>' \
                            % (escape(endpoint._get_pk_val()), escape(endpoint))
                return HttpResponse(resp)

    return render(request, template, {
        'name': 'Add Endpoint',
        'breadcrumbs': get_breadcrumbs(obj=product,
                                       title="Add Endpoint",
                                       user=request.user),
        'form': form})


@user_passes_test(lambda u: u.is_staff)
def add_product_endpoint(request):
    form = AddEndpointForm()
    if request.method == 'POST':
        form = AddEndpointForm(request.POST)
        if form.is_valid():
            form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Endpoint added successfully.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('endpoints'))

    return render(request,
                  'dojo/add_endpoint.html',
                  {'name': 'Add Endpoint',
                   'form': form,
                   'breadcrumbs': get_breadcrumbs(title="Add Endpoint", user=request.user)})
