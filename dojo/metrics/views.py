# #  metrics
import collections
import logging
import operator
from calendar import monthrange
from collections import OrderedDict
from datetime import date, datetime, timedelta
from math import ceil
from operator import itemgetter

from dateutil.relativedelta import relativedelta
from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.urls import reverse
from django.db.models import Q, Sum, Case, When, IntegerField, Value, Count
from django.http import HttpResponseRedirect
from django.shortcuts import render, get_object_or_404
from django.utils.html import escape
from django.views.decorators.cache import cache_page
from django.utils import timezone

from dojo.filters import MetricsFindingFilter, EngineerFilter
from dojo.forms import SimpleMetricsForm, ProductTypeCountsForm
from dojo.models import Product_Type, Finding, Product, Engagement, Test, \
    Risk_Acceptance, Dojo_User
from dojo.utils import get_page_items, add_breadcrumb, findings_this_period, opened_in_period, count_findings, \
    get_period_counts, get_system_setting, get_punchcard_data
from functools import reduce

logger = logging.getLogger(__name__)

"""
Greg, Jay
status: in production
generic metrics method
"""


def critical_product_metrics(request, mtype):
    template = 'dojo/metrics.html'
    page_name = 'Critical Product Metrics'
    critical_products = Product_Type.objects.filter(critical_product=True)
    add_breadcrumb(title=page_name, top_level=not len(request.GET), request=request)
    return render(request, template, {
        'name': page_name,
        'critical_prods': critical_products,
        'url_prefix': get_system_setting('url_prefix')
    })


@cache_page(60 * 5)  # cache for 5 minutes
def metrics(request, mtype):
    template = 'dojo/metrics.html'
    page_name = 'Product Type Metrics'
    show_pt_filter = True

    findings = Finding.objects.filter(verified=True,
                                      severity__in=('Critical', 'High', 'Medium', 'Low', 'Info')).prefetch_related(
        'test__engagement__product',
        'test__engagement__product__prod_type',
        'test__engagement__risk_acceptance',
        'risk_acceptance_set',
        'reporter').extra(
        select={
            'ra_count': 'SELECT COUNT(*) FROM dojo_risk_acceptance INNER JOIN '
                        'dojo_risk_acceptance_accepted_findings ON '
                        '( dojo_risk_acceptance.id = dojo_risk_acceptance_accepted_findings.risk_acceptance_id ) '
                        'WHERE dojo_risk_acceptance_accepted_findings.finding_id = dojo_finding.id',
        },
    )
    active_findings = Finding.objects.filter(verified=True, active=True,
                                      severity__in=('Critical', 'High', 'Medium', 'Low', 'Info')).prefetch_related(
        'test__engagement__product',
        'test__engagement__product__prod_type',
        'test__engagement__risk_acceptance',
        'risk_acceptance_set',
        'reporter').extra(
        select={
            'ra_count': 'SELECT COUNT(*) FROM dojo_risk_acceptance INNER JOIN '
                        'dojo_risk_acceptance_accepted_findings ON '
                        '( dojo_risk_acceptance.id = dojo_risk_acceptance_accepted_findings.risk_acceptance_id ) '
                        'WHERE dojo_risk_acceptance_accepted_findings.finding_id = dojo_finding.id',
        },
    )

    if mtype != 'All':
        pt = Product_Type.objects.filter(id=mtype)
        request.GET._mutable = True
        request.GET.appendlist('test__engagement__product__prod_type', mtype)
        request.GET._mutable = False
        mtype = pt[0].name
        show_pt_filter = False
        page_name = '%s Metrics' % mtype
        prod_type = pt
    elif 'test__engagement__product__prod_type' in request.GET:
        prod_type = Product_Type.objects.filter(id__in=request.GET.getlist('test__engagement__product__prod_type', []))
    else:
        prod_type = Product_Type.objects.all()
    findings = MetricsFindingFilter(request.GET, queryset=findings)
    active_findings = MetricsFindingFilter(request.GET, queryset=active_findings)

    findings.qs  # this is needed to load details from filter since it is lazy
    active_findings.qs  # this is needed to load details from filter since it is lazy

    start_date = findings.filters['date'].start_date
    start_date = datetime(start_date.year,
                          start_date.month, start_date.day,
                          tzinfo=timezone.get_current_timezone())
    end_date = findings.filters['date'].end_date
    end_date = datetime(end_date.year,
                        end_date.month, end_date.day,
                        tzinfo=timezone.get_current_timezone())

    if len(prod_type) > 0:
        findings_closed = Finding.objects.filter(mitigated__range=[start_date, end_date],
                                                 test__engagement__product__prod_type__in=prod_type).prefetch_related(
            'test__engagement__product')
        # capture the accepted findings in period
        accepted_findings = Finding.objects.filter(risk_acceptance__created__range=[start_date, end_date],
                                                   test__engagement__product__prod_type__in=prod_type). \
            prefetch_related('test__engagement__product')
        accepted_findings_counts = Finding.objects.filter(risk_acceptance__created__range=[start_date, end_date],
                                                          test__engagement__product__prod_type__in=prod_type). \
            prefetch_related('test__engagement__product').aggregate(
            total=Sum(
                Case(When(severity__in=('Critical', 'High', 'Medium', 'Low'),
                          then=Value(1)),
                     output_field=IntegerField())),
            critical=Sum(
                Case(When(severity='Critical',
                          then=Value(1)),
                     output_field=IntegerField())),
            high=Sum(
                Case(When(severity='High',
                          then=Value(1)),
                     output_field=IntegerField())),
            medium=Sum(
                Case(When(severity='Medium',
                          then=Value(1)),
                     output_field=IntegerField())),
            low=Sum(
                Case(When(severity='Low',
                          then=Value(1)),
                     output_field=IntegerField())),
            info=Sum(
                Case(When(severity='Info',
                          then=Value(1)),
                     output_field=IntegerField())),
        )
    else:
        findings_closed = Finding.objects.filter(mitigated__range=[start_date, end_date]).prefetch_related(
            'test__engagement__product')
        accepted_findings = Finding.objects.filter(risk_acceptance__created__range=[start_date, end_date]). \
            prefetch_related('test__engagement__product')
        accepted_findings_counts = Finding.objects.filter(risk_acceptance__created__range=[start_date, end_date]). \
            prefetch_related('test__engagement__product').aggregate(
            total=Sum(
                Case(When(severity__in=('Critical', 'High', 'Medium', 'Low'),
                          then=Value(1)),
                     output_field=IntegerField())),
            critical=Sum(
                Case(When(severity='Critical',
                          then=Value(1)),
                     output_field=IntegerField())),
            high=Sum(
                Case(When(severity='High',
                          then=Value(1)),
                     output_field=IntegerField())),
            medium=Sum(
                Case(When(severity='Medium',
                          then=Value(1)),
                     output_field=IntegerField())),
            low=Sum(
                Case(When(severity='Low',
                          then=Value(1)),
                     output_field=IntegerField())),
            info=Sum(
                Case(When(severity='Info',
                          then=Value(1)),
                     output_field=IntegerField())),
        )

    r = relativedelta(end_date, start_date)
    months_between = (r.years * 12) + r.months
    # include current month
    months_between += 1

    weeks_between = int(ceil((((r.years * 12) + r.months) * 4.33) + (r.days / 7)))
    if weeks_between <= 0:
        weeks_between += 2

    monthly_counts = get_period_counts(active_findings.qs, findings.qs, findings_closed, accepted_findings, months_between, start_date,
                                       relative_delta='months')
    weekly_counts = get_period_counts(active_findings.qs, findings.qs, findings_closed, accepted_findings, weeks_between, start_date,
                                      relative_delta='weeks')

    top_ten = Product.objects.filter(engagement__test__finding__verified=True,
                                     engagement__test__finding__false_p=False,
                                     engagement__test__finding__duplicate=False,
                                     engagement__test__finding__out_of_scope=False,
                                     engagement__test__finding__mitigated__isnull=True,
                                     engagement__test__finding__severity__in=(
                                         'Critical', 'High', 'Medium', 'Low'),
                                     prod_type__in=prod_type).annotate(
        critical=Sum(
            Case(When(engagement__test__finding__severity='Critical', then=Value(1)),
                 output_field=IntegerField())
        ),
        high=Sum(
            Case(When(engagement__test__finding__severity='High', then=Value(1)),
                 output_field=IntegerField())
        ),
        medium=Sum(
            Case(When(engagement__test__finding__severity='Medium', then=Value(1)),
                 output_field=IntegerField())
        ),
        low=Sum(
            Case(When(engagement__test__finding__severity='Low', then=Value(1)),
                 output_field=IntegerField())
        ),
        total=Sum(
            Case(When(engagement__test__finding__severity__in=(
                'Critical', 'High', 'Medium', 'Low'), then=Value(1)),
                output_field=IntegerField()))
    ).order_by('-critical', '-high', '-medium', '-low')[:10]

    age_detail = [0, 0, 0, 0]

    in_period_counts = {"Critical": 0, "High": 0, "Medium": 0,
                        "Low": 0, "Info": 0, "Total": 0}
    in_period_details = {}

    closed_in_period_counts = {"Critical": 0, "High": 0, "Medium": 0,
                               "Low": 0, "Info": 0, "Total": 0}
    closed_in_period_details = {}

    accepted_in_period_details = {}

    for finding in findings.qs:
        if 0 <= finding.age <= 30:
            age_detail[0] += 1
        elif 30 < finding.age <= 60:
            age_detail[1] += 1
        elif 60 < finding.age <= 90:
            age_detail[2] += 1
        elif finding.age > 90:
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

    for finding in accepted_findings:
        if finding.test.engagement.product.name not in accepted_in_period_details:
            accepted_in_period_details[finding.test.engagement.product.name] = {
                'path': reverse('accepted_findings') + '?test__engagement__product=' + str(
                    finding.test.engagement.product.id),
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
                'path': reverse('closed_findings') + '?test__engagement__product=' + str(
                    f.test.engagement.product.id),
                'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0, 'Total': 0}
        closed_in_period_details[
            f.test.engagement.product.name
        ][f.severity] += 1
        closed_in_period_details[f.test.engagement.product.name]['Total'] += 1

    punchcard = list()
    ticks = list()

    if 'view' in request.GET and 'dashboard' == request.GET['view']:
        punchcard, ticks = get_punchcard_data(findings.qs, start_date, weeks_between)
        page_name = (get_system_setting('team_name')) + " Metrics"
        template = 'dojo/dashboard-metrics.html'

    add_breadcrumb(title=page_name, top_level=not len(request.GET), request=request)

    return render(request, template, {
        'name': page_name,
        'start_date': start_date,
        'end_date': end_date,
        'findings': findings,
        'opened_per_month': monthly_counts['opened_per_period'],
        'active_per_month': monthly_counts['active_per_period'],
        'opened_per_week': weekly_counts['opened_per_period'],
        'accepted_per_month': monthly_counts['accepted_per_period'],
        'accepted_per_week': weekly_counts['accepted_per_period'],
        'top_ten_products': top_ten,
        'age_detail': age_detail,
        'in_period_counts': in_period_counts,
        'in_period_details': in_period_details,
        'accepted_in_period_counts': accepted_findings_counts,
        'accepted_in_period_details': accepted_in_period_details,
        'closed_in_period_counts': closed_in_period_counts,
        'closed_in_period_details': closed_in_period_details,
        'punchcard': punchcard,
        'ticks': ticks,
        'show_pt_filter': show_pt_filter,
    })


"""
Jay
status: in production
simple metrics for easy reporting
"""


@cache_page(60 * 5)  # cache for 5 minutes
def simple_metrics(request):
    now = timezone.now()

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
        total_critical = []
        total_high = []
        total_medium = []
        total_low = []
        total_info = []
        total_closed = []
        total_opened = []
        findings_broken_out = {}

        total = Finding.objects.filter(test__engagement__product__prod_type=pt,
                                       verified=True,
                                       false_p=False,
                                       duplicate=False,
                                       out_of_scope=False,
                                       date__month=now.month,
                                       date__year=now.year,
                                       ).distinct()

        for f in total.all():
            if f.severity == "Critical":
                total_critical.append(f)
            elif f.severity == 'High':
                total_high.append(f)
            elif f.severity == 'Medium':
                total_medium.append(f)
            elif f.severity == 'Low':
                total_low.append(f)
            else:
                total_info.append(f)

            if f.mitigated and f.mitigated.year == now.year and f.mitigated.month == now.month:
                total_closed.append(f)

            if f.date.year == now.year and f.date.month == now.month:
                total_opened.append(f)

        findings_broken_out['Total'] = total.count()
        findings_broken_out['S0'] = len(total_critical)
        findings_broken_out['S1'] = len(total_high)
        findings_broken_out['S2'] = len(total_medium)
        findings_broken_out['S3'] = len(total_low)
        findings_broken_out['S4'] = len(total_info)

        findings_broken_out['Opened'] = len(total_opened)
        findings_broken_out['Closed'] = len(total_closed)

        findings_by_product_type[pt] = findings_broken_out

    add_breadcrumb(title="Simple Metrics", top_level=True, request=request)

    return render(request, 'dojo/simple_metrics.html', {
        'findings': findings_by_product_type,
        'name': 'Simple Metrics',
        'metric': True,
        'user': request.user,
        'form': form,
    })


# @cache_page(60 * 5)  # cache for 5 minutes
def product_type_counts(request):
    form = ProductTypeCountsForm()
    opened_in_period_list = []
    oip = None
    cip = None
    aip = None
    all_current_in_pt = None
    top_ten = None
    pt = None
    today = timezone.now()
    first_of_month = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    mid_month = first_of_month.replace(day=15, hour=23, minute=59, second=59, microsecond=999999)
    end_of_month = mid_month.replace(day=monthrange(today.year, today.month)[1], hour=23, minute=59, second=59,
                                     microsecond=999999)
    start_date = first_of_month
    end_date = end_of_month

    if request.method == 'GET' and 'month' in request.GET and 'year' in request.GET and 'product_type' in request.GET:
        form = ProductTypeCountsForm(request.GET)
        if form.is_valid():
            pt = form.cleaned_data['product_type']
            month = int(form.cleaned_data['month'])
            year = int(form.cleaned_data['year'])
            first_of_month = first_of_month.replace(month=month, year=year)

            month_requested = datetime(year, month, 1)

            end_of_month = month_requested.replace(day=monthrange(month_requested.year, month_requested.month)[1],
                                                   hour=23, minute=59, second=59, microsecond=999999)
            start_date = first_of_month
            start_date = datetime(start_date.year,
                                  start_date.month, start_date.day,
                                  tzinfo=timezone.get_current_timezone())
            end_date = end_of_month
            end_date = datetime(end_date.year,
                                end_date.month, end_date.day,
                                tzinfo=timezone.get_current_timezone())

            oip = opened_in_period(start_date, end_date, pt)

            # trending data - 12 months
            for x in range(12, 0, -1):
                opened_in_period_list.append(
                    opened_in_period(start_date + relativedelta(months=-x), end_of_month + relativedelta(months=-x),
                                     pt))

            opened_in_period_list.append(oip)

            closed_in_period = Finding.objects.filter(mitigated__range=[start_date, end_date],
                                                      test__engagement__product__prod_type=pt,
                                                      severity__in=('Critical', 'High', 'Medium', 'Low')).values(
                'numerical_severity').annotate(Count('numerical_severity')).order_by('numerical_severity')

            total_closed_in_period = Finding.objects.filter(mitigated__range=[start_date, end_date],
                                                            test__engagement__product__prod_type=pt,
                                                            severity__in=(
                                                                'Critical', 'High', 'Medium', 'Low')).aggregate(
                total=Sum(
                    Case(When(severity__in=('Critical', 'High', 'Medium', 'Low'),
                              then=Value(1)),
                         output_field=IntegerField())))['total']

            overall_in_pt = Finding.objects.filter(date__lt=end_date,
                                                   verified=True,
                                                   false_p=False,
                                                   duplicate=False,
                                                   out_of_scope=False,
                                                   mitigated__isnull=True,
                                                   test__engagement__product__prod_type=pt,
                                                   severity__in=('Critical', 'High', 'Medium', 'Low')).values(
                'numerical_severity').annotate(Count('numerical_severity')).order_by('numerical_severity')

            total_overall_in_pt = Finding.objects.filter(date__lte=end_date,
                                                         verified=True,
                                                         false_p=False,
                                                         duplicate=False,
                                                         out_of_scope=False,
                                                         mitigated__isnull=True,
                                                         test__engagement__product__prod_type=pt,
                                                         severity__in=('Critical', 'High', 'Medium', 'Low')).aggregate(
                total=Sum(
                    Case(When(severity__in=('Critical', 'High', 'Medium', 'Low'),
                              then=Value(1)),
                         output_field=IntegerField())))['total']

            all_current_in_pt = Finding.objects.filter(date__lte=end_date,
                                                       verified=True,
                                                       false_p=False,
                                                       duplicate=False,
                                                       out_of_scope=False,
                                                       mitigated__isnull=True,
                                                       test__engagement__product__prod_type=pt,
                                                       severity__in=(
                                                           'Critical', 'High', 'Medium', 'Low')).prefetch_related(
                'test__engagement__product',
                'test__engagement__product__prod_type',
                'test__engagement__risk_acceptance',
                'reporter').order_by(
                'numerical_severity')

            top_ten = Product.objects.filter(engagement__test__finding__date__lte=end_date,
                                             engagement__test__finding__verified=True,
                                             engagement__test__finding__false_p=False,
                                             engagement__test__finding__duplicate=False,
                                             engagement__test__finding__out_of_scope=False,
                                             engagement__test__finding__mitigated__isnull=True,
                                             engagement__test__finding__severity__in=(
                                                 'Critical', 'High', 'Medium', 'Low'),
                                             prod_type=pt).annotate(
                critical=Sum(
                    Case(When(engagement__test__finding__severity='Critical', then=Value(1)),
                         output_field=IntegerField())
                ),
                high=Sum(
                    Case(When(engagement__test__finding__severity='High', then=Value(1)),
                         output_field=IntegerField())
                ),
                medium=Sum(
                    Case(When(engagement__test__finding__severity='Medium', then=Value(1)),
                         output_field=IntegerField())
                ),
                low=Sum(
                    Case(When(engagement__test__finding__severity='Low', then=Value(1)),
                         output_field=IntegerField())
                ),
                total=Sum(
                    Case(When(engagement__test__finding__severity__in=(
                        'Critical', 'High', 'Medium', 'Low'), then=Value(1)),
                        output_field=IntegerField()))
            ).order_by('-critical', '-high', '-medium', '-low')[:10]

            cip = {'S0': 0,
                   'S1': 0,
                   'S2': 0,
                   'S3': 0,
                   'Total': total_closed_in_period}

            aip = {'S0': 0,
                   'S1': 0,
                   'S2': 0,
                   'S3': 0,
                   'Total': total_overall_in_pt}

            for o in closed_in_period:
                cip[o['numerical_severity']] = o['numerical_severity__count']

            for o in overall_in_pt:
                aip[o['numerical_severity']] = o['numerical_severity__count']
        else:
            messages.add_message(request, messages.ERROR, "Please choose month and year and the Product Type.",
                                 extra_tags='alert-danger')

    add_breadcrumb(title="Bi-Weekly Metrics", top_level=True, request=request)

    return render(request,
                  'dojo/pt_counts.html',
                  {'form': form,
                   'start_date': start_date,
                   'end_date': end_date,
                   'opened_in_period': oip,
                   'trending_opened': opened_in_period_list,
                   'closed_in_period': cip,
                   'overall_in_pt': aip,
                   'all_current_in_pt': all_current_in_pt,
                   'top_ten': top_ten,
                   'pt': pt}
                  )


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

    users = EngineerFilter(request.GET,
                           queryset=users)
    paged_users = get_page_items(request, users.qs, 15)

    add_breadcrumb(title="Engineer Metrics", top_level=True, request=request)

    return render(request,
                  'dojo/engineer_metrics.html',
                  {'users': paged_users})


"""
Greg
Status: in prod
indvidual view of engineer metrics for a given month. Only superusers,
and root can view others metrics
"""


# noinspection DjangoOrm
@user_passes_test(lambda u: u.is_staff)
@cache_page(60 * 5)  # cache for 5 minutes
def view_engineer(request, eid):
    user = get_object_or_404(Dojo_User, pk=eid)
    if not (request.user.is_superuser or
            request.user.username == 'root' or
            request.user.username == user.username):
        return HttpResponseRedirect(reverse('engineer_metrics'))
    now = timezone.now()

    findings = Finding.objects.filter(reporter=user, verified=True)
    closed_findings = Finding.objects.filter(mitigated_by=user)
    open_findings = findings.exclude(mitigated__isnull=False)
    open_month = findings.filter(date__year=now.year, date__month=now.month)
    accepted_month = [finding for ra in Risk_Acceptance.objects.filter(
        created__range=[datetime(now.year,
                                 now.month, 1,
                                 tzinfo=timezone.get_current_timezone()),
                        datetime(now.year,
                                 now.month,
                                 monthrange(now.year,
                                            now.month)[1],
                                 tzinfo=timezone.get_current_timezone())],
        reporter=user)
                      for finding in ra.accepted_findings.all()]
    closed_month = []
    for f in closed_findings:
        if f.mitigated and f.mitigated.year == now.year and f.mitigated.month == now.month:
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
    for f in closed_findings:
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
        month_start = datetime.strptime(
            month[0].strip(), "%b %Y")
        month_end = datetime(month_start.year,
                             month_start.month,
                             monthrange(
                                 month_start.year,
                                 month_start.month)[1],
                             tzinfo=timezone.get_current_timezone())
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
        week_start = datetime.strptime(
            wk_range[0].strip() + " " + str(now.year), "%b %d %Y")
        week_end = datetime.strptime(
            wk_range[1].strip() + " " + str(now.year), "%b %d %Y")

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
    od = OrderedDict(sorted(list(vulns.items()), key=itemgetter(1)))
    items = list(od.items())
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
    chart_data = [['Date', 'S0', 'S1', 'S2', 'S3', 'Total']]
    for thing in o_stuff:
        chart_data.insert(1, thing)

    a_chart_data = [['Date', 'S0', 'S1', 'S2', 'S3', 'Total']]
    for thing in a_stuff:
        a_chart_data.insert(1, thing)

    # Data for the weekly charts
    week_chart_data = [['Date', 'S0', 'S1', 'S2', 'S3', 'Total']]
    for thing in week_o_stuff:
        week_chart_data.insert(1, thing)

    week_a_chart_data = [['Date', 'S0', 'S1', 'S2', 'S3', 'Total']]
    for thing in week_a_stuff:
        week_a_chart_data.insert(1, thing)

    details = []
    for find in open_findings:
        team = find.test.engagement.product.prod_type.name
        name = find.test.engagement.product.name
        severity = find.severity
        description = find.title
        life = date.today() - find.date
        life = life.days
        status = 'Active'
        if len(find.risk_acceptance_set.all()) > 0:
            status = 'Accepted'
        detail = [team, name, severity, description, life, status, find.reporter]
        details.append(detail)

    details = sorted(details, key=lambda x: x[2])

    add_breadcrumb(title="%s Metrics" % user.get_full_name(), top_level=False, request=request)

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
For tracking issues reported by SEC researchers.
"""


@user_passes_test(lambda u: u.is_staff)
def research_metrics(request):
    now = timezone.now()
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
    closed_findings_dict = {'S0': closed_findings.filter(severity='Critical'),
                            'S1': closed_findings.filter(severity='High'),
                            'S2': closed_findings.filter(severity='Medium'),
                            'S3': closed_findings.filter(severity='Low')}

    time_to_close = {}
    for sev, finds in list(closed_findings_dict.items()):
        total = 0
        for f in finds:
            total += (datetime.date(f.mitigated) - f.date).days
        if finds.count() != 0:
            time_to_close[sev] = total / finds.count()
        else:
            time_to_close[sev] = 'N/A'

    add_breadcrumb(title="Security Research Metrics", top_level=True, request=request)

    return render(request, 'dojo/research_metrics.html', {
        'user': request.user,
        'month_all_by_product': month_all_by_product,
        'month_verified_by_product': month_verified_by_product,
        'remaining_by_product': remaining_by_product,
        'remaining_aggregate': remaining_aggregate,
        'time_to_close': time_to_close,
    })
