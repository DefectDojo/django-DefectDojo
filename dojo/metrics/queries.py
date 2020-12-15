"""
Database queries used for metrics reporting.
"""

from datetime import datetime
from math import ceil

from dateutil.relativedelta import relativedelta
from django.db.models import Case, IntegerField, Sum, Q, Value, When
from django.db.models.query import QuerySet
from django.urls import reverse
from django.utils import timezone

from dojo.filters import MetricsEndpointFilter, MetricsFindingFilter
from dojo.models import Endpoint_Status, Finding, Product
from dojo.utils import get_period_counts, queryset_check


def finding_querys(prod_type, user, findings_filter, alert_error_func):
    filters = dict()

    findings_query = Finding.objects.filter(
        verified=True,
        severity__in=('Critical', 'High', 'Medium', 'Low', 'Info')
    ).prefetch_related(
        'test__engagement__product',
        'test__engagement__product__prod_type',
        'test__engagement__risk_acceptance',
        'risk_acceptance_set',
        'reporter'
    )
    if not user.is_staff:
        findings_query = findings_query.filter(
            Q(test__engagement__product__authorized_users__in=[user]) |
            Q(test__engagement__product__prod_type__authorized_users__in=[user]))

    active_findings_query = Finding.objects.filter(
        verified=True,
        active=True,
        severity__in=('Critical', 'High', 'Medium', 'Low', 'Info')
    ).prefetch_related(
        'test__engagement__product',
        'test__engagement__product__prod_type',
        'test__engagement__risk_acceptance',
        'risk_acceptance_set',
        'reporter'
    )
    if not user.is_staff:
        active_findings_query = active_findings_query.filter(
            Q(test__engagement__product__authorized_users__in=[user]) |
            Q(test__engagement__product__prod_type__authorized_users__in=[user]))

    findings = MetricsFindingFilter(findings_filter, queryset=findings_query)
    active_findings = MetricsFindingFilter(findings_filter, queryset=active_findings_query)

    findings_qs = queryset_check(findings)
    active_findings_qs = queryset_check(active_findings)

    if not findings_qs and not findings_query:
        findings = findings_query
        active_findings = active_findings_query
        findings_qs = findings if isinstance(findings, QuerySet) else findings.qs
        active_findings_qs = active_findings if isinstance(active_findings, QuerySet) else active_findings.qs
        alert_error_func('All objects have been filtered away. Displaying all objects')

    try:
        start_date = findings_qs.earliest('date').date
        start_date = datetime(start_date.year,
                            start_date.month, start_date.day,
                            tzinfo=timezone.get_current_timezone())
        end_date = findings_qs.latest('date').date
        end_date = datetime(end_date.year,
                            end_date.month, end_date.day,
                            tzinfo=timezone.get_current_timezone())
    except:  # pylint: disable=bare-except
        start_date = timezone.now()
        end_date = timezone.now()

    if len(prod_type) > 0:
        findings_closed = Finding.objects.filter(mitigated__date__range=[start_date, end_date],
                                                 test__engagement__product__prod_type__in=prod_type).prefetch_related(
            'test__engagement__product')
        # capture the accepted findings in period
        accepted_findings = Finding.objects.filter(risk_acceptance__created__date__range=[start_date, end_date],
                                                   test__engagement__product__prod_type__in=prod_type). \
            prefetch_related('test__engagement__product')
        accepted_findings_counts = Finding.objects.filter(risk_acceptance__created__date__range=[start_date, end_date],
                                                          test__engagement__product__prod_type__in=prod_type). \
            prefetch_related('test__engagement__product')
        if not user.is_staff:
            accepted_findings_counts = accepted_findings_counts.filter(
                Q(test__engagement__product__authorized_users__in=[user]) |
                Q(test__engagement__product__prod_type__authorized_users__in=[user]))
        accepted_findings_counts = severity_count(accepted_findings_counts, 'aggregate', 'severity')
    else:
        findings_closed = Finding.objects.filter(mitigated__date__range=[start_date, end_date]).prefetch_related(
            'test__engagement__product')
        accepted_findings = Finding.objects.filter(risk_acceptance__created__date__range=[start_date, end_date]). \
            prefetch_related('test__engagement__product')
        accepted_findings_counts = Finding.objects.filter(risk_acceptance__created__date__range=[start_date, end_date]). \
            prefetch_related('test__engagement__product')
        if not user.is_staff:
            accepted_findings_counts = accepted_findings_counts.filter(
                Q(test__engagement__product__authorized_users__in=[user]) |
                Q(test__engagement__product__prod_type__authorized_users__in=[user]))
        accepted_findings_counts = severity_count(accepted_findings_counts, 'aggregate', 'severity')

    if not user.is_staff:
        findings_closed = findings_closed.filter(
            Q(test__engagement__product__authorized_users__in=[user]) |
            Q(test__engagement__product__prod_type__authorized_users__in=[user]))
        accepted_findings = accepted_findings.filter(
            Q(test__engagement__product__authorized_users__in=[user]) |
            Q(test__engagement__product__prod_type__authorized_users__in=[user]))

    r = relativedelta(end_date, start_date)
    months_between = (r.years * 12) + r.months
    # include current month
    months_between += 1

    weeks_between = int(ceil((((r.years * 12) + r.months) * 4.33) + (r.days / 7)))
    if weeks_between <= 0:
        weeks_between += 2

    monthly_counts = get_period_counts(active_findings_qs, findings_qs, findings_closed, accepted_findings, months_between, start_date,
                                       relative_delta='months')
    weekly_counts = get_period_counts(active_findings_qs, findings_qs, findings_closed, accepted_findings, weeks_between, start_date,
                                      relative_delta='weeks')

    top_ten = Product.objects.filter(engagement__test__finding__verified=True,
                                     engagement__test__finding__false_p=False,
                                     engagement__test__finding__duplicate=False,
                                     engagement__test__finding__out_of_scope=False,
                                     engagement__test__finding__mitigated__isnull=True,
                                     engagement__test__finding__severity__in=(
                                         'Critical', 'High', 'Medium', 'Low'),
                                     prod_type__in=prod_type)
    if not user.is_staff:
        top_ten = top_ten.filter(
            Q(authorized_users__in=[user]) |
            Q(prod_type__authorized_users__in=[user]))
    top_ten = severity_count(
        top_ten, 'annotate', 'engagement__test__finding__severity'
    ).order_by('-critical', '-high', '-medium', '-low')[:10]

    filters['all'] = findings
    filters['closed'] = findings_closed
    filters['accepted'] = accepted_findings
    filters['accepted_count'] = accepted_findings_counts
    filters['top_ten'] = top_ten
    filters['monthly_counts'] = monthly_counts
    filters['weekly_counts'] = weekly_counts
    filters['weeks_between'] = weeks_between
    filters['start_date'] = start_date
    filters['end_date'] = end_date

    return filters


def severity_count(queryset, method, expression):
    total_expression = expression + '__in'
    return getattr(queryset, method)(
        total=Sum(
            Case(When(**{total_expression: ('Critical', 'High', 'Medium', 'Low')},
                        then=Value(1)),
                    output_field=IntegerField())),
        critical=Sum(
            Case(When(**{expression: 'Critical'},
                        then=Value(1)),
                    output_field=IntegerField())),
        high=Sum(
            Case(When(**{expression: 'High'},
                        then=Value(1)),
                    output_field=IntegerField())),
        medium=Sum(
            Case(When(**{expression: 'Medium'},
                        then=Value(1)),
                    output_field=IntegerField())),
        low=Sum(
            Case(When(**{expression: 'Low'},
                        then=Value(1)),
                    output_field=IntegerField())),
        info=Sum(
            Case(When(**{expression: 'Info'},
                        then=Value(1)),
                    output_field=IntegerField())),
    )


def endpoint_querys(prod_type, user, findings_filter, alert_error_func):
    filters = dict()

    endpoints_query = Endpoint_Status.objects.filter(mitigated=False,
                                      finding__severity__in=('Critical', 'High', 'Medium', 'Low', 'Info')).prefetch_related(
        'finding__test__engagement__product',
        'finding__test__engagement__product__prod_type',
        'finding__test__engagement__risk_acceptance',
        'finding__risk_acceptance_set',
        'finding__reporter')
    if not user.is_staff:
        endpoints_query = endpoints_query.filter(
            Q(endpoint__product__authorized_users__in=[user]) |
            Q(endpoint__product__prod_type__authorized_users__in=[user]))

    active_endpoints_query = Endpoint_Status.objects.filter(mitigated=False,
                                      finding__severity__in=('Critical', 'High', 'Medium', 'Low', 'Info')).prefetch_related(
        'finding__test__engagement__product',
        'finding__test__engagement__product__prod_type',
        'finding__test__engagement__risk_acceptance',
        'finding__risk_acceptance_set',
        'finding__reporter')
    if not user.is_staff:
        active_endpoints_query = active_endpoints_query.filter(
            Q(endpoint__product__authorized_users__in=[user]) |
            Q(endpoint__product__prod_type__authorized_users__in=[user]))

    endpoints = MetricsEndpointFilter(findings_filter, queryset=endpoints_query)
    active_endpoints = MetricsEndpointFilter(findings_filter, queryset=active_endpoints_query)

    endpoints_qs = queryset_check(endpoints)
    active_endpoints_qs = queryset_check(active_endpoints)

    if not endpoints_qs:
        endpoints = endpoints_query
        active_endpoints = active_endpoints_query
        endpoints_qs = endpoints if isinstance(endpoints, QuerySet) else endpoints.qs
        active_endpoints_qs = active_endpoints if isinstance(active_endpoints, QuerySet) else active_endpoints.qs
        alert_error_func('All objects have been filtered away. Displaying all objects')

    try:
        start_date = endpoints_qs.earliest('date').date
        start_date = datetime(start_date.year,
                            start_date.month, start_date.day,
                            tzinfo=timezone.get_current_timezone())
        end_date = endpoints_qs.latest('date').date
        end_date = datetime(end_date.year,
                            end_date.month, end_date.day,
                            tzinfo=timezone.get_current_timezone())
    except:  # pylint: disable=bare-except
        start_date = timezone.now()
        end_date = timezone.now()

    if len(prod_type) > 0:
        endpoints_closed = Endpoint_Status.objects.filter(mitigated_time__range=[start_date, end_date],
                                                 finding__test__engagement__product__prod_type__in=prod_type).prefetch_related(
            'finding__test__engagement__product')
        # capture the accepted findings in period
        accepted_endpoints = Endpoint_Status.objects.filter(date__range=[start_date, end_date], risk_accepted=True,
                                                   finding__test__engagement__product__prod_type__in=prod_type). \
            prefetch_related('finding__test__engagement__product')
        accepted_endpoints_counts = Endpoint_Status.objects.filter(date__range=[start_date, end_date], risk_accepted=True,
                                                          finding__test__engagement__product__prod_type__in=prod_type). \
            prefetch_related('finding__test__engagement__product')
        if not user.is_staff:
            accepted_endpoints_counts = accepted_endpoints_counts.filter(
                Q(endpoint__product__authorized_users__in=[user]) |
                Q(endpoint__product__prod_type__authorized_users__in=[user]))
        accepted_endpoints_counts = severity_count(accepted_endpoints_counts, 'aggregate', 'finding__severity')
    else:
        endpoints_closed = Endpoint_Status.objects.filter(date__range=[start_date, end_date]).prefetch_related(
            'finding__test__engagement__product')
        accepted_endpoints = Endpoint_Status.objects.filter(date__range=[start_date, end_date], risk_accepted=True). \
            prefetch_related('finding__test__engagement__product')
        accepted_endpoints_counts = Endpoint_Status.objects.filter(date__range=[start_date, end_date], risk_accepted=True). \
            prefetch_related('finding__test__engagement__product')
        if not user.is_staff:
            accepted_endpoints_counts = accepted_endpoints_counts.filter(
                Q(endpoint__product__authorized_users__in=[user]) |
                Q(endpoint__product__prod_type__authorized_users__in=[user]))
        accepted_endpoints_counts = severity_count(accepted_endpoints_counts, 'aggregate', 'finding__severity')

    if not user.is_staff:
        endpoints_closed = endpoints_closed.filter(
            Q(endpoint__product__authorized_users__in=[user]) |
            Q(endpoint__product__prod_type__authorized_users__in=[user]))
        accepted_endpoints = accepted_endpoints.filter(
            Q(endpoint__product__authorized_users__in=[user]) |
            Q(endpoint__product__prod_type__authorized_users__in=[user]))

    r = relativedelta(end_date, start_date)
    months_between = (r.years * 12) + r.months
    # include current month
    months_between += 1

    weeks_between = int(ceil((((r.years * 12) + r.months) * 4.33) + (r.days / 7)))
    if weeks_between <= 0:
        weeks_between += 2

    monthly_counts = get_period_counts(active_endpoints_qs, endpoints_qs, endpoints_closed, accepted_endpoints, months_between, start_date,
                                       relative_delta='months')
    weekly_counts = get_period_counts(active_endpoints_qs, endpoints_qs, endpoints_closed, accepted_endpoints, weeks_between, start_date,
                                      relative_delta='weeks')

    top_ten = Product.objects.filter(engagement__test__finding__endpoint_status__mitigated=False,
                                     engagement__test__finding__endpoint_status__false_positive=False,
                                     engagement__test__finding__endpoint_status__out_of_scope=False,
                                     engagement__test__finding__severity__in=(
                                         'Critical', 'High', 'Medium', 'Low'),
                                     prod_type__in=prod_type)
    if not user.is_staff:
        top_ten = top_ten.filter(
            Q(authorized_users__in=[user]) |
            Q(prod_type__authorized_users__in=[user]))
    top_ten = severity_count(
        top_ten, 'annotate', 'engagement__test__finding__severity'
    ).order_by('-critical', '-high', '-medium', '-low')[:10]

    filters['all'] = endpoints
    filters['closed'] = endpoints_closed
    filters['accepted'] = accepted_endpoints
    filters['accepted_count'] = accepted_endpoints_counts
    filters['top_ten'] = top_ten
    filters['monthly_counts'] = monthly_counts
    filters['weekly_counts'] = weekly_counts
    filters['weeks_between'] = weeks_between
    filters['start_date'] = start_date
    filters['end_date'] = end_date

    return filters


def get_in_period_details(findings):
    in_period_counts = {"Critical": 0, "High": 0, "Medium": 0,
                        "Low": 0, "Info": 0, "Total": 0}
    in_period_details = {}
    age_detail = [0, 0, 0, 0]

    for obj in findings:
        if 0 <= obj.age <= 30:
            age_detail[0] += 1
        elif 30 < obj.age <= 60:
            age_detail[1] += 1
        elif 60 < obj.age <= 90:
            age_detail[2] += 1
        elif obj.age > 90:
            age_detail[3] += 1

        in_period_counts[obj.severity] += 1
        in_period_counts['Total'] += 1

        if obj.test.engagement.product.name not in in_period_details:
            in_period_details[obj.test.engagement.product.name] = {
                'path': reverse('product_open_findings', args=(obj.test.engagement.product.id,)),
                'Critical': 0,
                'High': 0,
                'Medium': 0,
                'Low': 0,
                'Info': 0,
                'Total': 0
            }
        in_period_details[obj.test.engagement.product.name][obj.severity] += 1
        in_period_details[obj.test.engagement.product.name]['Total'] += 1

    return in_period_counts, in_period_details, age_detail


def get_accepted_in_period_details(findings):
    accepted_in_period_details = {}
    for obj in findings:
        if obj.test.engagement.product.name not in accepted_in_period_details:
            accepted_in_period_details[obj.test.engagement.product.name] = {
                'path': reverse('accepted_findings') + '?test__engagement__product=' + str(obj.test.engagement.product.id),
                'Critical': 0,
                'High': 0,
                'Medium': 0,
                'Low': 0,
                'Info': 0,
                'Total': 0
            }
        accepted_in_period_details[
            obj.test.engagement.product.name
        ][obj.severity] += 1
        accepted_in_period_details[obj.test.engagement.product.name]['Total'] += 1

    return accepted_in_period_details


def get_closed_in_period_details(findings):
    closed_in_period_counts = {"Critical": 0, "High": 0, "Medium": 0,
                               "Low": 0, "Info": 0, "Total": 0}
    closed_in_period_details = {}

    for obj in findings:
        closed_in_period_counts[obj.severity] += 1
        closed_in_period_counts['Total'] += 1

        if obj.test.engagement.product.name not in closed_in_period_details:
            closed_in_period_details[obj.test.engagement.product.name] = {
                'path': reverse('closed_findings') + '?test__engagement__product=' + str(
                    obj.test.engagement.product.id),
                'Critical': 0,
                'High': 0,
                'Medium': 0,
                'Low': 0,
                'Info': 0,
                'Total': 0
            }
        closed_in_period_details[
            obj.test.engagement.product.name
        ][obj.severity] += 1
        closed_in_period_details[obj.test.engagement.product.name]['Total'] += 1

    return closed_in_period_counts, closed_in_period_details


def get_metrics(mtype):
    print(mtype)
