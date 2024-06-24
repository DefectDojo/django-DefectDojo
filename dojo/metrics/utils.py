import collections
import logging
import operator
from calendar import monthrange
from collections import OrderedDict
from datetime import date, datetime, timedelta
from functools import reduce, partial
from math import ceil
from operator import itemgetter
from typing import Union, Optional, Callable, Protocol, TypeAlias, TypeVar

from dateutil.relativedelta import MO, relativedelta
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.db.models import Case, Count, IntegerField, Q, Sum, Value, When, F
from django.db.models.query import QuerySet
from django.db.models.functions import Coalesce, ExtractDay, Now, TruncMonth, TruncWeek
from django.http import HttpResponseRedirect, HttpRequest
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.utils import timezone
from django.utils.html import escape
from django.utils.translation import gettext as _
from django.views.decorators.cache import cache_page
from django.views.decorators.vary import vary_on_cookie

from dojo.authorization.authorization import user_has_permission_or_403
from dojo.authorization.roles_permissions import Permissions
from dojo.endpoint.queries import get_authorized_endpoint_status
from dojo.filters import (
    MetricsEndpointFilter,
    MetricsEndpointFilterWithoutObjectLookups,
    MetricsFindingFilter,
    MetricsFindingFilterWithoutObjectLookups,
    UserFilter,
)
from dojo.finding.helper import ACCEPTED_FINDINGS_QUERY, CLOSED_FINDINGS_QUERY, OPEN_FINDINGS_QUERY
from dojo.finding.queries import get_authorized_findings
from dojo.forms import ProductTagCountsForm, ProductTypeCountsForm, SimpleMetricsForm
from dojo.models import Dojo_User, Endpoint_Status, Engagement, Finding, Product, Product_Type, Risk_Acceptance, Test
from dojo.product.queries import get_authorized_products
from dojo.product_type.queries import get_authorized_product_types
from dojo.utils import (
    add_breadcrumb,
    count_findings,
    findings_this_period,
    get_page_items,
    get_period_counts,
    get_punchcard_data,
    get_system_setting,
    opened_in_period,
    queryset_check,
)


# For type-hinting methods that take querysets we perform metrics over
MetricsQuerySet = TypeVar('MetricsQuerySet', QuerySet[Finding], QuerySet[Endpoint_Status])


# For type-hinting
class _ChartingFunc(Protocol):
    def __call__(self, qs: MetricsQuerySet, closed_lookup: Optional[str] = None) -> MetricsQuerySet: pass


def get_date_range(
    qs: QuerySet
) -> tuple[datetime, datetime]:
    """
    Given a queryset of objects, returns a tuple of (earliest date, latest date) from among those objects, based on the
    objects' 'date' attribute.

    :param qs: The queryset of objects
    :return: A tuple of (earliest date, latest date)
    """
    tz = timezone.get_current_timezone()

    start_date = qs.earliest('date').date
    start_date = datetime(start_date.year, start_date.month, start_date.day, tzinfo=tz)

    end_date = qs.latest('date').date
    end_date = datetime(end_date.year, end_date.month, end_date.day, tzinfo=tz)

    return start_date, end_date


def severity_count(
    queryset: MetricsQuerySet,
    method: str,
    expression: str
) -> QuerySet:
    """
    Aggregates counts by severity for the given queryset.

    :param queryset: The queryset to aggregate
    :param method: The method to use for aggregation, either 'annotate' or 'aggregate' depending on use case.
    :param expression: The lookup expression for severity, relative to the queryset model type
    :return: A queryset containing aggregated counts of severities
    """
    total_expression = expression + '__in'
    return getattr(queryset, method)(
        total=Sum(
            Case(When(**{total_expression: ('Critical', 'High', 'Medium', 'Low', 'Info')},
                      then=Value(1)),
                 output_field=IntegerField(),
                 default=0)),
        critical=Sum(
            Case(When(**{expression: 'Critical'},
                      then=Value(1)),
                 output_field=IntegerField(),
                 default=0)),
        high=Sum(
            Case(When(**{expression: 'High'},
                      then=Value(1)),
                 output_field=IntegerField(),
                 default=0)),
        medium=Sum(
            Case(When(**{expression: 'Medium'},
                      then=Value(1)),
                 output_field=IntegerField(),
                 default=0)),
        low=Sum(
            Case(When(**{expression: 'Low'},
                      then=Value(1)),
                 output_field=IntegerField(),
                 default=0)),
        info=Sum(
            Case(When(**{expression: 'Info'},
                      then=Value(1)),
                 output_field=IntegerField(),
                 default=0)),
    )


def identify_view(
    request: HttpRequest
) -> str:
    """
    Identifies the requested metrics view.

    :param request: The request object
    :return: A string, either 'Endpoint' or 'Finding,' that represents the requested metrics view
    """
    get_data = request.GET
    view = get_data.get('type', None)
    if view:
        return view

    finding_severity = get_data.get('finding__severity', None)
    false_positive = get_data.get('false_positive', None)

    referer = request.META.get('HTTP_REFERER', None)
    endpoint_in_referer = referer and referer.find('type=Endpoint') > -1

    if finding_severity or false_positive or endpoint_in_referer:
        return 'Endpoint'

    return 'Finding'


def js_epoch(
    d: Union[date, datetime]
) -> int:
    """
    Converts a date/datetime object to a JavaScript epoch time (for use in FE charts)

    :param d: The date or datetime object
    :return: The js epoch time (milliseconds since the epoch)
    """
    if isinstance(d, date):
        d = datetime.combine(d, datetime.min.time())
    return int(d.timestamp()) * 1000


def get_charting_data(
    qs: MetricsQuerySet,
    start_date: date,
    period: str,
    period_count: int
) -> list[dict]:
    """
    Given a queryset of severities data for charting, adds epoch timestamp information and fills in missing data points
    queryset aggregation didn't include (because the data didn't exist) with zero-element data, all useful for frontend
    chart rendering. Returns a list of these dictionaries, sorted by date ascending.

    :param qs: The query set
    :param start_date: The start date
    :param period: A string, either 'weeks' or 'months,' representing the period
    :param period_count: The number of periods we should have data for
    :return: A list of dictionaries representing data points for charting, sorted by date
    """
    tz = timezone.get_current_timezone()

    # Calculate the start date for our data. This will depend on whether we're generating for months or weeks.
    if period == 'weeks':
        # For weeks, start at the first day of the specified week
        start_date = datetime(start_date.year, start_date.month, start_date.day, tzinfo=tz)
        start_date = start_date + timedelta(days=-start_date.weekday())
    else:
        # For months, start on the first day of the month
        start_date = datetime(start_date.year, start_date.month, 1, tzinfo=tz)

    # Arrange all our data by epoch date for easy lookup in the loop below.
    # At the same time, add the epoch date to each entry as the charts will rely on that.
    by_date = {e: {'epoch': e, **q} for q in qs if (e := js_epoch(q['grouped_date'])) is not None}

    # Iterate over our period of time, adding zero-element data entries for dates not represented
    for x in range(-1, period_count):
        cur_date = start_date + relativedelta(**{period: x})
        if (e := js_epoch(cur_date)) not in by_date:
            by_date[e] = {
                'grouped_date': cur_date.date(), 'epoch': e,
                'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'closed': 0, }

    # Return, sorting by date
    return sorted(by_date.values(), key=lambda m: m['grouped_date'])


def period_deltas(start_date, end_date):
    """
    Given a start date and end date, returns a tuple of (weeks between the dates, months between the dates).

    :param start_date: The start date to consider
    :param end_date: The end date to consider
    :return: A tuple of integers representing (number of weeks between the dates, number of months between the dates)
    """
    r = relativedelta(end_date, start_date)
    months_between = (r.years * 12) + r.months
    # include current month
    months_between += 1

    weeks_between = int(ceil((((r.years * 12) + r.months) * 4.33) + (r.days / 7)))
    if weeks_between <= 0:
        weeks_between += 2
    return weeks_between, months_between


def finding_querys(prod_type, request):
    # Get the initial list of findings th use is authorized to see
    findings_query = get_authorized_findings(
        Permissions.Finding_View,
        user=request.user,
    ).select_related(
        'reporter',
        'test',
        'test__engagement__product',
        'test__engagement__product__prod_type',
    ).prefetch_related(
        'risk_acceptance_set',
        'test__engagement__risk_acceptance',
        'test__test_type',
    )

    filter_string_matching = get_system_setting("filter_string_matching", False)
    finding_filter_class = MetricsFindingFilterWithoutObjectLookups if filter_string_matching else MetricsFindingFilter
    findings = finding_filter_class(request.GET, queryset=findings_query)
    form = findings.form
    findings_qs = queryset_check(findings)
    # Quick check to determine if the filters were too tight and filtered everything away
    if not findings_qs.exists() and not findings_query.exists():
        findings = findings_query
        findings_qs = findings if isinstance(findings, QuerySet) else findings.qs
        messages.add_message(
            request,
            messages.ERROR,
            _('All objects have been filtered away. Displaying all objects'),
            extra_tags='alert-danger')
    # Attempt to parser the date ranges
    try:
        start_date, end_date = get_date_range(findings_qs)
    except:
        start_date = timezone.now()
        end_date = timezone.now()
    # Filter by the date ranges supplied
    findings_query = findings_query.filter(date__range=[start_date, end_date])
    # Get the list of closed and risk accepted findings
    findings_closed = findings_query.filter(CLOSED_FINDINGS_QUERY)
    accepted_findings = findings_query.filter(ACCEPTED_FINDINGS_QUERY)
    active_findings = findings_query.filter(OPEN_FINDINGS_QUERY)

    # filter by product type if applicable
    if len(prod_type) > 0:
        findings_query = findings_query.filter(test__engagement__product__prod_type__in=prod_type)
        findings_closed = findings_closed.filter(test__engagement__product__prod_type__in=prod_type)
        accepted_findings = accepted_findings.filter(test__engagement__product__prod_type__in=prod_type)
        active_findings = active_findings.filter(test__engagement__product__prod_type__in=prod_type)

    # Get the severity counts of risk accepted findings
    accepted_findings_counts = severity_count(accepted_findings, 'aggregate', 'severity')

    weeks_between, months_between = period_deltas(start_date, end_date)

    monthly_counts = get_monthly_counts(
        findings_query,
        active_findings,
        accepted_findings,
        start_date,
        months_between,
        'severity',
        'is_mitigated'
    )

    weekly_counts = get_weekly_counts(
        findings_query,
        active_findings,
        accepted_findings,
        start_date,
        weeks_between,
        'severity',
        'is_mitigated',
    )

    top_ten = get_authorized_products(Permissions.Product_View)
    top_ten = top_ten.filter(engagement__test__finding__verified=True,
                             engagement__test__finding__false_p=False,
                             engagement__test__finding__duplicate=False,
                             engagement__test__finding__out_of_scope=False,
                             engagement__test__finding__mitigated__isnull=True,
                             engagement__test__finding__severity__in=('Critical', 'High', 'Medium', 'Low'),
                             prod_type__in=prod_type)

    top_ten = severity_count(
        top_ten, 'annotate', 'engagement__test__finding__severity'
    ).order_by(
        '-critical', '-high', '-medium', '-low'
    )[:10]

    return {
        'all': findings_query,
        'closed': findings_closed,
        'accepted': accepted_findings,
        'accepted_count': accepted_findings_counts,
        'top_ten': top_ten,
        'monthly_counts': monthly_counts,
        'weekly_counts': weekly_counts,
        'weeks_between': weeks_between,
        'start_date': start_date,
        'end_date': end_date,
        'form': form,
    }


def endpoint_querys(prod_type, request):
    endpoints_query = Endpoint_Status.objects.filter(
        mitigated=False,
        finding__severity__in=('Critical', 'High', 'Medium', 'Low', 'Info')
    ).prefetch_related(
        'finding__test__engagement__product',
        'finding__test__engagement__product__prod_type',
        'finding__test__engagement__risk_acceptance',
        'finding__risk_acceptance_set',
        'finding__reporter'
    )

    endpoints_query = get_authorized_endpoint_status(Permissions.Endpoint_View, endpoints_query, request.user)
    filter_string_matching = get_system_setting("filter_string_matching", False)
    filter_class = MetricsEndpointFilterWithoutObjectLookups if filter_string_matching else MetricsEndpointFilter
    endpoints = filter_class(request.GET, queryset=endpoints_query)
    form = endpoints.form
    endpoints_qs = queryset_check(endpoints)

    if not endpoints_qs.exists():
        endpoints = endpoints_query
        endpoints_qs = endpoints if isinstance(endpoints, QuerySet) else endpoints.qs
        messages.add_message(
            request,
            messages.ERROR,
            _('All objects have been filtered away. Displaying all objects'),
            extra_tags='alert-danger')

    try:
        start_date, end_date = get_date_range(endpoints_qs)
    except:
        start_date = timezone.now()
        end_date = timezone.now()

    if len(prod_type) > 0:
        endpoints_closed = Endpoint_Status.objects.filter(
            mitigated_time__range=[start_date, end_date],
            finding__test__engagement__product__prod_type__in=prod_type
        ).prefetch_related(
            'finding__test__engagement__product'
        )
        # capture the accepted findings in period
        accepted_endpoints = Endpoint_Status.objects.filter(
            date__range=[start_date, end_date],
            risk_accepted=True,
            finding__test__engagement__product__prod_type__in=prod_type
        ).prefetch_related(
            'finding__test__engagement__product'
        )
    else:
        endpoints_closed = Endpoint_Status.objects.filter(
            mitigated_time__range=[start_date, end_date]
        ).prefetch_related(
            'finding__test__engagement__product'
        )
        # capture the accepted findings in period
        accepted_endpoints = Endpoint_Status.objects.filter(
            date__range=[start_date, end_date],
            risk_accepted=True
        ).prefetch_related(
            'finding__test__engagement__product'
        )

    endpoints_closed = get_authorized_endpoint_status(Permissions.Endpoint_View, endpoints_closed, request.user)
    accepted_endpoints = get_authorized_endpoint_status(Permissions.Endpoint_View, accepted_endpoints, request.user)
    accepted_endpoints_counts = severity_count(accepted_endpoints, 'aggregate', 'finding__severity')

    weeks_between, months_between = period_deltas(start_date, end_date)

    monthly_counts = get_monthly_counts(
        endpoints_qs,
        endpoints_qs.filter(finding__active=True),
        accepted_endpoints,
        start_date,
        months_between,
        'finding__severity',
        'mitigated'
    )

    weekly_counts = get_weekly_counts(
        endpoints_qs,
        endpoints_qs.filter(finding__active=True),
        accepted_endpoints,
        start_date,
        weeks_between,
        'finding__severity',
        'mitigated'
    )

    top_ten = get_authorized_products(Permissions.Product_View)
    top_ten = top_ten.filter(engagement__test__finding__status_finding__mitigated=False,
                             engagement__test__finding__status_finding__false_positive=False,
                             engagement__test__finding__status_finding__out_of_scope=False,
                             engagement__test__finding__status_finding__risk_accepted=False,
                             engagement__test__finding__severity__in=('Critical', 'High', 'Medium', 'Low'),
                             prod_type__in=prod_type)

    top_ten = severity_count(
        top_ten, 'annotate', 'engagement__test__finding__severity'
    ).order_by(
        '-critical', '-high', '-medium', '-low'
    )[:10]

    return {
        'all': endpoints,
        'closed': endpoints_closed,
        'accepted': accepted_endpoints,
        'accepted_count': accepted_endpoints_counts,
        'top_ten': top_ten,
        'monthly_counts': monthly_counts,
        'weekly_counts': weekly_counts,
        'weeks_between': weeks_between,
        'start_date': start_date,
        'end_date': end_date,
        'form': form,
    }


def aggregate_counts_by_period(
    qs: MetricsQuerySet,
    trunc_method: Union[TruncMonth, TruncWeek],
    severity_lookup_expression: str,
    closed_lookup_expression: Optional[str] = None,
) -> QuerySet:
    """
    Annotates the given queryset with severity counts, grouping by desired period as defined by the specified
    trunc_method. Optionally includes a sum of closed findings/statuses as well.

    :param qs: The queryset to annotate with aggregate severity counts, either of Findings or Endpoint_Statuses
    :param trunc_method: Database function TruncMonth or TruncWeek, for aggregating data by desired period
    :param severity_lookup_expression: The query lookup expression for severities relative to the QuerySet model type
    :param closed_lookup_expression: An optional query lookup expression for aggregating 'closed' finding counts,
        matched against the constant True. If None, closed statistics will not be gathered.
    :return: A queryset with aggregate severity counts grouped by period
    """

    desired_values = ('grouped_date', 'total', 'critical', 'high', 'medium', 'low', 'info',)

    severities_by_period = severity_count(
        # Group by desired period
        qs.annotate(grouped_date=trunc_method('date')).values('grouped_date'),
        'annotate',
        severity_lookup_expression
    )
    if closed_lookup_expression:
        severities_by_period = severities_by_period.annotate(
            # Include 'closed' counts
            closed=Sum(Case(When(Q(**{closed_lookup_expression: True}), then=Value(1)), output_field=IntegerField(), default=0)),
        )
        desired_values += ('closed',)

    return severities_by_period.values(*desired_values)


def charting_func(
    start_date: date,
    period: str,
    period_count: int,
    trunc_method: Union[TruncMonth, TruncWeek],
    severity_lookup: str
) -> _ChartingFunc:
    def c(
        qs: MetricsQuerySet,
        cl: Optional[str] = None
    ) -> list[dict]:
        chart = partial(get_charting_data, start_date=start_date, period=period, period_count=period_count)
        agg = partial(aggregate_counts_by_period, trunc_method=trunc_method, severity_lookup_expression=severity_lookup)
        return chart(agg(qs, closed_lookup_expression=cl))
    return c


def _period_counts(
    count_func: _ChartingFunc,
    open_qs: MetricsQuerySet,
    active_qs: MetricsQuerySet,
    accepted_qs: MetricsQuerySet,
    closed_lookup: str
) -> dict[str, list[dict]]:
    return {
        'opened_per_period': count_func(open_qs, closed_lookup),
        'active_per_period': count_func(active_qs),
        'accepted_per_period': count_func(accepted_qs)
    }


def get_monthly_counts(
    open_qs: MetricsQuerySet,
    active_qs: MetricsQuerySet,
    accepted_qs: MetricsQuerySet,
    start_date: date,
    months_between: int,
    severity_lookup: str,
    closed_lookup: str
) -> dict[str, list[dict]]:
    c = charting_func(start_date, 'months', months_between, TruncMonth, severity_lookup)
    return _period_counts(c, open_qs, active_qs, accepted_qs, closed_lookup)


def get_weekly_counts(
    open_qs: MetricsQuerySet,
    active_qs: MetricsQuerySet,
    accepted_qs: MetricsQuerySet,
    start_date: date,
    weeks_between: int,
    severity_lookup: str,
    closed_lookup: str
) -> dict[str, list[dict]]:
    c = charting_func(start_date, 'weeks', weeks_between, TruncWeek, severity_lookup)
    return _period_counts(c, open_qs, active_qs, accepted_qs, closed_lookup)


def findings_by_product(
    findings: QuerySet[Finding]
) -> QuerySet[Finding]:
    return findings.values(product_name=F('test__engagement__product__name'),
                           product_id=F('test__engagement__product__id'))


def get_in_period_details(findings):
    in_period_counts = severity_count(findings, 'aggregate', 'severity')
    in_period_details = severity_count(
        findings_by_product(findings), 'annotate', 'severity'
    ).order_by('product_name')

    age_detail = findings.annotate(age=ExtractDay(Coalesce('mitigated', Now()) - F('date'))).aggregate(
        age_under_30=Sum(Case(When(age__lte=30, then=Value(1))), default=Value(0), output_field=IntegerField()),
        age_31_60=Sum(Case(When(age__range=[31, 60], then=Value(1))), default=Value(0), output_field=IntegerField()),
        age_61_90=Sum(Case(When(age__range=[61, 90], then=Value(1))), default=Value(0), output_field=IntegerField()),
        age_90_plus=Sum(Case(When(age__gt=90, then=Value(1))), default=Value(0), output_field=IntegerField()),
    )
    return in_period_counts, in_period_details, age_detail


def get_accepted_in_period_details(findings):
    return severity_count(
        findings_by_product(findings), 'annotate', 'severity'
    ).order_by('product_name')


def get_closed_in_period_details(findings):
    return (
        severity_count(findings, 'aggregate', 'severity'),
        severity_count(
            findings_by_product(findings), 'annotate', 'severity'
        ).order_by('product_name')
    )


def get_prod_type(request):
    if 'test__engagement__product__prod_type' in request.GET:
        prod_type = Product_Type.objects.filter(id__in=request.GET.getlist('test__engagement__product__prod_type', []))
    else:
        prod_type = get_authorized_product_types(Permissions.Product_Type_View)
    # legacy code calls has 'prod_type' as 'related_name' for product.... so weird looking prefetch
    prod_type = prod_type.prefetch_related('prod_type')
    return prod_type


def findings_queryset(
    qs: MetricsQuerySet
) -> QuerySet[Finding]:
    if qs.model is Endpoint_Status:
        return Finding.objects.filter(status_finding__in=qs)
    else:
        return qs
