from datetime import timedelta
from dateutil.relativedelta import relativedelta

from django.urls import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.utils import timezone

from dojo.models import Finding, Engagement
from django.db.models import Count, Q
from dojo.utils import add_breadcrumb, get_punchcard_data
from dojo.models import Answered_Survey


def home(request):
    return HttpResponseRedirect(reverse('dashboard'))


def dashboard(request):
    if request.user.is_staff:
        engagements = Engagement.objects.all()
        findings = Finding.objects.all()
    else:
        engagements = Engagement.objects.filter(
            Q(product__authorized_users=request.user) |
            Q(product__prod_type__authorized_users=request.user)
        ).distinct()
        findings = Finding.objects.filter(
            Q(test__engagement__product__authorized_users=request.user) |
            Q(test__engagement__product__prod_type__authorized_users=request.user)
        ).distinct()

    findings = findings.filter(duplicate=False)

    engagement_count = engagements.filter(active=True).count()

    today = timezone.now().date()

    date_range = [today - timedelta(days=6), today]  # 7 days (6 days plus today)
    finding_count = findings\
        .filter(created__date__range=date_range)\
        .count()
    mitigated_count = findings\
        .filter(mitigated__date__range=date_range)\
        .count()
    accepted_count = findings\
        .filter(risk_acceptance__created__date__range=date_range)\
        .count()

    severity_count_all = get_severities_all(findings)
    severity_count_by_month = get_severities_by_month(findings, today)

    start_date = today - relativedelta(weeks=26)
    punchcard, ticks = get_punchcard_data(findings, start_date, 26)

    unassigned_surveys = Answered_Survey.objects.all().filter(
        assignee_id__isnull=True, completed__gt=0)

    add_breadcrumb(request=request, clear=True)
    return render(request,
                  'dojo/dashboard.html',
                  {'engagement_count': engagement_count,
                   'finding_count': finding_count,
                   'mitigated_count': mitigated_count,
                   'accepted_count': accepted_count,
                   'critical': severity_count_all['Critical'],
                   'high': severity_count_all['High'],
                   'medium': severity_count_all['Medium'],
                   'low': severity_count_all['Low'],
                   'info': severity_count_all['Info'],
                   'by_month': severity_count_by_month,
                   'punchcard': punchcard,
                   'ticks': ticks,
                   'surveys': unassigned_surveys})


def get_severities_all(findings):
    # order_by is needed due to ordering being present in Meta of Finding
    severities_all = findings.values('severity').annotate(count=Count('severity')).order_by()

    # make sure all keys are present
    sev_counts_all = {'Critical': 0,
                  'High': 0,
                  'Medium': 0,
                  'Low': 0,
                  'Info': 0}

    for s in severities_all:
        sev_counts_all[s['severity']] = s['count']

    return sev_counts_all


def get_severities_by_month(findings, today):
    by_month = list()

    # order_by is needed due to ordering being present in Meta of Finding
    # severities_all = findings.values('severity').annotate(count=Count('severity')).order_by()
    severities_by_month = findings.filter(created__gte=today + relativedelta(months=-6)) \
                                .values('created__year', 'created__month', 'severity').annotate(count=Count('severity')).order_by('created__year', 'created__month')

    results = {}
    for ms in severities_by_month:
        year = str(ms['created__year'])
        month = str(ms['created__month']).zfill(2)
        key = year + '-' + month

        if key not in results:
            # graph expects a, b, c, d, e instead of Critical, High, ...
            sourcedata = {'y': key, 'a': 0, 'b': 0,
                    'c': 0, 'd': 0, 'e': 0}
            results[key] = sourcedata

        month_stats = results[key]

        if ms['severity'] == 'Critical':
            month_stats['a'] = ms['count']
        elif ms['severity'] == 'High':
            month_stats['b'] = ms['count']
        elif ms['severity'] == 'Medium':
            month_stats['c'] = ms['count']
        elif ms['severity'] == 'Low':
            month_stats['d'] = ms['count']
        elif ms['severity'] == 'Info':
            month_stats['e'] = ms['count']

    by_month = [v for k, v in sorted(results.items())]
    return by_month
