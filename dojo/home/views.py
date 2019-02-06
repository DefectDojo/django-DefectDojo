# #  dojo home pages
import logging
from calendar import monthrange
from datetime import datetime, timedelta
from math import ceil

from dateutil.relativedelta import relativedelta
from django.contrib.auth.decorators import user_passes_test
from django.urls import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.utils import timezone

from dojo.models import Finding, Engagement, Risk_Acceptance
from dojo.utils import add_breadcrumb, get_punchcard_data

logger = logging.getLogger(__name__)


def home(request):
    if request.user.is_authenticated and request.user.is_staff:
        return HttpResponseRedirect(reverse('dashboard'))
    return HttpResponseRedirect(reverse('product'))


@user_passes_test(lambda u: u.is_staff)
def dashboard(request):
    now = timezone.now()
    seven_days_ago = now - timedelta(days=7)
    if request.user.is_superuser:
        engagement_count = Engagement.objects.filter(active=True).count()
        finding_count = Finding.objects.filter(verified=True,
                                               mitigated=None,
                                               duplicate=False,
                                               date__range=[seven_days_ago,
                                                            now]).count()
        mitigated_count = Finding.objects.filter(mitigated__range=[seven_days_ago,
                                                                   now]).count()

        accepted_count = len([finding for ra in Risk_Acceptance.objects.filter(
            reporter=request.user, created__range=[seven_days_ago, now]) for finding in ra.accepted_findings.all()])

        # forever counts
        findings = Finding.objects.filter(verified=True, duplicate=False)
    else:
        engagement_count = Engagement.objects.filter(lead=request.user,
                                                     active=True).count()
        finding_count = Finding.objects.filter(reporter=request.user,
                                               verified=True,
                                               duplicate=False,
                                               mitigated=None,
                                               date__range=[seven_days_ago,
                                                            now]).count()
        mitigated_count = Finding.objects.filter(mitigated_by=request.user,
                                                 mitigated__range=[seven_days_ago,
                                                                   now]).count()

        accepted_count = len([finding for ra in Risk_Acceptance.objects.filter(
            reporter=request.user, created__range=[seven_days_ago, now]) for finding in ra.accepted_findings.all()])

        # forever counts
        findings = Finding.objects.filter(reporter=request.user,
                                          verified=True, duplicate=False)

    sev_counts = {'Critical': 0,
                  'High': 0,
                  'Medium': 0,
                  'Low': 0,
                  'Info': 0}

    for finding in findings:
        if finding.severity:
            sev_counts[finding.severity.capitalize()] += 1

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
                duplicate=False,
                date__range=[datetime(date_to_use.year,
                                      date_to_use.month, 1,
                                      tzinfo=timezone.get_current_timezone()),
                             datetime(date_to_use.year,
                                      date_to_use.month,
                                      monthrange(date_to_use.year,
                                                 date_to_use.month)[1],
                                      tzinfo=timezone.get_current_timezone())]):
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
    add_breadcrumb(request=request, clear=True)
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
