import calendar as tcalendar
import os
import re
from calendar import monthrange
from datetime import date, datetime, timedelta
from math import pi, sqrt

import vobject
from dateutil.relativedelta import relativedelta, MO
from django.conf import settings
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.core.urlresolvers import get_resolver, reverse
from django.db.models import Q, Sum, Case, When, IntegerField, Value, Count
from django.template.defaultfilters import pluralize
from pytz import timezone

from dojo.models import Finding, Scan, Test, Engagement, Stub_Finding, Finding_Template, Report

localtz = timezone(settings.TIME_ZONE)

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
        if product in product_count:
            product_count[product][4] += 1
            if f.severity == 'Low':
                product_count[product][3] += 1
                finding_count['low'] += 1
            if f.severity == 'Medium':
                product_count[product][2] += 1
                finding_count['med'] += 1
            if f.severity == 'High':
                product_count[product][1] += 1
                finding_count['high'] += 1
            if f.severity == 'Critical':
                product_count[product][0] += 1
                finding_count['crit'] += 1
        else:
            product_count[product] = [0, 0, 0, 0, 0]
            product_count[product][4] += 1
            if f.severity == 'Low':
                product_count[product][3] += 1
                finding_count['low'] += 1
            if f.severity == 'Medium':
                product_count[product][2] += 1
                finding_count['med'] += 1
            if f.severity == 'High':
                product_count[product][1] += 1
                finding_count['high'] += 1
            if f.severity == 'Critical':
                product_count[product][0] += 1
                finding_count['crit'] += 1
    return product_count, finding_count


def findings_this_period(findings, period_type, stuff, o_stuff, a_stuff):
    # periodType: 0 - weeks
    # 1 - months
    now = localtz.localize(datetime.today())
    for i in range(6):
        counts = []
        # Weeks start on Monday
        if period_type == 0:
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
            if f.mitigated is not None and end_of_period >= f.mitigated >= start_of_period:
                o_count['closed'] += 1
            elif f.mitigated is not None and f.mitigated > end_of_period and f.date <= end_of_period.date():
                if f.severity == 'Critical':
                    o_count['zero'] += 1
                elif f.severity == 'High':
                    o_count['one'] += 1
                elif f.severity == 'Medium':
                    o_count['two'] += 1
                elif f.severity == 'Low':
                    o_count['three'] += 1
            elif f.mitigated is None and f.date <= end_of_period.date():
                if f.severity == 'Critical':
                    o_count['zero'] += 1
                elif f.severity == 'High':
                    o_count['one'] += 1
                elif f.severity == 'Medium':
                    o_count['two'] += 1
                elif f.severity == 'Low':
                    o_count['three'] += 1
            elif f.mitigated is None and f.date <= end_of_period.date():
                if f.severity == 'Critical':
                    a_count['zero'] += 1
                elif f.severity == 'High':
                    a_count['one'] += 1
                elif f.severity == 'Medium':
                    a_count['two'] += 1
                elif f.severity == 'Low':
                    a_count['three'] += 1

        total = sum(o_count.values()) - o_count['closed']
        if period_type == 0:
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
        if period_type == 0:
            a_counts.append(start_of_period.strftime("%b %d") + " - " + end_of_period.strftime("%b %d"))
        else:
            a_counts.append(start_of_period.strftime("%b %Y"))
        a_counts.append(a_count['zero'])
        a_counts.append(a_count['one'])
        a_counts.append(a_count['two'])
        a_counts.append(a_count['three'])
        a_counts.append(a_total)
        a_stuff.append(a_counts)


def add_breadcrumb(parent=None, title=None, top_level=True, url=None, request=None, clear=False):
    title_done = False
    if clear:
        request.session['dojo_breadcrumbs'] = None
        return
    else:
        crumbs = request.session.get('dojo_breadcrumbs', None)

    if top_level or crumbs is None:
        crumbs = [{'title': 'Home',
                   'url': reverse('home')}, ]
        if parent is not None and getattr(parent, "get_breadcrumbs", None):
            crumbs += parent.get_breadcrumbs()
        else:
            title_done = True
            crumbs += [{'title': title,
                        'url': request.get_full_path() if url is None else url}]
    else:
        resolver = get_resolver(None).resolve
        if parent is not None and getattr(parent, "get_breadcrumbs", None):
            obj_crumbs = parent.get_breadcrumbs()
            if title is not None:
                obj_crumbs += [{'title': title,
                                'url': request.get_full_path() if url is None else url}]
        else:
            title_done = True
            obj_crumbs = [{'title': title,
                           'url': request.get_full_path() if url is None else url}]

        for crumb in crumbs:
            crumb_to_resolve = crumb['url'] if '?' not in crumb['url'] else crumb['url'][
                                                                            :crumb['url'].index('?')]
            crumb_view = resolver(crumb_to_resolve)
            for obj_crumb in obj_crumbs:
                obj_crumb_to_resolve = obj_crumb['url'] if '?' not in obj_crumb['url'] else obj_crumb['url'][
                                                                                            :obj_crumb[
                                                                                                'url'].index(
                                                                                                '?')]
                obj_crumb_view = resolver(obj_crumb_to_resolve)

                if crumb_view.view_name == obj_crumb_view.view_name:
                    if crumb_view.kwargs == obj_crumb_view.kwargs:
                        if len(obj_crumbs) == 1 and crumb in crumbs:
                            crumbs = crumbs[:crumbs.index(crumb)]
                        else:
                            obj_crumbs.remove(obj_crumb)
                    else:
                        if crumb in crumbs:
                            crumbs = crumbs[:crumbs.index(crumb)]

        crumbs += obj_crumbs

    request.session['dojo_breadcrumbs'] = crumbs


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
	    try:
		    if new_date < datetime.combine(finding.date, datetime.min.time()).replace(tzinfo=localtz) <= end_date:
			# [0,0,(20*.02)]
			# [week, day, weight]
			days[day_offset[finding.date.weekday()]] += 1
			if days[day_offset[finding.date.weekday()]] > highest_count:
			    highest_count = days[day_offset[finding.date.weekday()]]
	    except:	
		if new_date < finding.date <= end_date:
			# [0,0,(20*.02)]
			# [week, day, weight]
			days[day_offset[finding.date.weekday()]] += 1
			if days[day_offset[finding.date.weekday()]] > highest_count:
			    highest_count = days[day_offset[finding.date.weekday()]]
		pass

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


def get_period_counts(active_findings, findings, findings_closed, accepted_findings, period_interval, start_date,
                      relative_delta='months'):
    opened_in_period = list()
    active_in_period = list()
    accepted_in_period = list()
    opened_in_period.append(['Timestamp', 'Date', 'S0', 'S1', 'S2',
                             'S3', 'Total', 'Closed'])
    active_in_period.append(['Timestamp', 'Date', 'S0', 'S1', 'S2',
                             'S3', 'Total', 'Closed'])
    accepted_in_period.append(['Timestamp', 'Date', 'S0', 'S1', 'S2',
                               'S3', 'Total', 'Closed'])

    for x in range(-1, period_interval):
        if relative_delta == 'months':
            # make interval the first through last of month
            end_date = (start_date + relativedelta(months=x)) + relativedelta(day=1, months=+1, days=-1)
            new_date = (start_date + relativedelta(months=x)) + relativedelta(day=1)
        else:
            # week starts the monday before
            new_date = start_date + relativedelta(weeks=x, weekday=MO(1))
            end_date = new_date + relativedelta(weeks=1, weekday=MO(1))

        closed_in_range_count = findings_closed.filter(mitigated__range=[new_date, end_date]).count()

        if accepted_findings:
            risks_a = accepted_findings.filter(
                risk_acceptance__created__range=[datetime(new_date.year,
                                                          new_date.month, 1,
                                                          tzinfo=localtz),
                                                 datetime(new_date.year,
                                                          new_date.month,
                                                          monthrange(new_date.year,
                                                                     new_date.month)[1],
                                                          tzinfo=localtz)])
        else:
            risks_a = None

        crit_count, high_count, med_count, low_count, closed_count = [0, 0, 0, 0, 0]
        for finding in findings:
            if new_date <= finding.date <= end_date:
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
             total, closed_in_range_count])
        crit_count, high_count, med_count, low_count, closed_count = [0, 0, 0, 0, 0]
        if risks_a is not None:
            for finding in risks_a:
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
        crit_count, high_count, med_count, low_count, closed_count = [0, 0, 0, 0, 0]
        for finding in active_findings:
            if  finding.date <= end_date:
                if finding.severity == 'Critical':
                    crit_count += 1
                elif finding.severity == 'High':
                    high_count += 1
                elif finding.severity == 'Medium':
                    med_count += 1
                elif finding.severity == 'Low':
                    low_count += 1

        total = crit_count + high_count + med_count + low_count
        active_in_period.append(
            [(tcalendar.timegm(new_date.timetuple()) * 1000), new_date, crit_count, high_count, med_count, low_count,
             total])
 
    return {'opened_per_period': opened_in_period,
            'accepted_per_period': accepted_in_period,
            'active_per_period': active_in_period}


def opened_in_period(start_date, end_date, pt):
    opened_in_period = Finding.objects.filter(date__range=[start_date, end_date],
                                              test__engagement__product__prod_type=pt,
                                              verified=True,
                                              false_p=False,
                                              duplicate=False,
                                              out_of_scope=False,
                                              mitigated__isnull=True,
                                              severity__in=('Critical', 'High', 'Medium', 'Low')).values(
        'numerical_severity').annotate(Count('numerical_severity')).order_by('numerical_severity')
    total_opened_in_period = Finding.objects.filter(date__range=[start_date, end_date],
                                                    test__engagement__product__prod_type=pt,
                                                    verified=True,
                                                    false_p=False,
                                                    duplicate=False,
                                                    out_of_scope=False,
                                                    mitigated__isnull=True,
                                                    severity__in=(
                                                        'Critical', 'High', 'Medium', 'Low')).aggregate(
        total=Sum(
            Case(When(severity__in=('Critical', 'High', 'Medium', 'Low'),
                      then=Value(1)),
                 output_field=IntegerField())))['total']

    oip = {'S0': 0,
           'S1': 0,
           'S2': 0,
           'S3': 0,
           'Total': total_opened_in_period,
           'start_date': start_date,
           'end_date': end_date,
           'closed': Finding.objects.filter(mitigated__range=[start_date, end_date],
                                            test__engagement__product__prod_type=pt,
                                            severity__in=(
                                                'Critical', 'High', 'Medium', 'Low')).aggregate(total=Sum(
               Case(When(severity__in=('Critical', 'High', 'Medium', 'Low'), then=Value(1)),
                    output_field=IntegerField())))['total'],
           'to_date_total': Finding.objects.filter(date__lte=end_date.date(),
                                                   verified=True,
                                                   false_p=False,
                                                   duplicate=False,
                                                   out_of_scope=False,
                                                   mitigated__isnull=True,
                                                   test__engagement__product__prod_type=pt,
                                                   severity__in=('Critical', 'High', 'Medium', 'Low')).count()}

    for o in opened_in_period:
        oip[o['numerical_severity']] = o['numerical_severity__count']

    return oip


def message(count, noun, verb):
    return ('{} ' + noun + '{} {} ' + verb).format(count, pluralize(count), pluralize(count, 'was,were'))


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


def get_cal_event(start_date, end_date, summary, description, uid):
    cal = vobject.iCalendar()
    cal.add('vevent')
    cal.vevent.add('summary').value = summary
    cal.vevent.add(
        'description').value = description
    start = cal.vevent.add('dtstart')
    start.value = start_date
    end = cal.vevent.add('dtend')
    end.value = end_date
    cal.vevent.add('uid').value = uid
    return cal


def named_month(month_number):
    """
    Return the name of the month, given the number.
    """
    return date(1900, month_number, 1).strftime("%B")


def normalize_query(query_string,
                    findterms=re.compile(r'"([^"]+)"|(\S+)').findall,
                    normspace=re.compile(r'\s{2,}').sub):
    return [normspace(' ',
                      (t[0] or t[1]).strip()) for t in findterms(query_string)]


def build_query(query_string, search_fields):
    """ Returns a query, that is a combination of Q objects. That combination
    aims to search keywords within a model by testing the given search fields.

    """
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


def template_search_helper(fields=None, query_string=None):
    if not fields:
        fields = ['title', 'description', ]
    findings = Finding_Template.objects.all()

    if not query_string:
        return findings

    entry_query = build_query(query_string, fields)
    found_entries = findings.filter(entry_query)

    return found_entries


def get_page_items(request, items, page_size, param_name='page'):
    size = request.GET.get('page_size', page_size)
    paginator = Paginator(items, size)
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
    # reports requested in the last 7 days
    completed_reports = Report.objects.filter(requester=user, datetime__range=[start, now], status='success')
    running_reports = Report.objects.filter(requester=user, datetime__range=[start, now], status='requested')
    for report in completed_reports:
        alerts.append(['Report Ready: ' + report.name,
                       humanize.naturaltime(localtz.normalize(now) - localtz.normalize(report.datetime)),
                       'file-text-o',
                       reverse('reports')])

    for report in running_reports:
        alerts.append(['Report Running: ' + report.name,
                       humanize.naturaltime(localtz.normalize(now) - localtz.normalize(report.datetime)),
                       'spinner fa-pulse',
                       reverse('reports')])

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
        last_reviewed__lt=twenty_four_hours_ago).order_by('-date')
    for finding in outstanding_s0_findings:
        alerts.append([
            'S0 Finding: ' + (
                finding.title if finding.title is not None else 'Finding'),
            'Reviewed On ' + finding.last_reviewed.strftime("%b. %d, %Y"),
            'bug',
            reverse('view_finding', args=(finding.id,))])

    seven_days_ago = now - timedelta(days=7)
    outstanding_s1_findings = Finding.objects.filter(
        severity='High',
        reporter=user,
        mitigated=None,
        verified=True,
        false_p=False,
        last_reviewed__lt=seven_days_ago).order_by('-date')
    for finding in outstanding_s1_findings:
        alerts.append([
            'S1 Finding: ' + (
                finding.title if finding.title is not None else 'Finding'),
            'Reviewed On ' + finding.last_reviewed.strftime("%b. %d, %Y"),
            'bug',
            reverse('view_finding', args=(finding.id,))])

    fourteen_days_ago = now - timedelta(days=14)
    outstanding_s2_findings = Finding.objects.filter(
        severity='Medium',
        reporter=user,
        mitigated=None,
        verified=True,
        false_p=False,
        last_reviewed__lt=fourteen_days_ago).order_by('-date')
    for finding in outstanding_s2_findings:
        alerts.append([
            'S2 Finding: ' + (
                finding.title if finding.title is not None else 'Finding'),
            'Reviewed On ' + finding.last_reviewed.strftime("%b. %d, %Y"),
            'bug',
            reverse('view_finding', args=(finding.id,))])

    incomplete_findings = Stub_Finding.objects.filter(reporter=user)
    for incomplete_finding in incomplete_findings:
        alerts.append([
            'Incomplete Finding: ' + (
                incomplete_finding.title if incomplete_finding.title is not None else 'Finding'),
            'Started On ' + incomplete_finding.date.strftime("%b. %d, %Y"),
            'bug',
            reverse('promote_to_finding', args=(incomplete_finding.id,))])
    return alerts


def handle_uploaded_threat(f, eng):
    name, extension = os.path.splitext(f.name)
    with open(settings.MEDIA_ROOT + '/threat/%s%s' % (eng.id, extension),
              'wb+') as destination:
        for chunk in f.chunks():
            destination.write(chunk)
    eng.tmodel_path = settings.MEDIA_ROOT + '/threat/%s%s' % (eng.id, extension)
    eng.save()

