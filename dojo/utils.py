import calendar as tcalendar
import re
import binascii
import os
import hashlib
import json
import StringIO
from Crypto.Cipher import AES
from calendar import monthrange
from datetime import date, datetime
from math import pi, sqrt

import vobject
import requests
from dateutil.relativedelta import relativedelta, MO
from django.conf import settings
from django.core.mail import send_mail
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.core.urlresolvers import get_resolver, reverse
from django.db.models import Q, Sum, Case, When, IntegerField, Value, Count
from django.template.defaultfilters import pluralize
from django.template.loader import render_to_string
from django.utils import timezone
from jira import JIRA
from jira.exceptions import JIRAError
from dojo.models import Finding, Engagement, Finding_Template, \
    Product, JIRA_PKey, JIRA_Issue, Dojo_User, User, \
    Alerts, System_Settings, Notifications, UserContactInfo, Endpoint, Benchmark_Type
from asteval import Interpreter
from requests.auth import HTTPBasicAuth
"""
Michael & Fatima:
Helper function for metrics
Counts the number of findings and the count for the products for each level of
severity for a given finding querySet
"""


def sync_false_history(new_finding, *args, **kwargs):
    eng_findings_cwe = Finding.objects.filter(
        test__engagement__product=new_finding.test.engagement.product,
        cwe=new_finding.cwe,
        test__test_type=new_finding.test.test_type,
        false_p=True).exclude(id=new_finding.id).exclude(cwe=None).exclude(
            endpoints=None)
    eng_findings_title = Finding.objects.filter(
        test__engagement__product=new_finding.test.engagement.product,
        title=new_finding.title,
        test__test_type=new_finding.test.test_type,
        false_p=True).exclude(id=new_finding.id).exclude(endpoints=None)
    total_findings = eng_findings_cwe | eng_findings_title
    if total_findings.count() > 0:
        new_finding.false_p = True
        super(Finding, new_finding).save(*args, **kwargs)


def sync_dedupe(new_finding, *args, **kwargs):
    eng_findings_cwe = Finding.objects.filter(
        test__engagement__product=new_finding.test.engagement.product,
        cwe=new_finding.cwe,
        static_finding=new_finding.static_finding,
        dynamic_finding=new_finding.dynamic_finding,
        date__lte=new_finding.date).exclude(id=new_finding.id).exclude(
            cwe=None).exclude(duplicate=True)
    eng_findings_title = Finding.objects.filter(
        test__engagement__product=new_finding.test.engagement.product,
        title=new_finding.title,
        static_finding=new_finding.static_finding,
        dynamic_finding=new_finding.dynamic_finding,
        date__lte=new_finding.date).exclude(id=new_finding.id).exclude(
            duplicate=True)
    total_findings = eng_findings_cwe | eng_findings_title
    # total_findings = total_findings.order_by('date')
    for find in total_findings:
        if find.endpoints.count() != 0 and new_finding.endpoints.count() != 0:
            list1 = new_finding.endpoints.all()
            list2 = find.endpoints.all()
            if all(x in list1 for x in list2):
                new_finding.duplicate = True
                new_finding.duplicate_finding = find
                find.duplicate_list.add(new_finding)
                find.found_by.add(new_finding.test.test_type)
                super(Finding, new_finding).save(*args, **kwargs)
                break
        elif find.line == new_finding.line and find.file_path == new_finding.file_path and new_finding.static_finding and len(
                new_finding.file_path) > 0:
            new_finding.duplicate = True
            new_finding.duplicate_finding = find
            find.duplicate_list.add(new_finding)
            find.found_by.add(new_finding.test.test_type)
            super(Finding, new_finding).save(*args, **kwargs)
        elif find.get_hash_code() == new_finding.get_hash_code():
            new_finding.duplicate = True
            new_finding.duplicate_finding = find
            find.duplicate_list.add(new_finding)
            find.found_by.add(new_finding.test.test_type)
            super(Finding, new_finding).save(*args, **kwargs)

        calculate_grade(find.test.engagement.product)


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
    now = timezone.now()
    for i in range(6):
        counts = []
        # Weeks start on Monday
        if period_type == 0:
            curr = now - relativedelta(weeks=i)
            start_of_period = curr - relativedelta(
                weeks=1, weekday=0, hour=0, minute=0, second=0)
            end_of_period = curr + relativedelta(
                weeks=0, weekday=0, hour=0, minute=0, second=0)
        else:
            curr = now - relativedelta(months=i)
            start_of_period = curr - relativedelta(
                day=1, hour=0, minute=0, second=0)
            end_of_period = curr + relativedelta(
                day=31, hour=23, minute=59, second=59)

        o_count = {
            'closed': 0,
            'zero': 0,
            'one': 0,
            'two': 0,
            'three': 0,
            'total': 0
        }
        a_count = {
            'closed': 0,
            'zero': 0,
            'one': 0,
            'two': 0,
            'three': 0,
            'total': 0
        }
        for f in findings:
            if f.mitigated is not None and end_of_period >= f.mitigated >= start_of_period:
                o_count['closed'] += 1
            elif f.mitigated is not None and f.mitigated > end_of_period and f.date <= end_of_period.date(
            ):
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
            a_counts.append(
                start_of_period.strftime("%b %d") + " - " +
                end_of_period.strftime("%b %d"))
        else:
            a_counts.append(start_of_period.strftime("%b %Y"))
        a_counts.append(a_count['zero'])
        a_counts.append(a_count['one'])
        a_counts.append(a_count['two'])
        a_counts.append(a_count['three'])
        a_counts.append(a_total)
        a_stuff.append(a_counts)


def add_breadcrumb(parent=None,
                   title=None,
                   top_level=True,
                   url=None,
                   request=None,
                   clear=False):
    title_done = False
    if clear:
        request.session['dojo_breadcrumbs'] = None
        return
    else:
        crumbs = request.session.get('dojo_breadcrumbs', None)

    if top_level or crumbs is None:
        crumbs = [
            {
                'title': 'Home',
                'url': reverse('home')
            },
        ]
        if parent is not None and getattr(parent, "get_breadcrumbs", None):
            crumbs += parent.get_breadcrumbs()
        else:
            title_done = True
            crumbs += [{
                'title': title,
                'url': request.get_full_path() if url is None else url
            }]
    else:
        resolver = get_resolver(None).resolve
        if parent is not None and getattr(parent, "get_breadcrumbs", None):
            obj_crumbs = parent.get_breadcrumbs()
            if title is not None:
                obj_crumbs += [{
                    'title':
                    title,
                    'url':
                    request.get_full_path() if url is None else url
                }]
        else:
            title_done = True
            obj_crumbs = [{
                'title':
                title,
                'url':
                request.get_full_path() if url is None else url
            }]

        for crumb in crumbs:
            crumb_to_resolve = crumb['url'] if '?' not in crumb[
                'url'] else crumb['url'][:crumb['url'].index('?')]
            crumb_view = resolver(crumb_to_resolve)
            for obj_crumb in obj_crumbs:
                obj_crumb_to_resolve = obj_crumb[
                    'url'] if '?' not in obj_crumb['url'] else obj_crumb[
                        'url'][:obj_crumb['url'].index('?')]
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
                if new_date < datetime.combine(finding.date, datetime.min.time(
                )).replace(tzinfo=timezone.get_current_timezone()) <= end_date:
                    # [0,0,(20*.02)]
                    # [week, day, weight]
                    days[day_offset[finding.date.weekday()]] += 1
                    if days[day_offset[finding.date.weekday()]] > highest_count:
                        highest_count = days[day_offset[
                            finding.date.weekday()]]
            except:
                if new_date < finding.date <= end_date:
                    # [0,0,(20*.02)]
                    # [week, day, weight]
                    days[day_offset[finding.date.weekday()]] += 1
                    if days[day_offset[finding.date.weekday()]] > highest_count:
                        highest_count = days[day_offset[
                            finding.date.weekday()]]
                pass

        if sum(days.values()) > 0:
            for day, count in days.items():
                punchcard.append([tick, day, count])
                if append_tick:
                    ticks.append([
                        tick,
                        new_date.strftime(
                            "<span class='small'>%m/%d<br/>%Y</span>")
                    ])
                    append_tick = False
            tick += 1
        week_count += 1
    # adjust the size
    ratio = (sqrt(highest_count / pi))
    for punch in punchcard:
        punch[2] = (sqrt(punch[2] / pi)) / ratio

    return punchcard, ticks, highest_count


# 5 params
def get_period_counts_legacy(findings,
                             findings_closed,
                             accepted_findings,
                             period_interval,
                             start_date,
                             relative_delta='months'):
    opened_in_period = list()
    accepted_in_period = list()
    opened_in_period.append(
        ['Timestamp', 'Date', 'S0', 'S1', 'S2', 'S3', 'Total', 'Closed'])
    accepted_in_period.append(
        ['Timestamp', 'Date', 'S0', 'S1', 'S2', 'S3', 'Total', 'Closed'])

    for x in range(-1, period_interval):
        if relative_delta == 'months':
            # make interval the first through last of month
            end_date = (start_date + relativedelta(months=x)) + relativedelta(
                day=1, months=+1, days=-1)
            new_date = (
                start_date + relativedelta(months=x)) + relativedelta(day=1)
        else:
            # week starts the monday before
            new_date = start_date + relativedelta(weeks=x, weekday=MO(1))
            end_date = new_date + relativedelta(weeks=1, weekday=MO(1))

        closed_in_range_count = findings_closed.filter(
            mitigated__range=[new_date, end_date]).count()

        if accepted_findings:
            risks_a = accepted_findings.filter(
                risk_acceptance__created__range=[
                    datetime(
                        new_date.year,
                        new_date.month,
                        1,
                        tzinfo=timezone.get_current_timezone()),
                    datetime(
                        new_date.year,
                        new_date.month,
                        monthrange(new_date.year, new_date.month)[1],
                        tzinfo=timezone.get_current_timezone())
                ])
        else:
            risks_a = None

        crit_count, high_count, med_count, low_count, closed_count = [
            0, 0, 0, 0, 0
        ]
        for finding in findings:
            if new_date <= datetime.combine(finding.date, datetime.min.time(
            )).replace(tzinfo=timezone.get_current_timezone()) <= end_date:
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
            [(tcalendar.timegm(new_date.timetuple()) * 1000), new_date,
             crit_count, high_count, med_count, low_count, total,
             closed_in_range_count])
        crit_count, high_count, med_count, low_count, closed_count = [
            0, 0, 0, 0, 0
        ]
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
            [(tcalendar.timegm(new_date.timetuple()) * 1000), new_date,
             crit_count, high_count, med_count, low_count, total])

    return {
        'opened_per_period': opened_in_period,
        'accepted_per_period': accepted_in_period
    }


def get_period_counts(active_findings,
                      findings,
                      findings_closed,
                      accepted_findings,
                      period_interval,
                      start_date,
                      relative_delta='months'):
    start_date = datetime(
        start_date.year,
        start_date.month,
        start_date.day,
        tzinfo=timezone.get_current_timezone())
    opened_in_period = list()
    active_in_period = list()
    accepted_in_period = list()
    opened_in_period.append(
        ['Timestamp', 'Date', 'S0', 'S1', 'S2', 'S3', 'Total', 'Closed'])
    active_in_period.append(
        ['Timestamp', 'Date', 'S0', 'S1', 'S2', 'S3', 'Total', 'Closed'])
    accepted_in_period.append(
        ['Timestamp', 'Date', 'S0', 'S1', 'S2', 'S3', 'Total', 'Closed'])

    for x in range(-1, period_interval):
        if relative_delta == 'months':
            # make interval the first through last of month
            end_date = (start_date + relativedelta(months=x)) + relativedelta(
                day=1, months=+1, days=-1)
            new_date = (
                start_date + relativedelta(months=x)) + relativedelta(day=1)
        else:
            # week starts the monday before
            new_date = start_date + relativedelta(weeks=x, weekday=MO(1))
            end_date = new_date + relativedelta(weeks=1, weekday=MO(1))

        closed_in_range_count = findings_closed.filter(
            mitigated__range=[new_date, end_date]).count()

        if accepted_findings:
            risks_a = accepted_findings.filter(
                risk_acceptance__created__range=[
                    datetime(
                        new_date.year,
                        new_date.month,
                        1,
                        tzinfo=timezone.get_current_timezone()),
                    datetime(
                        new_date.year,
                        new_date.month,
                        monthrange(new_date.year, new_date.month)[1],
                        tzinfo=timezone.get_current_timezone())
                ])
        else:
            risks_a = None

        crit_count, high_count, med_count, low_count, closed_count = [
            0, 0, 0, 0, 0
        ]
        for finding in findings:
            try:
                if new_date <= datetime.combine(
                        finding.date, datetime.min.time()
                ).replace(tzinfo=timezone.get_current_timezone()) <= end_date:
                    if finding.severity == 'Critical':
                        crit_count += 1
                    elif finding.severity == 'High':
                        high_count += 1
                    elif finding.severity == 'Medium':
                        med_count += 1
                    elif finding.severity == 'Low':
                        low_count += 1
            except:
                if new_date <= finding.date <= end_date:
                    if finding.severity == 'Critical':
                        crit_count += 1
                    elif finding.severity == 'High':
                        high_count += 1
                    elif finding.severity == 'Medium':
                        med_count += 1
                    elif finding.severity == 'Low':
                        low_count += 1
                pass

        total = crit_count + high_count + med_count + low_count
        opened_in_period.append(
            [(tcalendar.timegm(new_date.timetuple()) * 1000), new_date,
             crit_count, high_count, med_count, low_count, total,
             closed_in_range_count])
        crit_count, high_count, med_count, low_count, closed_count = [
            0, 0, 0, 0, 0
        ]
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
            [(tcalendar.timegm(new_date.timetuple()) * 1000), new_date,
             crit_count, high_count, med_count, low_count, total])
        crit_count, high_count, med_count, low_count, closed_count = [
            0, 0, 0, 0, 0
        ]
        for finding in active_findings:
            try:
                if datetime.combine(finding.date, datetime.min.time()).replace(
                        tzinfo=timezone.get_current_timezone()) <= end_date:
                    if finding.severity == 'Critical':
                        crit_count += 1
                    elif finding.severity == 'High':
                        high_count += 1
                    elif finding.severity == 'Medium':
                        med_count += 1
                    elif finding.severity == 'Low':
                        low_count += 1
            except:
                if finding.date <= end_date:
                    if finding.severity == 'Critical':
                        crit_count += 1
                    elif finding.severity == 'High':
                        high_count += 1
                    elif finding.severity == 'Medium':
                        med_count += 1
                    elif finding.severity == 'Low':
                        low_count += 1
                pass
        total = crit_count + high_count + med_count + low_count
        active_in_period.append(
            [(tcalendar.timegm(new_date.timetuple()) * 1000), new_date,
             crit_count, high_count, med_count, low_count, total])

    return {
        'opened_per_period': opened_in_period,
        'accepted_per_period': accepted_in_period,
        'active_per_period': active_in_period
    }


def opened_in_period(start_date, end_date, pt):
    start_date = datetime(
        start_date.year,
        start_date.month,
        start_date.day,
        tzinfo=timezone.get_current_timezone())
    end_date = datetime(
        end_date.year,
        end_date.month,
        end_date.day,
        tzinfo=timezone.get_current_timezone())
    opened_in_period = Finding.objects.filter(
        date__range=[start_date, end_date],
        test__engagement__product__prod_type=pt,
        verified=True,
        false_p=False,
        duplicate=False,
        out_of_scope=False,
        mitigated__isnull=True,
        severity__in=(
            'Critical', 'High', 'Medium',
            'Low')).values('numerical_severity').annotate(
                Count('numerical_severity')).order_by('numerical_severity')
    total_opened_in_period = Finding.objects.filter(
        date__range=[start_date, end_date],
        test__engagement__product__prod_type=pt,
        verified=True,
        false_p=False,
        duplicate=False,
        out_of_scope=False,
        mitigated__isnull=True,
        severity__in=('Critical', 'High', 'Medium', 'Low')).aggregate(
            total=Sum(
                Case(
                    When(
                        severity__in=('Critical', 'High', 'Medium', 'Low'),
                        then=Value(1)),
                    output_field=IntegerField())))['total']

    oip = {
        'S0':
        0,
        'S1':
        0,
        'S2':
        0,
        'S3':
        0,
        'Total':
        total_opened_in_period,
        'start_date':
        start_date,
        'end_date':
        end_date,
        'closed':
        Finding.objects.filter(
            mitigated__range=[start_date, end_date],
            test__engagement__product__prod_type=pt,
            severity__in=('Critical', 'High', 'Medium', 'Low')).aggregate(
                total=Sum(
                    Case(
                        When(
                            severity__in=('Critical', 'High', 'Medium', 'Low'),
                            then=Value(1)),
                        output_field=IntegerField())))['total'],
        'to_date_total':
        Finding.objects.filter(
            date__lte=end_date.date(),
            verified=True,
            false_p=False,
            duplicate=False,
            out_of_scope=False,
            mitigated__isnull=True,
            test__engagement__product__prod_type=pt,
            severity__in=('Critical', 'High', 'Medium', 'Low')).count()
    }

    for o in opened_in_period:
        oip[o['numerical_severity']] = o['numerical_severity__count']

    return oip


def message(count, noun, verb):
    return ('{} ' + noun + '{} {} ' + verb).format(
        count, pluralize(count), pluralize(count, 'was,were'))


class FileIterWrapper(object):
    def __init__(self, flo, chunk_size=1024**2):
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
    cal.vevent.add('description').value = description
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
    return [
        normspace(' ', (t[0] or t[1]).strip()) for t in findterms(query_string)
    ]


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
        fields = [
            'title',
            'description',
        ]
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


def handle_uploaded_threat(f, eng):
    name, extension = os.path.splitext(f.name)
    with open(settings.MEDIA_ROOT + '/threat/%s%s' % (eng.id, extension),
              'wb+') as destination:
        for chunk in f.chunks():
            destination.write(chunk)
    eng.tmodel_path = settings.MEDIA_ROOT + '/threat/%s%s' % (eng.id,
                                                              extension)
    eng.save()


def handle_uploaded_selenium(f, cred):
    name, extension = os.path.splitext(f.name)
    with open(settings.MEDIA_ROOT + '/selenium/%s%s' % (cred.id, extension),
              'wb+') as destination:
        for chunk in f.chunks():
            destination.write(chunk)
    cred.selenium_script = settings.MEDIA_ROOT + '/selenium/%s%s' % (cred.id,
                                                                     extension)
    cred.save()


# Gets a connection to a Jira server based on the finding
def get_jira_connection(finding):
    prod = Product.objects.get(
        engagement=Engagement.objects.get(test=finding.test))
    jpkey = JIRA_PKey.objects.get(product=prod)
    jira_conf = jpkey.conf

    jira = JIRA(
        server=jira_conf.url,
        basic_auth=(jira_conf.username, jira_conf.password))
    return jira


def jira_get_resolution_id(jira, issue, status):
    transitions = jira.transitions(issue)
    resolution_id = None
    for t in transitions:
        if t['name'] == "Resolve Issue":
            resolution_id = t['id']
            break
        if t['name'] == "Reopen Issue":
            resolution_id = t['id']
            break

    return resolution_id


def jira_change_resolution_id(jira, issue, id):
    jira.transition_issue(issue, id)


# Logs the error to the alerts table, which appears in the notification toolbar
def log_jira_generic_alert(title, description):
    create_notification(
        event='jira_update',
        title=title,
        description=description,
        icon='bullseye',
        source='Jira')


# Logs the error to the alerts table, which appears in the notification toolbar
def log_jira_alert(error, finding):
    create_notification(
        event='jira_update',
        title='Jira update issue',
        description='Finding: ' + str(finding.id) + ', ' + error,
        icon='bullseye',
        source='Jira')


# Displays an alert for Jira notifications
def log_jira_message(text, finding):
    create_notification(
        event='jira_update',
        title='Jira update message',
        description=text + " Finding: " + str(finding.id),
        url=reverse('view_finding', args=(finding.id, )),
        icon='bullseye',
        source='Jira')


# Adds labels to a Jira issue
def add_labels(find, issue):
    # Update Label with Security
    system_settings = System_Settings.objects.get()
    labels = system_settings.jira_labels.split()
    if labels is not None:
        for label in labels:
            issue.fields.labels.append(label)
    # Update the label with the product name (underscore)
    prod_name = find.test.engagement.product.name.replace(" ", "_")
    issue.fields.labels.append(prod_name)
    issue.update(fields={"labels": issue.fields.labels})


def jira_long_description(find_description, find_id, jira_conf_finding_text):
    return find_description + "\n\n*Dojo ID:* " + str(
        find_id) + "\n\n" + jira_conf_finding_text


def add_issue(find, push_to_jira):
    eng = Engagement.objects.get(test=find.test)
    prod = Product.objects.get(engagement=eng)
    jpkey = JIRA_PKey.objects.get(product=prod)
    jira_conf = jpkey.conf

    if push_to_jira:
        if 'Active' in find.status() and 'Verified' in find.status():
            if ((jpkey.push_all_issues and Finding.get_number_severity(
                    System_Settings.objects.get().jira_minimum_severity) >
                 Finding.get_number_severity(find.severity))):
                pass
            else:
                try:
                    JIRAError.log_to_tempfile = False
                    jira = JIRA(
                        server=jira_conf.url,
                        basic_auth=(jira_conf.username, jira_conf.password))
                    if jpkey.component:
                        new_issue = jira.create_issue(
                            project=jpkey.project_key,
                            summary=find.title,
                            components=[
                                {
                                    'name': jpkey.component
                                },
                            ],
                            description=jira_long_description(
                                find.long_desc(), find.id,
                                jira_conf.finding_text),
                            issuetype={'name': jira_conf.default_issue_type},
                            priority={
                                'name': jira_conf.get_priority(find.severity)
                            })
                    else:
                        new_issue = jira.create_issue(
                            project=jpkey.project_key,
                            summary=find.title,
                            description=jira_long_description(
                                find.long_desc(), find.id,
                                jira_conf.finding_text),
                            issuetype={'name': jira_conf.default_issue_type},
                            priority={
                                'name': jira_conf.get_priority(find.severity)
                            })
                    j_issue = JIRA_Issue(
                        jira_id=new_issue.id, jira_key=new_issue, finding=find)
                    j_issue.save()
                    issue = jira.issue(new_issue.id)

                    # Add labels (security & product)
                    add_labels(find, new_issue)
                    # Upload dojo finding screenshots to Jira
                    for pic in find.images.all():
                        jira_attachment(
                            jira, issue,
                            settings.MEDIA_ROOT + pic.image_large.name)

                        # if jpkey.enable_engagement_epic_mapping:
                        #      epic = JIRA_Issue.objects.get(engagement=eng)
                        #      issue_list = [j_issue.jira_id,]
                        #      jira.add_issues_to_epic(epic_id=epic.jira_id, issue_keys=[str(j_issue.jira_id)], ignore_epics=True)
                except JIRAError as e:
                    log_jira_alert(e.text, find)
        else:
            log_jira_alert("Finding not active, verified, or over threshold.",
                           find)


def jira_attachment(jira, issue, file, jira_filename=None):

    basename = file
    if jira_filename is None:
        basename = os.path.basename(file)

    # Check to see if the file has been uploaded to Jira
    if jira_check_attachment(issue, basename) is False:
        try:
            if jira_filename is not None:
                attachment = StringIO.StringIO()
                attachment.write(jira_filename)
                jira.add_attachment(
                    issue=issue, attachment=attachment, filename=jira_filename)
            else:
                # read and upload a file
                with open(file, 'rb') as f:
                    jira.add_attachment(issue=issue, attachment=f)
        except JIRAError as e:
            log_jira_alert("Attachment: " + e.text)


def jira_check_attachment(issue, source_file_name):
    file_exists = False
    for attachment in issue.fields.attachment:
        filename = attachment.filename

        if filename == source_file_name:
            file_exists = True
            break

    return file_exists


def update_issue(find, old_status, push_to_jira):
    prod = Product.objects.get(
        engagement=Engagement.objects.get(test=find.test))
    jpkey = JIRA_PKey.objects.get(product=prod)
    jira_conf = jpkey.conf

    if push_to_jira:
        j_issue = JIRA_Issue.objects.get(finding=find)
        try:
            JIRAError.log_to_tempfile = False
            jira = JIRA(
                server=jira_conf.url,
                basic_auth=(jira_conf.username, jira_conf.password))
            issue = jira.issue(j_issue.jira_id)

            fields = {}
            # Only update the component if it didn't exist earlier in Jira, this is to avoid assigning multiple components to an item
            if issue.fields.components:
                log_jira_alert(
                    "Component not updated, exists in Jira already. Update from Jira instead.",
                    find)
            else:
                # Add component to the Jira issue
                component = [
                    {
                        'name': jpkey.component
                    },
                ]
                fields = {"components": component}

            # Upload dojo finding screenshots to Jira
            for pic in find.images.all():
                jira_attachment(jira, issue,
                                settings.MEDIA_ROOT + pic.image_large.name)

            issue.update(
                summary=find.title,
                description=jira_long_description(find.long_desc(), find.id,
                                                  jira_conf.finding_text),
                priority={'name': jira_conf.get_priority(find.severity)},
                fields=fields)

            # Add labels(security & product)
            add_labels(find, issue)
        except JIRAError as e:
            log_jira_alert(e.text, find)

        req_url = jira_conf.url + '/rest/api/latest/issue/' + j_issue.jira_id + '/transitions'
        if 'Inactive' in find.status() or 'Mitigated' in find.status(
        ) or 'False Positive' in find.status(
        ) or 'Out of Scope' in find.status() or 'Duplicate' in find.status():
            if 'Active' in old_status:
                json_data = {'transition': {'id': jira_conf.close_status_key}}
                r = requests.post(
                    url=req_url,
                    auth=HTTPBasicAuth(jira_conf.username, jira_conf.password),
                    json=json_data)
        elif 'Active' in find.status() and 'Verified' in find.status():
            if 'Inactive' in old_status:
                json_data = {'transition': {'id': jira_conf.open_status_key}}
                r = requests.post(
                    url=req_url,
                    auth=HTTPBasicAuth(jira_conf.username, jira_conf.password),
                    json=json_data)


def close_epic(eng, push_to_jira):
    engagement = eng
    prod = Product.objects.get(engagement=engagement)
    jpkey = JIRA_PKey.objects.get(product=prod)
    jira_conf = jpkey.conf
    if jpkey.enable_engagement_epic_mapping and push_to_jira:
        try:
            j_issue = JIRA_Issue.objects.get(engagement=eng)
            req_url = jira_conf.url + '/rest/api/latest/issue/' + j_issue.jira_id + '/transitions'
            j_issue = JIRA_Issue.objects.get(engagement=eng)
            json_data = {'transition': {'id': jira_conf.close_status_key}}
            r = requests.post(
                url=req_url,
                auth=HTTPBasicAuth(jira_conf.username, jira_conf.password),
                json=json_data)
        except Exception as e:
            log_jira_generic_alert('Jira Engagement/Epic Close Error', str(e))
            pass


def update_epic(eng, push_to_jira):
    engagement = eng
    prod = Product.objects.get(engagement=engagement)
    jpkey = JIRA_PKey.objects.get(product=prod)
    jira_conf = jpkey.conf
    if jpkey.enable_engagement_epic_mapping and push_to_jira:
        try:
            jira = JIRA(
                server=jira_conf.url,
                basic_auth=(jira_conf.username, jira_conf.password))
            j_issue = JIRA_Issue.objects.get(engagement=eng)
            issue = jira.issue(j_issue.jira_id)
            issue.update(summary=eng.name, description=eng.name)
        except Exception as e:
            log_jira_generic_alert('Jira Engagement/Epic Update Error', str(e))
            pass


def add_epic(eng, push_to_jira):
    engagement = eng
    prod = Product.objects.get(engagement=engagement)
    jpkey = JIRA_PKey.objects.get(product=prod)
    jira_conf = jpkey.conf
    if jpkey.enable_engagement_epic_mapping and push_to_jira:
        issue_dict = {
            'project': {
                'key': jpkey.project_key
            },
            'summary': engagement.name,
            'description': engagement.name,
            'issuetype': {
                'name': 'Epic'
            },
            'customfield_' + str(jira_conf.epic_name_id): engagement.name,
        }
        try:
            jira = JIRA(
                server=jira_conf.url,
                basic_auth=(jira_conf.username, jira_conf.password))
            new_issue = jira.create_issue(fields=issue_dict)
            j_issue = JIRA_Issue(
                jira_id=new_issue.id,
                jira_key=new_issue,
                engagement=engagement)
            j_issue.save()
        except Exception as e:
            error = str(e)
            message = ""
            if "customfield" in error:
                message = "The 'Epic name id' in your DefectDojo Jira Configuration does not appear to be correct. Please visit, " + jira_conf.url + "/rest/api/2/field and search for Epic Name. Copy the number out of cf[number] and place in your DefectDojo settings for Jira and try again. For example, if your results are cf[100001] then copy 100001 and place it in 'Epic name id'. (Your Epic Id will be different.) \n\n"

            log_jira_generic_alert('Jira Engagement/Epic Creation Error',
                                   message + error)
            pass


def add_comment(find, note, force_push=False):
    prod = Product.objects.get(
        engagement=Engagement.objects.get(test=find.test))
    jpkey = JIRA_PKey.objects.get(product=prod)
    jira_conf = jpkey.conf
    if jpkey.push_notes or force_push is True:
        try:
            jira = JIRA(
                server=jira_conf.url,
                basic_auth=(jira_conf.username, jira_conf.password))
            j_issue = JIRA_Issue.objects.get(finding=find)
            jira.add_comment(
                j_issue.jira_id,
                '(%s): %s' % (note.author.get_full_name(), note.entry))
        except Exception as e:
            log_jira_generic_alert('Jira Add Comment Error', str(e))
            pass


def send_review_email(request, user, finding, users, new_note):
    recipients = [u.email for u in users]
    msg = "\nGreetings, \n\n"
    msg += "{0} has requested that you please review ".format(str(user))
    msg += "the following finding for accuracy:"
    msg += "\n\n" + finding.title
    msg += "\n\nIt can be reviewed at " + request.build_absolute_uri(
        reverse("view_finding", args=(finding.id, )))
    msg += "\n\n{0} provided the following details:".format(str(user))
    msg += "\n\n" + new_note.entry
    msg += "\n\nThanks\n"

    send_mail(
        'DefectDojo Finding Review Request',
        msg,
        user.email,
        recipients,
        fail_silently=False)
    pass


def process_notifications(request, note, parent_url, parent_title):
    regex = re.compile(r'(?:\A|\s)@(\w+)\b')
    usernames_to_check = set([un.lower() for un in regex.findall(note.entry)])
    users_to_notify = [
        User.objects.filter(username=username).get()
        for username in usernames_to_check
        if User.objects.filter(is_active=True, username=username).exists()
    ]  # is_staff also?
    user_posting = request.user

    create_notification(
        event='user_mentioned',
        section=parent_title,
        note=note,
        user=request.user,
        title='%s mentioned you in a note' % request.user,
        url=parent_url,
        icon='commenting',
        recipients=users_to_notify)


def send_atmention_email(user, users, parent_url, parent_title, new_note):
    recipients = [u.email for u in users]
    msg = "\nGreetings, \n\n"
    msg += "User {0} mentioned you in a note on {1}".format(
        str(user), parent_title)
    msg += "\n\n" + new_note.entry
    msg += "\n\nIt can be reviewed at " + parent_url
    msg += "\n\nThanks\n"
    send_mail(
        'DefectDojo - {0} @mentioned you in a note'.format(str(user)),
        msg,
        user.email,
        recipients,
        fail_silently=False)


def encrypt(key, iv, plaintext):
    text = ""
    if plaintext is not "" and plaintext is not None:
        aes = AES.new(key, AES.MODE_CBC, iv, segment_size=128)
        plaintext = _pad_string(plaintext)
        encrypted_text = aes.encrypt(plaintext)
        text = binascii.b2a_hex(encrypted_text).rstrip()
    return text


def decrypt(key, iv, encrypted_text):
    aes = AES.new(key, AES.MODE_CBC, iv, segment_size=128)
    encrypted_text_bytes = binascii.a2b_hex(encrypted_text)
    decrypted_text = aes.decrypt(encrypted_text_bytes)
    decrypted_text = _unpad_string(decrypted_text)
    return decrypted_text


def _pad_string(value):
    length = len(value)
    pad_size = 16 - (length % 16)
    return value.ljust(length + pad_size, '\x00')


def _unpad_string(value):
    if value is not "" and value is not None:
        while value[-1] == '\x00':
            value = value[:-1]
    return value


def dojo_crypto_encrypt(plaintext):
    data = None
    if plaintext:
        key = None
        key = get_db_key()

        iv = os.urandom(16)
        data = prepare_for_save(
            iv, encrypt(key, iv, plaintext.encode('ascii', 'ignore')))

    return data


def prepare_for_save(iv, encrypted_value):
    stored_value = None

    if encrypted_value is not "" and encrypted_value is not None:
        binascii.b2a_hex(encrypted_value).rstrip()
        stored_value = "AES.1:" + binascii.b2a_hex(iv) + ":" + encrypted_value
    return stored_value


def get_db_key():
    db_key = None
    if hasattr(settings, 'DB_KEY'):
        db_key = settings.DB_KEY
        db_key = binascii.b2a_hex(
            hashlib.sha256(db_key).digest().rstrip())[:32]

    return db_key


def prepare_for_view(encrypted_value):

    key = None
    decrypted_value = ""
    if encrypted_value is not NotImplementedError:
        key = get_db_key()
        encrypted_values = encrypted_value.split(":")

        if len(encrypted_values) > 1:
            type = encrypted_values[0]

            iv = binascii.a2b_hex(encrypted_values[1])
            value = encrypted_values[2]

            try:
                decrypted_value = decrypt(key, iv, value)
                decrypted_value.decode('ascii')
            except UnicodeDecodeError:
                decrypted_value = ""

    return decrypted_value


def get_system_setting(setting):
    try:
        system_settings = System_Settings.objects.get()
    except:
        system_settings = System_Settings()

    return getattr(system_settings, setting, None)


def get_slack_user_id(user_email):
    user_id = None

    res = requests.request(
        method='POST',
        url='https://slack.com/api/users.list',
        data={'token': get_system_setting('slack_token')})

    users = json.loads(res.text)

    if users:
        for member in users["members"]:
            if "email" in member["profile"]:
                if user_email == member["profile"]["email"]:
                    if "id" in member:
                        user_id = member["id"]
                        break

    return user_id


def create_notification(event=None, **kwargs):
    def create_notification_message(event, notification_type):
        template = 'notifications/%s.tpl' % event.replace('/', '')
        kwargs.update({'type': notification_type})

        try:
            notification = render_to_string(template, kwargs)
        except:
            notification = render_to_string('notifications/other.tpl', kwargs)

        return notification

    def send_slack_notification(channel):
        try:
            res = requests.request(
                method='POST',
                url='https://slack.com/api/chat.postMessage',
                data={
                    'token': get_system_setting('slack_token'),
                    'channel': channel,
                    'username': get_system_setting('slack_username'),
                    'text': create_notification_message(event, 'slack')
                })
        except Exception as e:
            log_alert(e)
            pass

    def send_hipchat_notification(channel):
        try:
            # We use same template for HipChat as for slack
            res = requests.request(
                method='POST',
                url='https://%s/v2/room/%s/notification?auth_token=%s' %
                (get_system_setting('hipchat_site'), channel,
                 get_system_setting('hipchat_token')),
                data={
                    'message': create_notification_message(event, 'slack'),
                    'message_format': 'text'
                })
        except Exception as e:
            log_alert(e)
            pass

    def send_mail_notification(address):
        subject = '%s notification' % get_system_setting('team_name')
        if 'title' in kwargs:
            subject += ': %s' % kwargs['title']
        try:
            send_mail(
                subject,
                create_notification_message(event, 'mail'),
                get_system_setting('mail_notifications_from'), [address],
                fail_silently=False)
        except Exception as e:
            log_alert(e)
            pass

    def send_alert_notification(user=None):
        icon = kwargs.get('icon', 'info-circle')
        alert = Alerts(
            user_id=user,
            title=kwargs.get('title'),
            description=create_notification_message(event, 'alert'),
            url=kwargs.get('url', reverse('alerts')),
            icon=icon,
            source=Notifications._meta.get_field(event).verbose_name.title())
        alert.save()

    def log_alert(e):
        users = Dojo_User.objects.filter(is_superuser=True)
        for user in users:
            alert = Alerts(
                user_id=user,
                url=kwargs.get('url', reverse('alerts')),
                title='Notification issue',
                description="%s" % e,
                icon="exclamation-triangle",
                source="Notifications")
            alert.save()

    # Global notifications
    try:
        notifications = Notifications.objects.get(user=None)
    except Exception as e:
        notifications = Notifications()

    slack_enabled = get_system_setting('enable_slack_notifications')
    hipchat_enabled = get_system_setting('enable_hipchat_notifications')
    mail_enabled = get_system_setting('enable_mail_notifications')

    if slack_enabled and 'slack' in getattr(notifications, event):
        send_slack_notification(get_system_setting('slack_channel'))

    if hipchat_enabled and 'hipchat' in getattr(notifications, event):
        send_hipchat_notification(get_system_setting('hipchat_channel'))

    if mail_enabled and 'mail' in getattr(notifications, event):
        send_slack_notification(get_system_setting('mail_notifications_from'))

    if 'alert' in getattr(notifications, event, None):
        send_alert_notification()

    # Personal notifications
    if 'recipients' in kwargs:
        users = User.objects.filter(username__in=kwargs['recipients'])
    else:
        users = User.objects.filter(is_superuser=True)
    for user in users:
        try:
            notifications = Notifications.objects.get(user=user)
        except Exception as e:
            notifications = Notifications()

        if slack_enabled and 'slack' in getattr(
                notifications,
                event) and user.usercontactinfo.slack_username is not None:
            slack_user_id = user.usercontactinfo.slack_user_id
            if user.usercontactinfo.slack_user_id is None:
                # Lookup the slack userid
                slack_user_id = get_slack_user_id(
                    user.usercontactinfo.slack_username)
                slack_user_save = UserContactInfo.objects.get(user_id=user.id)
                slack_user_save.slack_user_id = slack_user_id
                slack_user_save.save()

            send_slack_notification('@%s' % slack_user_id)

        # HipChat doesn't seem to offer direct message functionality, so no HipChat PM functionality here...

        if mail_enabled and 'mail' in getattr(notifications, event):
            send_mail_notification(user.email)

        if 'alert' in getattr(notifications, event):
            send_alert_notification(user)


def calculate_grade(product):
    system_settings = System_Settings.objects.get()
    if system_settings.enable_product_grade:
        severity_values = Finding.objects.filter(
            ~Q(severity='Info'),
            active=True,
            duplicate=False,
            verified=True,
            false_p=False,
            test__engagement__product=product).values('severity').annotate(
                Count('numerical_severity')).order_by()

        low = 0
        medium = 0
        high = 0
        critical = 0
        for severity_count in severity_values:
            if severity_count['severity'] == "Critical":
                critical = severity_count['numerical_severity__count']
            elif severity_count['severity'] == "High":
                high = severity_count['numerical_severity__count']
            elif severity_count['severity'] == "Medium":
                medium = severity_count['numerical_severity__count']
            elif severity_count['severity'] == "Low":
                low = severity_count['numerical_severity__count']

        if severity_values:
            aeval = Interpreter()
            aeval(system_settings.product_grade)
            grade_product = "grade_product(%s, %s, %s, %s)" % (critical, high,
                                                               medium, low)
            # prod = Product.objects.get(id=finding.test.engagement.product.id)
            product.prod_numeric_grade = aeval(grade_product)
            product.save()


def get_celery_worker_status():
    ERROR_KEY = "ERROR"
    try:
        from celery.task.control import inspect
        insp = inspect()
        d = insp.stats()
        if not d:
            d = {ERROR_KEY: 'No running Celery workers were found.'}
    except IOError as e:
        from errno import errorcode
        msg = "Error connecting to the backend: " + str(e)
        if len(e.args) > 0 and errorcode.get(e.args[0]) == 'ECONNREFUSED':
            msg += ' Check that the RabbitMQ server is running.'
        d = {ERROR_KEY: msg}
    except ImportError as e:
        d = {ERROR_KEY: str(e)}
    return d


def tab_view_count(product_id):
    product = Product.objects.get(id=product_id)
    engagements = Engagement.objects.filter(product=product, active=True)
    open_findings = Finding.objects.filter(test__engagement__product=product,
                                           false_p=False,
                                           verified=True,
                                           duplicate=False,
                                           out_of_scope=False,
                                           active=True,
                                           mitigated__isnull=True)
    endpoints = Endpoint.objects.filter(product=product)
    # benchmarks = Benchmark_Product_Summary.objects.filter(product=product, publish=True, benchmark_type__enabled=True).order_by('benchmark_type__name')
    benchmark_type = Benchmark_Type.objects.filter(enabled=True).order_by('name')
    return product, engagements, open_findings, endpoints.count(), benchmark_type
