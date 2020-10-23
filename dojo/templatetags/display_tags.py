from itertools import chain
import random
from django import template
from django.contrib.contenttypes.models import ContentType
from django.template.defaultfilters import stringfilter
from django.utils.html import escape
from django.utils.safestring import mark_safe, SafeData
from django.utils.text import normalize_newlines
from django.urls import reverse
from django.contrib.auth.models import User
from dojo.utils import prepare_for_view, get_system_setting, get_full_url
from dojo.user.helper import user_is_authorized
from dojo.models import Check_List, FindingImageAccessToken, Finding, System_Settings, JIRA_PKey, Product
import markdown
from django.db.models import Sum, Case, When, IntegerField, Value
from django.utils import timezone
import dateutil.relativedelta
import datetime
from ast import literal_eval
from urllib.parse import urlparse
import bleach
import git
from django.conf import settings


register = template.Library()

# Tags suitable for rendering markdown
markdown_tags = [
    "h1", "h2", "h3", "h4", "h5", "h6",
    "b", "i", "strong", "em", "tt",
    "table", "thead", "th", "tbody", "tr", "td",  # enables markdown.extensions.tables
    "p", "br",
    "pre", "div",  # used for code highlighting
    "span", "div", "blockquote", "code", "hr", "pre",
    "ul", "ol", "li", "dd", "dt",
    "img",
    "a",
    "sub", "sup",
]

markdown_attrs = {
    "*": ["id"],
    "img": ["src", "alt", "title"],
    "a": ["href", "alt", "title"],
    "span": ["class"],  # used for code highlighting
    "pre": ["class"],  # used for code highlighting
    "div": ["class"],  # used for code highlighting
}

finding_related_action_classes_dict = {
    'reset_finding_duplicate_status': 'fa fa-eraser',
    'set_finding_as_original': 'fa fa-superpowers',
    'mark_finding_duplicate': 'fa fa-copy'
}

finding_related_action_title_dict = {
    'reset_finding_duplicate_status': 'Reset duplicate status',
    'set_finding_as_original': 'Set as original',
    'mark_finding_duplicate': 'Mark as duplicate'
}


@register.filter
def markdown_render(value):
    if value:
        markdown_text = markdown.markdown(value,
                                          extensions=['markdown.extensions.nl2br',
                                                      'markdown.extensions.sane_lists',
                                                      'markdown.extensions.codehilite',
                                                      'markdown.extensions.fenced_code',
                                                      'markdown.extensions.toc',
                                                      'markdown.extensions.tables'])
        return mark_safe(bleach.clean(markdown_text, markdown_tags, markdown_attrs))


@register.filter(name='ports_open')
def ports_open(value):
    count = 0
    for ipscan in value.ipscan_set.all():
        count += len(literal_eval(ipscan.services))
    return count


@register.filter(name='url_shortner')
def url_shortner(value):
    return_value = str(value)
    url = urlparse(return_value)

    if url.path:
        return_value = url.path
        if len(return_value) == 1:
            return_value = value
    if len(str(return_value)) > 50:
        return_value = "..." + return_value[50:]

    return return_value


@register.filter(name='get_pwd')
def get_pwd(value):
    return prepare_for_view(value)


@register.filter(name='checklist_status')
def checklist_status(value):
    return Check_List.get_status(value)


@register.filter(is_safe=True, needs_autoescape=True)
@stringfilter
def linebreaksasciidocbr(value, autoescape=None):
    """
    Converts all newlines in a piece of plain text to HTML line breaks
    (``+ <br />``).
    """
    autoescape = autoescape and not isinstance(value, SafeData)
    value = normalize_newlines(value)
    if autoescape:
        value = escape(value)

    return mark_safe(value.replace('\n', '&nbsp;+<br />'))


@register.simple_tag
def dojo_version():
    from dojo import __version__
    return 'v. ' + __version__


@register.simple_tag
def dojo_current_hash():
    try:
        repo = git.Repo(search_parent_directories=True)
        sha = repo.head.object.hexsha
        return sha[:8]
    except:
        return "release mode"


@register.simple_tag
def display_date():
    return timezone.now().strftime("%b %d, %Y")


@register.simple_tag
def dojo_docs_url():
    from dojo import __docs__
    return mark_safe(__docs__)


@register.filter
def content_type(obj):
    if not obj:
        return False
    return ContentType.objects.get_for_model(obj).id


@register.filter
def content_type_str(obj):
    if not obj:
        return False
    return ContentType.objects.get_for_model(obj)


@register.filter(name='remove_string')
def remove_string(string, value):
    return string.replace(value, '')


@register.filter(name='percentage')
def percentage(fraction, value):
    return_value = ''
    if int(value) > 0 and int(fraction) > 0:
        try:
            return_value = "%.1f%%" % ((float(fraction) / float(value)) * 100)
        except ValueError:
            pass
    return return_value


def asvs_calc_level(benchmark_score):
    level = 0
    total_pass = 0
    total = 0
    if benchmark_score:
        total = benchmark_score.asvs_level_1_benchmark + \
                benchmark_score.asvs_level_2_benchmark + benchmark_score.asvs_level_3_benchmark
        total_pass = benchmark_score.asvs_level_1_score + \
                     benchmark_score.asvs_level_2_score + benchmark_score.asvs_level_3_score

        if benchmark_score.desired_level == "Level 1":
            total = benchmark_score.asvs_level_1_benchmark
            total_pass = benchmark_score.asvs_level_1_score
        elif benchmark_score.desired_level == "Level 2":
            total = benchmark_score.asvs_level_1_benchmark + \
                    benchmark_score.asvs_level_2_benchmark
            total_pass = benchmark_score.asvs_level_1_score + \
                         benchmark_score.asvs_level_2_score
        elif benchmark_score.desired_level == "Level 3":
            total = benchmark_score.asvs_level_1_benchmark + \
                    benchmark_score.asvs_level_2_benchmark + benchmark_score.asvs_level_3_benchmark

        level = percentage(total_pass, total)

    return benchmark_score.desired_level, level, str(total_pass), str(total)


def get_level(benchmark_score):
    benchmark_score.desired_level, level, total_pass, total = asvs_calc_level(benchmark_score)
    level = percentage(total_pass, total)
    return level


@register.filter(name='asvs_level')
def asvs_level(benchmark_score):
    benchmark_score.desired_level, level, total_pass, total = asvs_calc_level(
        benchmark_score)
    if level is None:
        level = ""
    else:
        level = "(" + level + ")"

    return "ASVS " + str(benchmark_score.desired_level) + " " + level + " Pass: " + str(
        total_pass) + " Total:  " + total


@register.filter(name='get_jira_conf')
def get_jira_conf(product):
    jira_conf = JIRA_PKey.objects.filter(product=product)

    return jira_conf


@register.filter(name='version_num')
def version_num(value):
    version = ""
    if value:
        version = "v." + value

    return version


@register.filter(name='count_findings_test_all')
def count_findings_test_all(test):
    open_findings = Finding.objects.filter(test=test).count()
    return open_findings


@register.filter(name='count_findings_test_duplicate')
def count_findings_test_duplicate(test):
    duplicate_findings = Finding.objects.filter(test=test, duplicate=True).count()
    return duplicate_findings


@register.filter(name='paginator')
def paginator(page):
    page_value = paginator_value(page)
    if page_value:
        page_value = "&page=" + page_value
    return page_value


@register.filter(name='paginator_form')
def paginator_form(page):
    return paginator_value(page)


def paginator_value(page):
    page_value = ""
    # isinstance(page, int):
    try:
        if int(page):
            page_value = str(page)
    except:
        pass
    return page_value


@register.filter(name='finding_sla')
def finding_sla(finding):
    if not get_system_setting('enable_finding_sla'):
        return ""

    title = ""
    severity = finding.severity
    find_sla = finding.sla_days_remaining()
    sla_age = get_system_setting('sla_' + severity.lower())
    if finding.mitigated:
        status = "blue"
        status_text = 'Remediated within SLA for ' + severity.lower() + ' findings (' + str(sla_age) + ' days)'
        if find_sla and find_sla < 0:
            status = "orange"
            find_sla = abs(find_sla)
            status_text = 'Out of SLA: Remediatied ' + str(
                find_sla) + ' days past SLA for ' + severity.lower() + ' findings (' + str(sla_age) + ' days)'
    else:
        status = "green"
        status_text = 'Remediation for ' + severity.lower() + ' findings in ' + str(sla_age) + ' days or less'
        if find_sla and find_sla < 0:
            status = "red"
            find_sla = abs(find_sla)
            status_text = 'Overdue: Remediation for ' + severity.lower() + ' findings in ' + str(
                sla_age) + ' days or less'

    if find_sla is not None:
        title = '<a data-toggle="tooltip" data-placement="bottom" title="" href="#" data-original-title="' + status_text + '">' \
                                                                                                                           '<span class="label severity age-' + status + '">' + str(find_sla) + '</span></a>'

    return mark_safe(title)


@register.filter(name='product_grade')
def product_grade(product):
    grade = ""
    system_settings = System_Settings.objects.get()
    if system_settings.enable_product_grade and product:
        prod_numeric_grade = product.prod_numeric_grade

        if prod_numeric_grade == "" or prod_numeric_grade is None:
            from dojo.utils import calculate_grade
            calculate_grade(product)
        if prod_numeric_grade:
            if prod_numeric_grade >= system_settings.product_grade_a:
                grade = 'A'
            elif prod_numeric_grade < system_settings.product_grade_a and prod_numeric_grade >= system_settings.product_grade_b:
                grade = 'B'
            elif prod_numeric_grade < system_settings.product_grade_b and prod_numeric_grade >= system_settings.product_grade_c:
                grade = 'C'
            elif prod_numeric_grade < system_settings.product_grade_c and prod_numeric_grade >= system_settings.product_grade_d:
                grade = 'D'
            elif prod_numeric_grade <= system_settings.product_grade_f:
                grade = 'F'

    return grade


@register.filter
def display_index(data, index):
    return data[index]


@register.filter
def finding_status(finding, duplicate):
    findingFilter = None
    if finding:
        findingFilter = finding.filter(duplicate=duplicate)
    return findingFilter


@register.simple_tag
def random_html():
    def r(): return random.randint(0, 255)

    return ('#%02X%02X%02X' % (r(), r(), r()))


@register.filter(is_safe=True, needs_autoescape=False)
@stringfilter
def action_log_entry(value, autoescape=None):
    import json
    history = json.loads(value)
    text = ''
    for k in history.keys():
        text += k.capitalize() + ' changed from "' + \
                history[k][0] + '" to "' + history[k][1] + '"'

    return text


@register.simple_tag(takes_context=True)
def dojo_body_class(context):
    request = context['request']
    return request.COOKIES.get('dojo-sidebar', 'min')


@register.simple_tag
def random_value():
    import string
    import random
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(12))


@register.filter(name='datediff_time')
def datediff_time(date1, date2):
    date_str = ""
    diff = dateutil.relativedelta.relativedelta(date2, date1)
    attrs = ['years', 'months', 'days']
    human_readable = lambda delta: ['%d %s' % (getattr(delta, attr), getattr(delta, attr) > 1 and attr or attr[:-1])
                                    for attr in attrs if getattr(delta, attr)]
    human_date = human_readable(diff)
    for date_part in human_date:
        date_str = date_str + date_part + " "

    # Date is for one day
    if date_str == "":
        date_str = "1 day"

    return date_str


@register.filter(name='overdue')
def overdue(date1):
    date_str = ""
    if date1 < datetime.datetime.now().date():
        date_str = datediff_time(date1, datetime.datetime.now().date())

    return date_str


@register.filter(name='notspecified')
def notspecified(text):
    if text:
        return text
    else:
        return mark_safe("<em class=\"text-muted\">Not Specified</em>")


@register.tag
def colgroup(parser, token):
    """
    Usage:: {% colgroup items into 3 cols as grouped_items %}

    <table border="0">
        {% for row in grouped_items %}
        <tr>
            {% for item in row %}
            <td>{% if item %}{{ forloop.parentloop.counter }}. {{ item }}{% endif %}</td>
            {% endfor %}
        </tr>
        {% endfor %}
    </table>

    Outputs::
    ============================================
    | 1. One   | 1. Eleven   | 1. Twenty One   |
    | 2. Two   | 2. Twelve   | 2. Twenty Two   |
    | 3. Three | 3. Thirteen | 3. Twenty Three |
    | 4. Four  | 4. Fourteen |                 |
    ============================================
    """

    class Node(template.Node):
        def __init__(self, iterable, num_cols, varname):
            self.iterable = iterable
            self.num_cols = num_cols
            self.varname = varname

        def render(self, context):
            iterable = template.Variable(self.iterable).resolve(context)
            num_cols = self.num_cols
            context[self.varname] = zip(
                *[chain(iterable, [None] * (num_cols - 1))] * num_cols)
            return ''

    try:
        _, iterable, _, num_cols, _, _, varname = token.split_contents()
        num_cols = int(num_cols)
    except ValueError:
        raise template.TemplateSyntaxError(
            "Invalid arguments passed to %r." % token.contents.split()[0])
    return Node(iterable, num_cols, varname)


@register.simple_tag(takes_context=True)
def pic_token(context, image, size):
    user_id = context['user_id']
    user = User.objects.get(id=user_id)
    token = FindingImageAccessToken(user=user, image=image, size=size)
    token.save()
    return reverse('download_finding_pic', args=[token.token])


@register.simple_tag
def severity_value(value):
    try:
        if get_system_setting('s_finding_severity_naming'):
            value = Finding.get_numerical_severity(value)
    except:
        pass

    return value


@register.simple_tag
def severity_number_value(value):
    return Finding.get_number_severity(value)


@register.filter
def tracked_object_value(current_object):
    value = ""

    if current_object.path is not None:
        value = current_object.path
    elif current_object.folder is not None:
        value = current_object.folder
    elif current_object.artifact is not None:
        value = current_object.artifact

    return value


@register.filter
def tracked_object_type(current_object):
    value = ""

    if current_object.path is not None:
        value = "File"
    elif current_object.folder is not None:
        value = "Folder"
    elif current_object.artifact is not None:
        value = "Artifact"

    return value


def icon(name, tooltip):
    return '<i class="fa fa-' + name + ' has-popover" data-trigger="hover" data-placement="bottom" data-content="' + tooltip + '"></i>'


def not_specified_icon(tooltip):
    return '<i class="fa fa-question fa-fw text-danger has-popover" aria-hidden="true" data-trigger="hover" data-placement="bottom" data-content="' + tooltip + '"></i>'


def stars(filled, total, tooltip):
    code = '<i class="has-popover" data-placement="bottom" data-content="' + tooltip + '">'
    for i in range(0, total):
        if i < filled:
            code += '<i class="fa fa-star has-popover" aria-hidden="true"></span>'
        else:
            code += '<i class="fa fa-star-o text-muted has-popover" aria-hidden="true"></span>'
    code += '</i>'
    return code


@register.filter
def business_criticality_icon(value):
    if value == Product.VERY_HIGH_CRITICALITY:
        return mark_safe(stars(5, 5, 'Very High'))
    if value == Product.HIGH_CRITICALITY:
        return mark_safe(stars(4, 5, 'High'))
    if value == Product.MEDIUM_CRITICALITY:
        return mark_safe(stars(3, 5, 'Medium'))
    if value == Product.LOW_CRITICALITY:
        return mark_safe(stars(2, 5, 'Low'))
    if value == Product.VERY_LOW_CRITICALITY:
        return mark_safe(stars(1, 5, 'Very Low'))
    if value == Product.NONE_CRITICALITY:
        return mark_safe(stars(0, 5, 'None'))
    else:
        return ""  # mark_safe(not_specified_icon('Business Criticality Not Specified'))


@register.filter
def last_value(value):
    if "/" in value:
        return value.rsplit("/")[-1:][0]
    else:
        return value


@register.filter
def platform_icon(value):
    if value == Product.WEB_PLATFORM:
        return mark_safe(icon('list-alt', 'Web'))
    elif value == Product.DESKTOP_PLATFORM:
        return mark_safe(icon('desktop', 'Desktop'))
    elif value == Product.MOBILE_PLATFORM:
        return mark_safe(icon('mobile', 'Mobile'))
    elif value == Product.WEB_SERVICE_PLATFORM:
        return mark_safe(icon('plug', 'Web Service'))
    elif value == Product.IOT:
        return mark_safe(icon('random', 'Internet of Things'))
    else:
        return ""  # mark_safe(not_specified_icon('Platform Not Specified'))


@register.filter
def lifecycle_icon(value):
    if value == Product.CONSTRUCTION:
        return mark_safe(icon('compass', 'Explore'))
    if value == Product.PRODUCTION:
        return mark_safe(icon('ship', 'Sustain'))
    if value == Product.RETIREMENT:
        return mark_safe(icon('moon-o', 'Retire'))
    else:
        return ""  # mark_safe(not_specified_icon('Lifecycle Not Specified'))


@register.filter
def origin_icon(value):
    if value == Product.THIRD_PARTY_LIBRARY_ORIGIN:
        return mark_safe(icon('book', 'Third-Party Library'))
    if value == Product.PURCHASED_ORIGIN:
        return mark_safe(icon('money', 'Purchased'))
    if value == Product.CONTRACTOR_ORIGIN:
        return mark_safe(icon('suitcase', 'Contractor Developed'))
    if value == Product.INTERNALLY_DEVELOPED_ORIGIN:
        return mark_safe(icon('home', 'Internally Developed'))
    if value == Product.OPEN_SOURCE_ORIGIN:
        return mark_safe(icon('code', 'Open Source'))
    if value == Product.OUTSOURCED_ORIGIN:
        return mark_safe(icon('globe', 'Outsourced'))
    else:
        return ""  # mark_safe(not_specified_icon('Origin Not Specified'))


@register.filter
def external_audience_icon(value):
    if value:
        return mark_safe(icon('users', 'External Audience'))
    else:
        return ''


@register.filter
def internet_accessible_icon(value):
    if value:
        return mark_safe(icon('cloud', 'Internet Accessible'))
    else:
        return ''


@register.filter
def get_severity_count(id, table):
    if table == "test":
        counts = Finding.objects.filter(test=id). \
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
    elif table == "engagement":
        counts = Finding.objects.filter(test__engagement=id, active=True, verified=False, duplicate=False). \
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
    elif table == "product":
        counts = Finding.objects.filter(test__engagement__product=id). \
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
    critical = 0
    high = 0
    medium = 0
    low = 0
    info = 0
    if counts["info"]:
        info = counts["info"]

    if counts["low"]:
        low = counts["low"]

    if counts["medium"]:
        medium = counts["medium"]

    if counts["high"]:
        high = counts["high"]

    if counts["critical"]:
        critical = counts["critical"]

    total = critical + high + medium + low + info
    display_counts = []

    display_counts.append("Critical: " + str(critical))
    display_counts.append("High: " + str(high))
    display_counts.append("Medium: " + str(medium))
    display_counts.append("Low: " + str(low))
    display_counts.append("Info: " + str(info))

    if table == "test":
        display_counts.append("Total: " + str(total) + " Findings")
    elif table == "engagement":
        display_counts.append("Total: " + str(total) + " Active Findings")
    elif table == "product":
        display_counts.append("Total: " + str(total) + " Active Findings")

    display_counts = ", ".join([str(item) for item in display_counts])

    return display_counts


@register.filter
def full_url(url):
    return get_full_url(url)


# check if setting is enabled in django settings.py
# use 'DISABLE_FINDING_MERGE'|setting_enabled
@register.filter
def setting_enabled(name):
    return getattr(settings, name, False)


@register.filter
def finding_display_status(finding):
    # add urls for some statuses
    # outputs html, so make sure to escape user provided fields
    display_status = finding.status()
    if finding.risk_acceptance_set.all():
        url = reverse('view_risk', args=(finding.test.engagement.id, finding.risk_acceptance_set.all()[0].id, ))
        name = finding.risk_acceptance_set.all()[0].name
        link = '<a href="' + url + '" class="has-popover" data-trigger="hover" data-placement="right" data-content="' + escape(name) + '" data-container="body" data-original-title="Risk Acceptance">Risk Accepted</a>'
        # print(link)
        display_status = display_status.replace('Risk Accepted', link)

    if finding.under_review:
        url = reverse('defect_finding_review', args=(finding.id, ))
        link = '<a href="' + url + '">Under Review</a>'
        display_status = display_status.replace('Under Review', link)

    if finding.duplicate:
        url = '#'
        name = 'unknown'
        if finding.duplicate_finding:
            url = reverse('view_finding', args=(finding.duplicate_finding.id,))
            name = finding.duplicate_finding.title + ', ' + \
                   finding.duplicate_finding.created.strftime('%b %d, %Y, %H:%M:%S')

        link = '<a href="' + url + '" data-toggle="tooltip" data-placement="top" title="' + escape(
            name) + '">Duplicate</a>'
        display_status = display_status.replace('Duplicate', link)

    return display_status


@register.filter
def is_authorized_for_change(user, obj):
    # print('filter: is_authorized_for_change')
    return user_is_authorized(user, 'change', obj)


@register.filter
def is_authorized_for_delete(user, obj):
    # print('filter: is_authorized_for_delete')
    return user_is_authorized(user, 'delete', obj)


@register.filter
def is_authorized_for_staff(user, obj):
    # print('filter: is_authorized_for_staff')
    return user_is_authorized(user, 'staff', obj)


@register.filter
def cwe_url(cwe):
    if not cwe:
        return ''
    return 'https://cwe.mitre.org/data/definitions/' + str(cwe) + '.html'


@register.filter
def cve_url(cve):
    if not cve:
        return ''
    return 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + str(cve)


@register.filter
def jiraencode(value):
    if not value:
        return value
    # jira can't handle some characters inside [] tag for urls https://jira.atlassian.com/browse/CONFSERVER-4009
    return value.replace("|", "").replace("@", "")


@register.filter
def finding_extended_title(finding):
    if not finding:
        return ''
    result = finding.title

    if finding.cve:
        result += ' (' + finding.cve + ')'

    if finding.cwe:
        result += ' (CWE-' + str(finding.cwe) + ')'

    return result


@register.filter
def finding_duplicate_cluster_size(finding):
    return len(finding.duplicate_finding_set()) + (1 if finding.duplicate_finding else 0)


@register.filter
def finding_related_action_classes(related_action):
    return finding_related_action_classes_dict.get(related_action, '')


@register.filter
def finding_related_action_title(related_action):
    return finding_related_action_title_dict.get(related_action, '')


def product_findings(product):
    return Finding.objects.filter(test__engagement__product=product)


@register.filter
def class_name(value):
    return value.__class__.__name__
