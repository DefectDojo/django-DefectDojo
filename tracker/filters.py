__author__ = 'Jay Paz'
from datetime import timedelta, datetime
import collections

from django.conf import settings

from django_filters.filters import ChoiceFilter, _truncate
from django.utils.translation import ugettext_lazy as _
from django.utils import six
from django_filters import FilterSet, CharFilter, \
    ModelMultipleChoiceFilter, ModelChoiceFilter, MultipleChoiceFilter, \
    BooleanFilter
from django.contrib.auth.models import User
from django.forms.widgets import CheckboxInput
from pytz import timezone

from tracker.models import Tracker_User, Product_Type, Finding, \
    Product, Test_Type


local_tz = timezone(settings.TIME_ZONE)


def now():
    return local_tz.localize(datetime.today())


class DateRangeFilter(ChoiceFilter):

    options = {
        '': (_('Any date'), lambda qs, name: qs.all()),
        1: (_('Today'), lambda qs, name: qs.filter(**{
            '%s__year' % name: now().year,
            '%s__month' % name: now().month,
            '%s__day' % name: now().day
        })),
        2: (_('Past 7 days'), lambda qs, name: qs.filter(**{
            '%s__gte' % name: _truncate(now() - timedelta(days=7)),
            '%s__lt' % name: _truncate(now() + timedelta(days=1)),
        })),
        3: (_('Past 30 days'), lambda qs, name: qs.filter(**{
            '%s__gte' % name: _truncate(now() - timedelta(days=30)),
            '%s__lt' % name: _truncate(now() + timedelta(days=1)),
        })),
        4: (_('Past 90 days'), lambda qs, name: qs.filter(**{
            '%s__gte' % name: _truncate(now() - timedelta(days=90)),
            '%s__lt' % name: _truncate(now() + timedelta(days=1)),
        })),
        5: (_('Current month'), lambda qs, name: qs.filter(**{
            '%s__year' % name: now().year,
            '%s__month' % name: now().month
        })),
        6: (_('Current year'), lambda qs, name: qs.filter(**{
            '%s__year' % name: now().year,
        })),
        7: (_('Past year'), lambda qs, name: qs.filter(**{
            '%s__gte' % name: _truncate(now() - timedelta(days=365)),
            '%s__lt' % name: _truncate(now() + timedelta(days=1)),
        })),
    }

    def __init__(self, *args, **kwargs):
        kwargs['choices'] = [
            (key, value[0]) for key, value in six.iteritems(self.options)]
        super(DateRangeFilter, self).__init__(*args, **kwargs)

    def filter(self, qs, value):
        try:
            value = int(value)
        except (ValueError, TypeError):
            value = ''
        return self.options[value][1](qs, self.name)


class MetricsDateRangeFilter(ChoiceFilter):
    def any(self, qs, name):
        findings = Finding.objects.all()
        if findings:
            first_date = findings.order_by('date')[:1][0].date
            start_date = local_tz.localize(datetime.combine(
                first_date, datetime.min.time())
            )
            self.start_date = _truncate(start_date - timedelta(days=1))
            self.end_date = _truncate(now() + timedelta(days=1))
            return qs.all()

    def current_month(self, qs, name):
        self.start_date = local_tz.localize(datetime(now().year, now().month, 1, 0, 0, 0))
        self.end_date = now()
        return qs.filter(**{
            '%s__year' % name: self.start_date.year,
            '%s__month' % name: self.start_date.month
        })

    def current_year(self, qs, name):
        self.start_date = local_tz.localize(datetime(now().year, 1, 1, 0, 0, 0))
        self.end_date = now()
        return qs.filter(**{
            '%s__year' % name: now().year,
        })

    def past_x_days(self, qs, name, days):
        self.start_date = _truncate(now() - timedelta(days=days))
        self.end_date = _truncate(now() + timedelta(days=1))
        return qs.filter(**{
            '%s__gte' % name: self.start_date,
            '%s__lt' % name: self.end_date,
        })

    def past_seven_days(self, qs, name):
        return self.past_x_days(qs, name, 7)

    def past_thirty_days(self, qs, name):
        return self.past_x_days(qs, name, 30)

    def past_ninety_days(self, qs, name):
        return self.past_x_days(qs, name, 90)

    def past_year(self, qs, name):
        return self.past_x_days(qs, name, 365)

    options = {
        '': (_('Past 30 days'), past_thirty_days),
        1: (_('Past 7 days'), past_seven_days),
        2: (_('Past 90 days'), past_ninety_days),
        3: (_('Current month'), current_month),
        4: (_('Current year'), current_year),
        5: (_('Past year'), past_year),
        6: (_('Any date'), any),
    }

    def __init__(self, *args, **kwargs):
        kwargs['choices'] = [
            (key, value[0]) for key, value in six.iteritems(self.options)]
        super(MetricsDateRangeFilter, self).__init__(*args, **kwargs)

        findings = Finding.objects.all()
        if findings:
            first_date = findings.order_by('date')[:1][0].date
            start_date = local_tz.localize(datetime.combine(
                first_date, datetime.min.time())
            )
            self.start_date = _truncate(start_date - timedelta(days=1))
            self.end_date = _truncate(now() + timedelta(days=1))

    def filter(self, qs, value):
        try:
            value = int(value)
        except (ValueError, TypeError):
            value = ''
        return self.options[value][1](self, qs, self.name)


class EngagementFilter(FilterSet):
    engagement__name = CharFilter(lookup_type='icontains')
    engagement__lead = ModelChoiceFilter(
        queryset=User.objects.filter(
            engagement__lead__isnull=False).distinct(),
        label="Lead")
    name = CharFilter(lookup_type='icontains')
    prod_type = ModelMultipleChoiceFilter(
        queryset=Product_Type.objects.all().order_by('name'),
        label="Product Type")

    class Meta:
        model = Product
        fields = ['name', 'prod_type']
        order_by = (('name', 'Product Name'),
                    ('prod_type', 'Product Type'),)


class ProductFilter(FilterSet):
    name = CharFilter(lookup_type='icontains', label="Product Name")
    prod_type = ModelMultipleChoiceFilter(
        queryset=Product_Type.objects.all().order_by('name'),
        label="Product Type")

    class Meta:
        model = Product
        fields = ['name', 'prod_type']
        order_by = (('name', 'Product Name'),
                    ('prod_type', 'Product Type'),)


class OpenFindingFilter(FilterSet):
    title = CharFilter(lookup_type='icontains')
    date = DateRangeFilter()
    cwe = MultipleChoiceFilter(choices=[])
    severity = MultipleChoiceFilter(choices=[])
    test__test_type = ModelMultipleChoiceFilter(
        queryset=Test_Type.objects.all())
    test__engagement__product = ModelMultipleChoiceFilter(
        queryset=Product.objects.all(),
        label="Product")

    class Meta:
        model = Finding
        order_by = (('numerical_severity', 'Severity'),
                    ('date', 'Date Ascending'),
                    ('-date', 'Date Descending'),
                    ('title', 'Finding Name'),
                    ('test__engagement__product__name', 'Product Name'))
        exclude = ['url', 'description', 'mitigation', 'impact',
                   'endpoint', 'references', 'test', 'is_template',
                   'active', 'verified', 'out_of_scope', 'false_p',
                   'duplicate', 'thread_id', 'mitigated', 'notes',
                   'numerical_severity', 'reporter']

    def __init__(self, *args, **kwargs):
        super(OpenFindingFilter, self).__init__(*args, **kwargs)
        cwe = dict()
        cwe = dict([finding.cwe, finding.cwe]
                   for finding in self.queryset.distinct()
                   if finding.cwe > 0 and finding.cwe not in cwe)
        cwe = collections.OrderedDict(sorted(cwe.items()))
        self.form.fields['cwe'].choices = cwe.items()
        sevs = dict()
        sevs = dict([finding.severity, finding.severity]
                    for finding in self.queryset.distinct()
                    if finding.severity not in sevs)
        self.form.fields['severity'].choices = sevs.items()


class OpenFingingSuperFilter(OpenFindingFilter):
    reporter = ModelMultipleChoiceFilter(
        queryset=Tracker_User.objects.all())


class ClosedFindingFilter(FilterSet):
    title = CharFilter(lookup_type='icontains')
    mitigated = DateRangeFilter(label="Mitigated Date")
    cwe = MultipleChoiceFilter(choices=[])
    severity = MultipleChoiceFilter(choices=[])
    test__test_type = ModelMultipleChoiceFilter(
        queryset=Test_Type.objects.all())
    test__engagement__product = ModelMultipleChoiceFilter(
        queryset=Product.objects.all(),
        label="Product")

    class Meta:
        model = Finding
        order_by = (('numerical_severity', 'Severity'),
                    ('date', 'Date Ascending'),
                    ('-date', 'Date Descending'),
                    ('mitigated', 'Mitigated Date Asc'),
                    ('-mitigated', 'Mitigated Date Desc'),
                    ('title', 'Finding Name'),
                    ('test__engagement__product__name', 'Product Name'))
        exclude = ['url', 'description', 'mitigation', 'impact',
                   'endpoint', 'references', 'test', 'is_template',
                   'active', 'verified', 'out_of_scope', 'false_p',
                   'duplicate', 'thread_id', 'date', 'notes',
                   'numerical_severity', 'reporter']

    def __init__(self, *args, **kwargs):
        super(ClosedFindingFilter, self).__init__(*args, **kwargs)
        cwe = dict()
        cwe = dict([finding.cwe, finding.cwe]
                   for finding in self.queryset.distinct()
                   if finding.cwe > 0 and finding.cwe not in cwe)
        cwe = collections.OrderedDict(sorted(cwe.items()))
        self.form.fields['cwe'].choices = cwe.items()
        sevs = dict()
        sevs = dict([finding.severity, finding.severity]
                    for finding in self.queryset.distinct()
                    if finding.severity not in sevs)
        self.form.fields['severity'].choices = sevs.items()


class ClosedFingingSuperFilter(ClosedFindingFilter):
    reporter = ModelMultipleChoiceFilter(
        queryset=Tracker_User.objects.all())


class AcceptedFindingFilter(FilterSet):
    title = CharFilter(lookup_type='icontains')
    test__engagement__risk_acceptance__created = \
        DateRangeFilter(label="Acceptance Date")
    date = DateRangeFilter(label="Finding Date")
    cwe = MultipleChoiceFilter(choices=[])
    severity = MultipleChoiceFilter(choices=[])
    test__test_type = ModelMultipleChoiceFilter(
        queryset=Test_Type.objects.all())
    test__engagement__product = ModelMultipleChoiceFilter(
        queryset=Product.objects.all(),
        label="Product")

    class Meta:
        model = Finding
        order_by = (('numerical_severity', 'Severity'),
                    ('date', 'Finding Date Asc'),
                    ('-date', 'Finding Date Desc'),
                    ('test__engagement__risk_acceptance__created',
                     'Acceptance Date Asc'),
                    ('-test__engagement__risk_acceptance__created',
                     'Acceptance Date Desc'),
                    ('title', 'Finding Name'),
                    ('test__engagement__product__name', 'Product Name'))
        fields = ['title', 'test__engagement__risk_acceptance__created']
        exclude = ['url', 'description', 'mitigation', 'impact',
                   'endpoint', 'references', 'test', 'is_template',
                   'active', 'verified', 'out_of_scope', 'false_p',
                   'duplicate', 'thread_id', 'mitigated', 'notes',
                   'numerical_severity', 'reporter']

    def __init__(self, *args, **kwargs):
        super(AcceptedFindingFilter, self).__init__(*args, **kwargs)
        cwe = dict()
        cwe = dict([finding.cwe, finding.cwe]
                   for finding in self.queryset.distinct()
                   if finding.cwe > 0 and finding.cwe not in cwe)
        cwe = collections.OrderedDict(sorted(cwe.items()))
        self.form.fields['cwe'].choices = cwe.items()
        sevs = dict()
        sevs = dict([finding.severity, finding.severity]
                    for finding in self.queryset.distinct()
                    if finding.severity not in sevs)
        self.form.fields['severity'].choices = sevs.items()


class AcceptedFingingSuperFilter(AcceptedFindingFilter):
    test__engagement__risk_acceptance__reporter = \
        ModelMultipleChoiceFilter(
            queryset=Tracker_User.objects.all(),
            label="Risk Acceptance Reporter")


class ProductFindingFilter(FilterSet):
    title = CharFilter(lookup_type='icontains')
    date = DateRangeFilter()
    cwe = MultipleChoiceFilter(choices=[])
    severity = MultipleChoiceFilter(choices=[])
    test__test_type = ModelMultipleChoiceFilter(
        queryset=Test_Type.objects.all())

    class Meta:
        model = Finding
        order_by = (('numerical_severity', 'Severity'),
                    ('test__engagement__risk_acceptance__created', 'Date'),)
        exclude = ['url', 'description', 'mitigation', 'impact',
                   'endpoint', 'references', 'test', 'is_template',
                   'active', 'verified', 'out_of_scope', 'false_p',
                   'duplicate', 'thread_id', 'mitigated', 'notes',
                   'numerical_severity', 'reporter']

    def __init__(self, *args, **kwargs):
        super(ProductFindingFilter, self).__init__(*args, **kwargs)
        cwe = dict()
        cwe = dict([finding.cwe, finding.cwe]
                   for finding in self.queryset.distinct()
                   if finding.cwe > 0 and finding.cwe not in cwe)
        cwe = collections.OrderedDict(sorted(cwe.items()))
        self.form.fields['cwe'].choices = cwe.items()
        sevs = dict()
        sevs = dict([finding.severity, finding.severity]
                    for finding in self.queryset.distinct()
                    if finding.severity not in sevs)
        self.form.fields['severity'].choices = sevs.items()


class MetricsFindingFilter(FilterSet):
    date = MetricsDateRangeFilter()
    test__engagement__product__prod_type = ModelMultipleChoiceFilter(
        queryset=Product_Type.objects.all().order_by('name'),
        label="Product Type")
    severity = MultipleChoiceFilter(choices=[])

    def __init__(self, *args, **kwargs):
        super(MetricsFindingFilter, self).__init__(*args, **kwargs)
        sevs = dict()
        sevs = dict([finding.severity, finding.severity]
                    for finding in self.queryset.distinct()
                    if finding.severity not in sevs)
        self.form.fields['severity'].choices = sevs.items()
