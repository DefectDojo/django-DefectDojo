__author__ = 'Jay Paz'
from auditlog.models import LogEntry
from datetime import timedelta, datetime
import collections
from django.conf import settings
from django import forms
from django_filters.filters import ChoiceFilter, _truncate
from django.utils.translation import ugettext_lazy as _
from django.utils import six
from django_filters import FilterSet, CharFilter, \
    ModelMultipleChoiceFilter, ModelChoiceFilter, MultipleChoiceFilter
from django.contrib.auth.models import User
from pytz import timezone
from dojo.models import Dojo_User, Product_Type, Finding, \
    Product, Test_Type, Endpoint, Development_Environment, Finding_Template

local_tz = timezone(settings.TIME_ZONE)
SEVERITY_CHOICES = (('Info', 'Info'), ('Low', 'Low'), ('Medium', 'Medium'),
                    ('High', 'High'), ('Critical', 'Critical'))
BOOLEAN_CHOICES = (('false', 'No'), ('true', 'Yes'),)


def now():
    return local_tz.localize(datetime.today())


class DojoFilter(FilterSet):
    def __init__(self, *args, **kwargs):
        super(DojoFilter, self).__init__(*args, **kwargs)
        page_size = forms.ChoiceField(
            choices=((25, 25), (50, 50), (75, 75), (100, 100), (150, 150),),
            required=False)
        self.form.fields['page_size'] = page_size


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


class MitigatedDateRangeFilter(ChoiceFilter):
    options = {
        '': (_('Either'), lambda qs, name: qs.all()),
        1: (_('Yes'), lambda qs, name: qs.filter(**{
            '%s__isnull' % name: False
        })),
        2: (_('No'), lambda qs, name: qs.filter(**{
            '%s__isnull' % name: True
        })),
    }

    def __init__(self, *args, **kwargs):
        kwargs['choices'] = [
            (key, value[0]) for key, value in six.iteritems(self.options)]
        super(MitigatedDateRangeFilter, self).__init__(*args, **kwargs)

    def filter(self, qs, value):
        try:
            value = int(value)
        except (ValueError, TypeError):
            value = ''
        return self.options[value][1](qs, self.name)


class ReportBooleanFilter(ChoiceFilter):
    options = {
        '': (_('Either'), lambda qs, name: qs.all()),
        1: (_('Yes'), lambda qs, name: qs.filter(**{
            '%s' % name: True
        })),
        2: (_('No'), lambda qs, name: qs.filter(**{
            '%s' % name: False
        })),
    }

    def __init__(self, *args, **kwargs):
        kwargs['choices'] = [
            (key, value[0]) for key, value in six.iteritems(self.options)]
        super(ReportBooleanFilter, self).__init__(*args, **kwargs)

    def filter(self, qs, value):
        try:
            value = int(value)
        except (ValueError, TypeError):
            value = ''
        return self.options[value][1](qs, self.name)


class MetricsDateRangeFilter(ChoiceFilter):
    def any(self, qs, name):
        try:
            earliest_finding = Finding.objects.earliest('date')
        except Finding.DoesNotExist:
            earliest_finding = None

        if earliest_finding:
            start_date = local_tz.localize(datetime.combine(
                earliest_finding.date, datetime.min.time())
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

    def past_six_months(self, qs, name):
        return self.past_x_days(qs, name, 183)

    def past_year(self, qs, name):
        return self.past_x_days(qs, name, 365)

    options = {
        '': (_('Past 30 days'), past_thirty_days),
        1: (_('Past 7 days'), past_seven_days),
        2: (_('Past 90 days'), past_ninety_days),
        3: (_('Current month'), current_month),
        4: (_('Current year'), current_year),
        5: (_('Past 6 Months'), past_six_months),
        6: (_('Past year'), past_year),
        7: (_('Any date'), any),
    }

    def __init__(self, *args, **kwargs):
        kwargs['choices'] = [
            (key, value[0]) for key, value in six.iteritems(self.options)]
        super(MetricsDateRangeFilter, self).__init__(*args, **kwargs)

        try:
            earliest_finding = Finding.objects.earliest('date')
        except Finding.DoesNotExist:
            earliest_finding = None

        if earliest_finding:
            start_date = local_tz.localize(datetime.combine(
                earliest_finding.date, datetime.min.time())
            )
            self.start_date = _truncate(start_date - timedelta(days=1))
            self.end_date = _truncate(now() + timedelta(days=1))

    def filter(self, qs, value):
        try:
            value = int(value)
        except (ValueError, TypeError):
            value = ''
        return self.options[value][1](self, qs, self.name)


class EngagementFilter(DojoFilter):
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
                    ('-name', 'Product Name Desc'),
                    ('prod_type__name', 'Product Type'),
                    ('-prod_type__name', 'Product Type Desc'),)


class ProductFilter(DojoFilter):
    name = CharFilter(lookup_type='icontains', label="Product Name")
    prod_type = ModelMultipleChoiceFilter(
        queryset=Product_Type.objects.all().order_by('name'),
        label="Product Type")

    def __init__(self, *args, **kwargs):
        self.user = None
        if 'user' in kwargs:
            self.user = kwargs.pop('user')
        super(ProductFilter, self).__init__(*args, **kwargs)

        if self.user is not None and not self.user.is_staff:
            self.form.fields['prod_type'].queryset = Product_Type.objects.filter(
                prod_type__authorized_users__in=[self.user])

    class Meta:
        model = Product
        fields = ['name', 'prod_type']
        order_by = (('name', 'Product Name'),
                    ('-name', 'Product Name Desc'),
                    ('prod_type__name', 'Product Type'),
                    ('-prod_type__name', 'Product Type Desc'))


class OpenFindingFilter(DojoFilter):
    title = CharFilter(lookup_type='icontains')
    date = DateRangeFilter()
    last_reviewed = DateRangeFilter()
    cwe = MultipleChoiceFilter(choices=[])
    severity = MultipleChoiceFilter(choices=[])
    test__test_type = ModelMultipleChoiceFilter(
        queryset=Test_Type.objects.all())
    test__engagement__product = ModelMultipleChoiceFilter(
        queryset=Product.objects.all(),
        label="Product")

    class Meta:
        model = Finding
        order_by = (('numerical_severity', 'Severity Asc'),
                    ('-numerical_severity', 'Severity Desc'),
                    ('date', 'Date Asc'),
                    ('-date', 'Date Desc'),
                    ('last_reviewed', 'Review Date Asc'),
                    ('-last_reviewed', 'Review Date Desc'),
                    ('title', 'Finding Name Asc'),
                    ('-title', 'Finding Name Desc'),
                    ('test__engagement__product__name', 'Product Name Asc'),
                    ('-test__engagement__product__name', 'Product Name Desc'))
        exclude = ['url', 'description', 'mitigation', 'impact',
                   'endpoint', 'references', 'test', 'is_template',
                   'active', 'verified', 'out_of_scope', 'false_p',
                   'duplicate', 'thread_id', 'mitigated', 'notes',
                   'numerical_severity', 'reporter', 'last_reviewed']

    def __init__(self, *args, **kwargs):
        self.user = None
        if 'user' in kwargs:
            self.user = kwargs.pop('user')
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
        if self.user is not None and not self.user.is_staff:
            self.form.fields['test__engagement__product'].queryset = Product.objects.filter(
                authorized_users__in=[self.user])
            self.form.fields['endpoints'].queryset = Endpoint.objects.filter(
                product__authorized_users__in=[self.user]).distinct()


class OpenFingingSuperFilter(OpenFindingFilter):
    reporter = ModelMultipleChoiceFilter(
        queryset=Dojo_User.objects.all())
    test__engagement__product__prod_type = ModelMultipleChoiceFilter(
        queryset=Product_Type.objects.all().order_by('name'),
        label="Product Type")


class ClosedFindingFilter(DojoFilter):
    title = CharFilter(lookup_type='icontains')
    mitigated = DateRangeFilter(label="Mitigated Date")
    cwe = MultipleChoiceFilter(choices=[])
    severity = MultipleChoiceFilter(choices=[])
    test__test_type = ModelMultipleChoiceFilter(
        queryset=Test_Type.objects.all())
    test__engagement__product = ModelMultipleChoiceFilter(
        queryset=Product.objects.all(),
        label="Product")
    test__engagement__product__prod_type = ModelMultipleChoiceFilter(
        queryset=Product_Type.objects.all(),
        label="Product Type")

    class Meta:
        model = Finding
        order_by = (('numerical_severity', 'Severity'),
                    ('-numerical_severity', 'Severity Desc'),
                    ('date', 'Date Ascending'),
                    ('-date', 'Date Descending'),
                    ('mitigated', 'Mitigated Date Asc'),
                    ('-mitigated', 'Mitigated Date Desc'),
                    ('title', 'Finding Name'),
                    ('-title', 'Finding Name Desc'),
                    ('test__engagement__product__name', 'Product Name'),
                    ('-test__engagement__product__name', 'Product Name Desc'))
        exclude = ['url', 'description', 'mitigation', 'impact',
                   'endpoint', 'references', 'test', 'is_template',
                   'active', 'verified', 'out_of_scope', 'false_p',
                   'duplicate', 'thread_id', 'date', 'notes',
                   'numerical_severity', 'reporter', 'endpoints', 'last_reviewed']

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
        queryset=Dojo_User.objects.all())


class AcceptedFindingFilter(DojoFilter):
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
    test__engagement__product__prod_type = ModelMultipleChoiceFilter(
        queryset=Product_Type.objects.all(),
        label="Product Type")

    class Meta:
        model = Finding
        order_by = (('numerical_severity', 'Severity'),
                    ('-numerical_severity', 'Severity Desc'),
                    ('date', 'Finding Date Asc'),
                    ('-date', 'Finding Date Desc'),
                    ('test__engagement__risk_acceptance__created',
                     'Acceptance Date Asc'),
                    ('-test__engagement__risk_acceptance__created',
                     'Acceptance Date Desc'),
                    ('title', 'Finding Name'),
                    ('-title', 'Finding Name Desc'),
                    ('test__engagement__product__name', 'Product Name'),
                    ('-test__engagement__product__name', 'Product Name Dec'))
        fields = ['title', 'test__engagement__risk_acceptance__created']
        exclude = ['url', 'description', 'mitigation', 'impact',
                   'endpoint', 'references', 'test', 'is_template',
                   'active', 'verified', 'out_of_scope', 'false_p',
                   'duplicate', 'thread_id', 'mitigated', 'notes',
                   'numerical_severity', 'reporter', 'endpoints', 'last_reviewed', 'o']

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
            queryset=Dojo_User.objects.all(),
            label="Risk Acceptance Reporter")


class ProductFindingFilter(DojoFilter):
    title = CharFilter(lookup_type='icontains')
    date = DateRangeFilter()
    cwe = MultipleChoiceFilter(choices=[])
    severity = MultipleChoiceFilter(choices=[])
    test__test_type = ModelMultipleChoiceFilter(
        queryset=Test_Type.objects.all())

    class Meta:
        model = Finding
        order_by = (('title', 'Name'),
                    ('-title', 'Name Desc'),
                    ('numerical_severity', 'Severity'),
                    ('-numerical_severity', 'Severity Desc'),
                    ('test__engagement__risk_acceptance__created', 'Date'),
                    ('-test__engagement__risk_acceptance__created', 'Date Desc'))
        exclude = ['url', 'description', 'mitigation', 'impact',
                   'endpoint', 'references', 'test', 'is_template',
                   'active', 'verified', 'out_of_scope', 'false_p',
                   'duplicate', 'thread_id', 'mitigated', 'notes',
                   'numerical_severity', 'reporter', 'endpoints', 'last_reviewed']

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


class TemplateFindingFilter(DojoFilter):
    title = CharFilter(lookup_type='icontains')
    cwe = MultipleChoiceFilter(choices=[])
    severity = MultipleChoiceFilter(choices=[])
    numerical_severity = MultipleChoiceFilter(choices=[])

    class Meta:
        model = Finding_Template
        order_by = (('cwe', 'CWE Asc'),
                    ('-cwe', 'CWE Desc'),
                    ('title', 'Title Asc'),
                    ('-title', 'Title Desc'),
                    ('-numerical_severity', 'Severity Asc'),
                    ('numerical_severity', 'Severity Desc'),)
        exclude = ['description', 'mitigation', 'impact',
                   'references', 'numerical_severity']

    def __init__(self, *args, **kwargs):
        super(TemplateFindingFilter, self).__init__(*args, **kwargs)
        cwe = dict()
        cwe = dict([finding.cwe, finding.cwe]
                   for finding in self.queryset.distinct()
                   if finding.cwe > 0 and finding.cwe not in cwe)
        cwe = collections.OrderedDict(sorted(cwe.items()))
        self.form.fields['cwe'].choices = cwe.items()

        self.form.fields['severity'].choices = ((u'Critical', u'Critical'),
                                                (u'High', u'High'),
                                                (u'Medium', u'Medium'),
                                                (u'Low', u'Low'),
                                                (u'Info', u'Info'))

        self.form.fields['numerical_severity'].choices = ((u'S0', u'S0'),
                                                          (u'S1', u'S1'),
                                                          (u'S2', u'S2'),
                                                          (u'S3', u'S3'),
                                                          (u'S4', u'S4'))


class FindingStatusFilter(ChoiceFilter):
    def any(self, qs, name):
        return qs.filter(verified=True,
                         false_p=False,
                         duplicate=False,
                         out_of_scope=False)

    def open(self, qs, name):
        return qs.filter(mitigated__isnull=True,
                         verified=True,
                         false_p=False,
                         duplicate=False,
                         out_of_scope=False, )

    def closed(self, qs, name):
        return qs.filter(mitigated__isnull=False,
                         verified=True,
                         false_p=False,
                         duplicate=False,
                         out_of_scope=False, )

    options = {
        '': (_('Any'), any),
        0: (_('Open'), open),
        1: (_('Closed'), closed),
    }

    def __init__(self, *args, **kwargs):
        kwargs['choices'] = [
            (key, value[0]) for key, value in six.iteritems(self.options)]
        super(FindingStatusFilter, self).__init__(*args, **kwargs)

        try:
            earliest_finding = Finding.objects.earliest('date')
        except Finding.DoesNotExist:
            earliest_finding = None

        if earliest_finding:
            start_date = local_tz.localize(datetime.combine(
                earliest_finding.date, datetime.min.time())
            )
            self.start_date = _truncate(start_date - timedelta(days=1))
            self.end_date = _truncate(now() + timedelta(days=1))

    def filter(self, qs, value):
        try:
            value = int(value)
        except (ValueError, TypeError):
            value = ''
        return self.options[value][1](self, qs, self.name)


class MetricsFindingFilter(FilterSet):
    date = MetricsDateRangeFilter()
    test__engagement__product__prod_type = ModelMultipleChoiceFilter(
        queryset=Product_Type.objects.all().order_by('name'),
        label="Product Type")
    severity = MultipleChoiceFilter(choices=[])
    status = FindingStatusFilter()

    def __init__(self, *args, **kwargs):
        super(MetricsFindingFilter, self).__init__(*args, **kwargs)
        self.form.fields['severity'].choices = self.queryset.order_by('numerical_severity') \
            .values_list('severity', 'severity').distinct()


class EndpointFilter(DojoFilter):
    product = ModelMultipleChoiceFilter(
        queryset=Product.objects.all().order_by('name'),
        label="Product")
    host = CharFilter(lookup_type='icontains')
    path = CharFilter(lookup_type='icontains')
    query = CharFilter(lookup_type='icontains')
    fragment = CharFilter(lookup_type='icontains')

    def __init__(self, *args, **kwargs):
        self.user = None
        if 'user' in kwargs:
            self.user = kwargs.pop('user')
        super(EndpointFilter, self).__init__(*args, **kwargs)
        if self.user and not self.user.is_staff:
            self.form.fields['product'].queryset = Product.objects.filter(
                authorized_users__in=[self.user]).distinct().order_by('name')

    class Meta:
        model = Endpoint
        order_by = (('product', 'Product'),
                    ('-product', 'Product Desc'),
                    ('host', 'Host'),
                    ('-host', 'Host Desc'))


class EndpointReportFilter(DojoFilter):
    host = CharFilter(lookup_type='icontains')
    path = CharFilter(lookup_type='icontains')
    query = CharFilter(lookup_type='icontains')
    fragment = CharFilter(lookup_type='icontains')
    finding__severity = MultipleChoiceFilter(choices=SEVERITY_CHOICES)
    finding__mitigated = MitigatedDateRangeFilter()

    class Meta:
        model = Endpoint
        exclude = ['product']


class ReportFindingFilter(DojoFilter):
    severity = MultipleChoiceFilter(choices=SEVERITY_CHOICES)
    active = ReportBooleanFilter()
    mitigated = MitigatedDateRangeFilter()
    verified = ReportBooleanFilter()
    false_p = ReportBooleanFilter(label="False Positive")
    duplicate = ReportBooleanFilter()
    out_of_scope = ReportBooleanFilter()

    class Meta:
        model = Finding
        exclude = ['title', 'date', 'cwe', 'url', 'description', 'mitigation', 'impact',
                   'endpoint', 'references', 'test', 'is_template',
                   'thread_id', 'notes', 'endpoints',
                   'numerical_severity', 'reporter', 'last_reviewed']


class ReportAuthedFindingFilter(DojoFilter):
    test__engagement__product = ModelMultipleChoiceFilter(queryset=Product.objects.all(), label="Product")
    severity = MultipleChoiceFilter(choices=SEVERITY_CHOICES)
    active = ReportBooleanFilter()
    mitigated = MitigatedDateRangeFilter()
    verified = ReportBooleanFilter()
    false_p = ReportBooleanFilter(label="False Positive")
    duplicate = ReportBooleanFilter()
    out_of_scope = ReportBooleanFilter()

    def __init__(self, *args, **kwargs):
        self.user = None
        if 'user' in kwargs:
            self.user = kwargs.pop('user')
        super(ReportAuthedFindingFilter, self).__init__(*args, **kwargs)
        if not self.user.is_staff:
            self.form.fields['test__engagement__product'].queryset = Product.objects.filter(
                authorized_users__in=[self.user])

    class Meta:
        model = Finding
        exclude = ['title', 'date', 'cwe', 'url', 'description', 'mitigation', 'impact',
                   'endpoint', 'references', 'test', 'is_template',
                   'thread_id', 'notes', 'endpoints',
                   'numerical_severity', 'reporter', 'last_reviewed']


class UserFilter(DojoFilter):
    first_name = CharFilter(lookup_type='icontains')
    last_name = CharFilter(lookup_type='icontains')
    username = CharFilter(lookup_type='icontains')

    class Meta:
        model = Dojo_User
        fields = ['is_staff', 'is_superuser', 'is_active', 'first_name', 'last_name', 'username']
        exclude = ['password', 'last_login', 'groups', 'user_permissions', 'date_joined']
        order_by = (('username', 'User Name'),
                    ('-username', 'User Name Desc'),
                    ('last_name', 'Last Name'),
                    ('-last_name', 'Last Name Desc'),
                    ('first_name', 'First Name'),
                    ('-first_name', 'First Name Desc'),
                    ('email', 'Email'),
                    ('-email', 'Email Desc'),
                    ('is_active', 'Active'),
                    ('-is_active', 'Active Desc'),
                    ('is_staff', 'Staff'),
                    ('-is_staff', 'Staff Desc'),
                    ('is_superuser', 'SuperUser'),
                    ('-is_superuser', 'SuperUser Desc'),)


class EngineerFilter(DojoFilter):
    class Meta:
        model = Dojo_User
        fields = ['is_staff', 'is_superuser', 'is_active', 'username', 'email', 'last_name', 'first_name']
        exclude = ['password', 'last_login', 'groups', 'user_permissions', 'date_joined']
        order_by = (('username', 'User Name'),
                    ('-username', 'User Name Desc'),
                    ('last_name', 'Last Name'),
                    ('-last_name', 'Last Name Desc'),
                    ('first_name', 'First Name'),
                    ('-first_name', 'First Name Desc'),
                    ('email', 'Email'),
                    ('-email', 'Email Desc'),
                    ('last_login', 'Last Login'),
                    ('-last_login', 'Last Login Desc'),
                    ('is_active', 'Active'),
                    ('-is_active', 'Active Desc'),
                    ('is_staff', 'Staff'),
                    ('-is_staff', 'Staff Desc'),
                    ('is_superuser', 'SuperUser'),
                    ('-is_superuser', 'SuperUser Desc'),
                    )


class LogEntryFilter(DojoFilter):
    from auditlog.models import LogEntry

    action = MultipleChoiceFilter(choices=LogEntry.Action.choices)
    actor = ModelMultipleChoiceFilter(queryset=Dojo_User.objects.all())
    timestamp = DateRangeFilter()

    class Meta:
        model = LogEntry
        exclude = ['content_type', 'object_pk', 'object_id', 'object_repr', 'changes']


class ProductTypeFilter(DojoFilter):
    name = CharFilter(lookup_type='icontains')

    class Meta:
        model = Product_Type
        include = ('name',)
        order_by = (('name', ' Name'),
                    ('-name', 'Name Desc'))


class TestTypeFilter(DojoFilter):
    name = CharFilter(lookup_type='icontains')

    class Meta:
        model = Test_Type
        include = ('name',)
        order_by = (('name', ' Name'),
                    ('-name', 'Name Desc'))


class DevelopmentEnvironmentFilter(DojoFilter):
    name = CharFilter(lookup_type='icontains')

    class Meta:
        model = Development_Environment
        include = ('name',)
        order_by = (('name', ' Name'),
                    ('-name', 'Name Desc'))
