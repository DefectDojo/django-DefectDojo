__author__ = 'Jay Paz'
import collections
from datetime import timedelta, datetime

from auditlog.models import LogEntry
from django import forms
from django.contrib.auth.models import User
from django.core.exceptions import SuspiciousOperation
from django.core.paginator import Paginator
from django.utils import six
from django.utils.functional import cached_property
from django.utils.translation import ugettext_lazy as _
from django_filters import (
    FilterSet, CharFilter, ChoiceFilter, DateTimeFilter, OrderingFilter,
    ModelMultipleChoiceFilter, ModelChoiceFilter, MultipleChoiceFilter,
    TypedChoiceFilter, BooleanFilter,
)
from django_filters.filters import _truncate
from pytz import timezone

from dojo.models import Dojo_User, Product_Type, Finding, Product, Test_Type, \
    Endpoint, Development_Environment, Finding_Template, Report, Note_Type, \
    Engagement_Survey, Question, TextQuestion, ChoiceQuestion
from dojo.forms import TypedMultipleValueField
from dojo.models_base import get_perm
from dojo.utils import get_system_setting
from django.contrib.contenttypes.models import ContentType

local_tz = timezone(get_system_setting('time_zone'))

SEVERITY_CHOICES = (('Info', 'Info'), ('Low', 'Low'), ('Medium', 'Medium'),
                    ('High', 'High'), ('Critical', 'Critical'))
BOOLEAN_CHOICES = (('false', 'No'), ('true', 'Yes'),)

EARLIEST_FINDING = None


def now():
    return local_tz.localize(datetime.today())


def get_earliest_finding():
    global EARLIEST_FINDING
    if EARLIEST_FINDING is not None:
        return EARLIEST_FINDING

    try:
        EARLIEST_FINDING = Finding.objects.earliest('date')
    except Finding.DoesNotExist:
        EARLIEST_FINDING = None
    return EARLIEST_FINDING


def get_ordering_filter(ordering_fields):
    """Shortcut for generating OrderingFilter objects using HiddenInput.

    It takes a dict with field names as keys and labels as values.
    """
    return OrderingFilter(
        fields=list(ordering_fields),
        field_labels={
            field: label for field, label in ordering_fields.items()
        },
        help_text=None,
        widget=forms.HiddenInput,
    )


class OptionalBooleanFilter(TypedChoiceFilter):
    str2bool = lambda s: {"true": True, "false": False}.get(s.lower(), None)

    def __init__(self, **kwargs):
        kwargs.setdefault("choices", (("", "Any"), ("true", "True"), ("false", "False")))
        kwargs.setdefault("coerce", self.str2bool)
        super(OptionalBooleanFilter, self).__init__(**kwargs)


class DojoFilterSetNew(FilterSet):
    """
    Base for all filter sets that adds permission checks, ordering and pagination.
    """

    # Bulk actions to provide when showing this filterset.
    # See the implementation of bulk_delete() to learn how to add custom ones.
    # Natively supported are: "delete"
    bulk_actions = ()

    # When this is enabled, the base queryset is restricted for the requesting
    # user in order to apply permission restrictions. The model's default manager
    # needs to be derived from DojoQuerySet for this setting to work.
    restrict_for_user = True

    # Number of ordering filters to show
    ordering_depth = 3

    # Whether to add pagination support
    pagination = True
    page_sizes = (10, 25, 50, 75, 100, 125, 150, 175, 200)
    default_page_size = 25

    # When the filterset is shown in a collapsible panel, should that be expanded?
    panel_open_initially = False

    def __init__(self, data=None, *args, **kwargs):
        # Create a mutable copy of the submitted form data to allow manipulating it
        if data is not None:
            data = data.copy()

        super(DojoFilterSetNew, self).__init__(data=data, *args, **kwargs)

        # Separate special fields from the main filter form
        self.meta_form = forms.Form(data=self.form.data, prefix=self.form.prefix)

        # Allow filtering for specific pk's
        self.meta_form.fields["pk"] = TypedMultipleValueField(
            coerce=int, required=False,
        )

        # Allow ticking a subset of the rows explicitly
        self.meta_form.fields["tick"] = TypedMultipleValueField(
            coerce=int, required=False,
        )

        if "o" in self.filters and self.ordering_depth:
            for index in range(1, self.ordering_depth + 1):
                self.meta_form.fields["o_{}".format(index)] = forms.ChoiceField(
                    choices=self.form.fields["o"].choices,
                    required=False, label="Order by {}.".format(index),
                )

        if self.pagination:
            assert self.default_page_size in self.page_sizes
            self.meta_form.fields["page_size"] = forms.ChoiceField(
                choices=((size, size) for size in self.page_sizes),
                required=False, widget=forms.HiddenInput(),
            )
            self.meta_form.fields["page"] = forms.IntegerField(
                min_value=1, required=False, widget=forms.HiddenInput(),
            )

        # For filters displayed in a collapsible panel, this field stores its state
        self.meta_form.fields["panel_open"] = forms.BooleanField(
            initial=self.panel_open_initially,
            required=False, widget=forms.HiddenInput(),
        )

        # Helper field which is submitted when the filters should be cleared
        self.meta_form.fields["reset"] = forms.BooleanField(
            required=False, widget=forms.HiddenInput(),
        )
        if self.meta_form["reset"].data:
            # Clear out all query data related to this filterset
            for name in self.form.fields:
                self.form.data.pop(self.form[name].html_name, None)
            for name in self.meta_form.fields:
                if name == "panel_open":
                    continue
                self.meta_form.data.pop(self.meta_form[name].html_name, None)

        # Helper fields for selecting/deselecting all items across pages
        self.meta_form.fields["select_all"] = forms.BooleanField(
            required=False, widget=forms.HiddenInput(),
        )
        self.meta_form.fields["deselect_all"] = forms.BooleanField(
            required=False, widget=forms.HiddenInput(),
        )

        # Allow performing bulk actions on all ticked objects
        self.meta_form.fields["bulk_action"] = forms.CharField(
            required=False, widget=forms.HiddenInput(),
        )
        if self.meta_form["bulk_action"].data:
            if self.request and self.request.method != "POST":
                raise SuspiciousOperation("bulk actions require POST")
            self.do_bulk_action()

    @property
    def queryset(self):
        """Filters the initially provided queryset, even before evaluating any filter.

        If the filterset was initialized with a request, the original queryset is
        filtered for the current user using DojoQuerySet.for_user().
        """
        try:
            return self._filtered_initial_queryset
        except AttributeError:
            try:
                qs = self._initial_queryset
            except AttributeError:
                raise AttributeError("queryset wasn't set yet")
            # Only filter and cache after self.request is available
            if self.restrict_for_user and self.request:
                qs = qs.for_user(self.request)
                self._filtered_initial_queryset = qs
        return qs

    @queryset.setter
    def queryset(self, qs):
        self._initial_queryset = qs
        # Invalidate an eventualy cached value
        self.__dict__.pop("_filtered_initial_queryset", None)

    def filter_queryset(self, queryset):
        """Does some filtering on the queryset not related to a particular filter.

        it patches the ordering filter's value to support deep ordering.
        """
        self.meta_form.is_valid()
        pks = self.meta_form.cleaned_data.get("pk")
        if pks:
            queryset = queryset.filter(pk__in=pks)

        if "o" in self.filters:
            values = []
            for field in self.deep_ordering_fields:
                value = self.meta_form.cleaned_data.get(field.name)
                if value:
                    values.append(value)
            self.form.cleaned_data["o"] = values

        return super().filter_queryset(queryset)

    @cached_property
    def ticked_qs(self):
        """Returns self.qs, restricted to only ticked objects.

        If none are ticked, an empty QuerySet is returned.
        """
        qs = self.qs
        self.meta_form.is_valid()
        if self.meta_form.cleaned_data["select_all"]:
            # Simulate all objects being ticked
            return qs
        if not self.meta_form.cleaned_data["deselect_all"]:
            pks = self.meta_form.cleaned_data["tick"]
            if pks:
                return qs.filter(pk__in=pks)
        # None ticked, more performant than qs.filter(pk__in=[])
        return qs.none()

    @cached_property
    def out_of_page_ticks(self):
        """Returns an iterable of ticked pk's on other pages."""
        if self.page is None:
            return ()
        page_pks = (obj.pk for obj in self.page)
        return (
            pk for pk in self.ticked_qs.values_list("pk", flat=True)
            if pk not in page_pks
        )

    def do_bulk_action(self):
        """Runs the bulk action, if one was requested.

        Returns whether a bulk action has been performed.
        """
        if not self.meta_form.is_valid():
            return False
        action = self.meta_form.cleaned_data["bulk_action"]
        if action not in self.bulk_actions:
            return False
        try:
            handler = getattr(self, "bulk_%s" % action)
        except AttributeError:
            return False

        try:
            # Execute handler for the requested action
            handler()
            return True
        finally:
            # Force reevaluation of the filters to account for changed objects
            for attr in ("_filtered_initial_queryset", "_qs", "qs", "ticked_qs", "paginator", "page"):
                self.__dict__.pop(attr, None)

    def bulk_delete(self):
        """Deletes all ticked objects.

        The user is checked for "delete" permission for each object.
        """
        user = self.request.user if self.request else None
        perm = get_perm("delete", self.ticked_qs.model)
        for obj in self.ticked_qs:
            if user is None or user.has_perm(perm, obj):
                obj.delete()

    @cached_property
    def deep_ordering_fields(self):
        """Returns a tuple of bound deep-ordering form fields of this filterset."""
        return tuple(
            self.meta_form["o_{}".format(index)]
            for index in range(1, self.ordering_depth + 1)
        )

    @cached_property
    def model_name(self):
        """Returns the _meta.model_name attribute of the underlying model.

        This is used to get the model name in templates.
        """
        return self._meta.model._meta.model_name

    @cached_property
    def min_page_size(self):
        """Returns the minimum selectable page size for use in templates."""
        if self.page_sizes:
            return min(self.page_sizes)
        return 0

    @cached_property
    def page(self):
        """Returns the current Page object or None, if pagination is disabled."""
        paginator = self.paginator
        if paginator is None:
            return None
        self.meta_form.is_valid()
        return paginator.get_page(self.meta_form.cleaned_data.get("page"))

    @cached_property
    def paginator(self):
        """Creates and returns a Paginator object for the current queryset.

        It returns None if pagination has been disabled via the pagination attribute.
        """
        if not self.pagination:
            return None
        page_size = self.default_page_size
        if self.meta_form.is_valid():
            page_size = int(self.meta_form.cleaned_data["page_size"] or page_size)
        return Paginator(self.qs, page_size)

    @cached_property
    def panel_open(self):
        """Returns whether a collapsible displaying the filterset should be open."""
        if self.meta_form["panel_open"].data:
            self.meta_form.is_valid()
            return self.meta_form.cleaned_data["panel_open"]
        return self.meta_form["panel_open"].initial


class DojoFilter(FilterSet):
    def __init__(self, *args, **kwargs):
        super(DojoFilter, self).__init__(*args, **kwargs)


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
        return self.options[value][1](qs, self.field_name)


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
        return self.options[value][1](qs, self.field_name)


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
        return self.options[value][1](qs, self.field_name)


class ReportRiskAcceptanceFilter(ChoiceFilter):
    def any(self, qs, name):
        return qs.all()

    def accpeted(self, qs, name):
        return qs.filter(risk_acceptance__isnull=False)

    def not_accpeted(self, qs, name):
        return qs.filter(risk_acceptance__isnull=True)

    options = {
        '': (_('Either'), any),
        1: (_('Yes'), accpeted),
        2: (_('No'), not_accpeted),
    }

    def __init__(self, *args, **kwargs):
        kwargs['choices'] = [
            (key, value[0]) for key, value in six.iteritems(self.options)]
        super(ReportRiskAcceptanceFilter, self).__init__(*args, **kwargs)

    def filter(self, qs, value):
        try:
            value = int(value)
        except (ValueError, TypeError):
            value = ''
        return self.options[value][1](self, qs, self.field_name)


class MetricsDateRangeFilter(ChoiceFilter):
    def any(self, qs, name):
        if get_earliest_finding() is not None:
            start_date = local_tz.localize(datetime.combine(
                get_earliest_finding().date, datetime.min.time())
            )
            self.start_date = _truncate(start_date - timedelta(days=1))
            self.end_date = _truncate(now() + timedelta(days=1))
            return qs.all()

    def current_month(self, qs, name):
        self.start_date = local_tz.localize(
            datetime(now().year, now().month, 1, 0, 0, 0))
        self.end_date = now()
        return qs.filter(**{
            '%s__year' % name: self.start_date.year,
            '%s__month' % name: self.start_date.month
        })

    def current_year(self, qs, name):
        self.start_date = local_tz.localize(
            datetime(now().year, 1, 1, 0, 0, 0))
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

    def filter(self, qs, value):
        if get_earliest_finding() is not None:
            start_date = local_tz.localize(datetime.combine(
                get_earliest_finding().date, datetime.min.time())
            )
            self.start_date = _truncate(start_date - timedelta(days=1))
            self.end_date = _truncate(now() + timedelta(days=1))
        try:
            value = int(value)
        except (ValueError, TypeError):
            value = ''
        return self.options[value][1](self, qs, self.field_name)


class EngagementFilter(DojoFilter):
    engagement__lead = ModelChoiceFilter(
        queryset=User.objects.filter(
            engagement__lead__isnull=False).distinct(),
        label="Lead")
    name = CharFilter(lookup_expr='icontains')
    prod_type = ModelMultipleChoiceFilter(
        queryset=Product_Type.objects.all().order_by('name'),
        label="Product Type")

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ('name', 'name'),
            ('prod_type__name', 'prod_type__name'),
        ),
        field_labels={
            'name': 'Product Name',
            'prod_type__name': 'Product Type',
        }

    )

    class Meta:
        model = Product
        fields = ['name', 'prod_type']


class ProductFilter(DojoFilter):
    name = CharFilter(lookup_expr='icontains', label="Product Name")
    prod_type = ModelMultipleChoiceFilter(
        queryset=Product_Type.objects.all().order_by('name'),
        label="Product Type")
    business_criticality = MultipleChoiceFilter(choices=Product.BUSINESS_CRITICALITY_CHOICES)
    platform = MultipleChoiceFilter(choices=Product.PLATFORM_CHOICES)
    lifecycle = MultipleChoiceFilter(choices=Product.LIFECYCLE_CHOICES)
    origin = MultipleChoiceFilter(choices=Product.ORIGIN_CHOICES)
    external_audience = BooleanFilter(field_name='external_audience')
    internet_accessible = BooleanFilter(field_name='internet_accessible')
    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ('name', 'name'),
            ('prod_type__name', 'prod_type__name'),
            ('business_criticality', 'business_criticality'),
            ('platform', 'platform'),
            ('lifecycle', 'lifecycle'),
            ('origin', 'origin'),
            ('external_audience', 'external_audience'),
            ('internet_accessible', 'internet_accessible'),
        ),
        field_labels={
            'name': 'Product Name',
            'prod_type__name': 'Product Type',
            'business_criticality': 'Business Criticality',
            'platform': 'Platform ',
            'lifecycle': 'Lifecycle ',
            'origin': 'Origin ',
            'external_audience': 'External Audience ',
            'internet_accessible': 'Internet Accessible ',
        }

    )

    # tags = CharFilter(lookup_expr='icontains', label="Tags")

    def __init__(self, *args, **kwargs):
        self.user = None
        if 'user' in kwargs:
            self.user = kwargs.pop('user')

        super(ProductFilter, self).__init__(*args, **kwargs)

        if self.user is not None and not self.user.is_staff:
            self.form.fields[
                'prod_type'].queryset = Product_Type.objects.filter(
                prod_type__authorized_users__in=[self.user])


class OpenFindingFilter(DojoFilter):
    title = CharFilter(lookup_expr='icontains')
    duplicate = ReportBooleanFilter()
    # sourcefile = CharFilter(lookup_expr='icontains')
    sourcefilepath = CharFilter(lookup_expr='icontains')
    param = CharFilter(lookup_expr='icontains')
    payload = CharFilter(lookup_expr='icontains')
    date = DateRangeFilter()
    last_reviewed = DateRangeFilter()
    cwe = MultipleChoiceFilter(choices=[])
    severity = MultipleChoiceFilter(choices=SEVERITY_CHOICES)
    test__test_type = ModelMultipleChoiceFilter(
        queryset=Test_Type.objects.all())
    test__engagement__product = ModelMultipleChoiceFilter(
        queryset=Product.objects.all(),
        label="Product")
    if get_system_setting('enable_jira'):
        jira_issue = BooleanFilter(field_name='jira_issue',
                                   lookup_expr='isnull',
                                   exclude=True,
                                   label='JIRA issue')

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ('numerical_severity', 'numerical_severity'),
            ('date', 'date'),
            ('last_reviewed', 'last_reviewed'),
            ('title', 'title'),
            ('test__engagement__product__name',
             'test__engagement__product__name'),
        ),

    )

    class Meta:
        model = Finding
        exclude = ['url', 'description', 'mitigation', 'impact',
                   'endpoint', 'references', 'test', 'is_template',
                   'thread_id', 'notes', 'scanner_confidence', 'mitigated',
                   'numerical_severity', 'reporter', 'last_reviewed', 'line',
                   'duplicate_finding', 'hash_code', 'images',
                   'line_number', 'reviewers', 'mitigated_by', 'sourcefile', 'jira_creation', 'jira_change', 'created']

    def __init__(self, *args, **kwargs):
        self.user = None
        self.pid = None
        if 'user' in kwargs:
            self.user = kwargs.pop('user')

        if 'pid' in kwargs:
            self.pid = kwargs.pop('pid')
        super(OpenFindingFilter, self).__init__(*args, **kwargs)

        cwe = dict()
        cwe = dict([cwe, cwe]
                   for cwe in self.queryset.values_list('cwe', flat=True).distinct()
                   if type(cwe) is int and cwe is not None and cwe > 0)
        cwe = collections.OrderedDict(sorted(cwe.items()))
        self.form.fields['cwe'].choices = list(cwe.items())
        if self.user is not None and not self.user.is_staff:
            if self.form.fields.get('test__engagement__product'):
                qs = Product.objects.filter(authorized_users__in=[self.user])
                self.form.fields['test__engagement__product'].queryset = qs
            self.form.fields['endpoints'].queryset = Endpoint.objects.filter(
                product__authorized_users__in=[self.user]).distinct()

        # Don't show the product filter on the product finding view
        if self.pid:
            del self.form.fields['test__engagement__product']


class OpenFindingSuperFilter(OpenFindingFilter):
    reporter = ModelMultipleChoiceFilter(
        queryset=Dojo_User.objects.all())
    test__engagement__product__prod_type = ModelMultipleChoiceFilter(
        queryset=Product_Type.objects.all().order_by('name'),
        label="Product Type")


class ClosedFindingFilter(DojoFilter):
    title = CharFilter(lookup_expr='icontains')
    sourcefile = CharFilter(lookup_expr='icontains')
    sourcefilepath = CharFilter(lookup_expr='icontains')
    param = CharFilter(lookup_expr='icontains')
    payload = CharFilter(lookup_expr='icontains')
    mitigated = DateRangeFilter(label="Mitigated Date")
    cwe = MultipleChoiceFilter(choices=[])
    severity = MultipleChoiceFilter(choices=SEVERITY_CHOICES)
    test__test_type = ModelMultipleChoiceFilter(
        queryset=Test_Type.objects.all())
    test__engagement__product = ModelMultipleChoiceFilter(
        queryset=Product.objects.all(),
        label="Product")
    test__engagement__product__prod_type = ModelMultipleChoiceFilter(
        queryset=Product_Type.objects.all(),
        label="Product Type")

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ('numerical_severity', 'numerical_severity'),
            ('date', 'date'),
            ('mitigated', 'mitigated'),
            ('title', 'title'),
            ('test__engagement__product__name',
             'test__engagement__product__name'),
        ),
        field_labels={
            'numerical_severity': 'Severity',
            'date': 'Date',
            'mitigated': 'Mitigated Date',
            'title': 'Finding Name',
            'test__engagement__product__name': 'Product Name',
        }

    )

    class Meta:
        model = Finding
        exclude = ['url', 'description', 'mitigation', 'impact',
                   'endpoint', 'references', 'test', 'is_template',
                   'active', 'verified', 'out_of_scope', 'false_p',
                   'duplicate', 'thread_id', 'date', 'notes',
                   'numerical_severity', 'reporter', 'endpoints',
                   'last_reviewed', 'review_requested_by', 'defect_review_requested_by',
                   'last_reviewed_by', 'created', 'jira_creation', 'jira_change']

    def __init__(self, *args, **kwargs):
        super(ClosedFindingFilter, self).__init__(*args, **kwargs)
        cwe = dict()
        cwe = dict([cwe, cwe]
                   for cwe in self.queryset.values_list('cwe', flat=True).distinct()
                   if type(cwe) is int and cwe is not None and cwe > 0)
        cwe = collections.OrderedDict(sorted(cwe.items()))
        self.form.fields['cwe'].choices = list(cwe.items())


class ClosedFindingSuperFilter(ClosedFindingFilter):
    reporter = ModelMultipleChoiceFilter(
        queryset=Dojo_User.objects.all())


class AcceptedFindingFilter(DojoFilter):
    title = CharFilter(lookup_expr='icontains')
    sourcefile = CharFilter(lookup_expr='icontains')
    sourcefilepath = CharFilter(lookup_expr='icontains')
    param = CharFilter(lookup_expr='icontains')
    payload = CharFilter(lookup_expr='icontains')
    test__engagement__risk_acceptance__created = \
        DateRangeFilter(label="Acceptance Date")
    date = DateRangeFilter(label="Finding Date")
    cwe = MultipleChoiceFilter(choices=[])
    severity = MultipleChoiceFilter(choices=SEVERITY_CHOICES)
    test__test_type = ModelMultipleChoiceFilter(
        queryset=Test_Type.objects.all())
    test__engagement__product = ModelMultipleChoiceFilter(
        queryset=Product.objects.all(),
        label="Product")
    test__engagement__product__prod_type = ModelMultipleChoiceFilter(
        queryset=Product_Type.objects.all(),
        label="Product Type")

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ('numerical_severity', 'numerical_severity'),
            ('date', 'date'),
            ('test__engagement__risk_acceptance__created',
             'test__engagement__risk_acceptance__created'),
            ('title', 'title'),
            ('test__engagement__product__name',
             'test__engagement__product__name'),
        ),
        field_labels={
            'numerical_severity': 'Severity',
            'date': 'Finding Date',
            'test__engagement__risk_acceptance__created': 'Acceptance Date',
            'title': 'Finding Name',
            'test__engagement__product__name': 'Product Name',
        }

    )

    class Meta:
        model = Finding
        fields = ['title', 'test__engagement__risk_acceptance__created']
        exclude = ['url', 'description', 'mitigation', 'impact',
                   'endpoint', 'references', 'test', 'is_template',
                   'active', 'verified', 'out_of_scope', 'false_p',
                   'duplicate', 'thread_id', 'mitigated', 'notes',
                   'numerical_severity', 'reporter', 'endpoints',
                   'last_reviewed', 'o', 'jira_creation', 'jira_change']

    def __init__(self, *args, **kwargs):
        super(AcceptedFindingFilter, self).__init__(*args, **kwargs)
        cwe = dict()
        cwe = dict([finding.cwe, finding.cwe]
                   for finding in self.queryset.distinct()
                   if type(finding.cwe) is int and finding.cwe is not None and finding.cwe > 0 and finding.cwe not in cwe)
        cwe = collections.OrderedDict(sorted(cwe.items()))
        self.form.fields['cwe'].choices = list(cwe.items())


class AcceptedFindingSuperFilter(AcceptedFindingFilter):
    test__engagement__risk_acceptance__reporter = \
        ModelMultipleChoiceFilter(
            queryset=Dojo_User.objects.all(),
            label="Risk Acceptance Reporter")


class ProductFindingFilter(DojoFilter):
    title = CharFilter(lookup_expr='icontains')
    sourcefile = CharFilter(lookup_expr='icontains')
    sourcefilepath = CharFilter(lookup_expr='icontains')
    param = CharFilter(lookup_expr='icontains')
    payload = CharFilter(lookup_expr='icontains')
    date = DateRangeFilter()
    cwe = MultipleChoiceFilter(choices=[])
    severity = MultipleChoiceFilter(choices=SEVERITY_CHOICES)
    test__test_type = ModelMultipleChoiceFilter(
        queryset=Test_Type.objects.all())

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ('numerical_severity', 'numerical_severity'),
            ('date', 'date'),
            ('test__engagement__risk_acceptance__created',
             'test__engagement__risk_acceptance__created'),
            ('title', 'title'),
            ('test__engagement__product__name',
             'test__engagement__product__name'),
        ),
        field_labels={
            'numerical_severity': 'Severity',
            'date': 'Finding Date',
            'test__engagement__risk_acceptance__created': 'Acceptance Date',
            'title': 'Finding Name',
            'test__engagement__product__name': 'Product Name',
        }

    )

    class Meta:
        model = Finding
        exclude = ['url', 'description', 'mitigation', 'impact',
                   'endpoint', 'references', 'test', 'is_template',
                   'active', 'verified', 'out_of_scope', 'false_p',
                   'duplicate_finding', 'thread_id', 'mitigated', 'notes',
                   'numerical_severity', 'reporter', 'endpoints',
                   'last_reviewed', 'jira_creation', 'jira_change']

    def __init__(self, *args, **kwargs):
        super(ProductFindingFilter, self).__init__(*args, **kwargs)
        cwe = dict()
        cwe = dict([finding.cwe, finding.cwe]
                   for finding in self.queryset.distinct()
                   if type(finding.cwe) is int and finding.cwe is not None and finding.cwe > 0 and finding.cwe not in cwe)
        cwe = collections.OrderedDict(sorted(cwe.items()))
        self.form.fields['cwe'].choices = list(cwe.items())


class TemplateFindingFilter(DojoFilter):
    title = CharFilter(lookup_expr='icontains')
    cwe = MultipleChoiceFilter(choices=[])
    severity = MultipleChoiceFilter(choices=[])
    numerical_severity = MultipleChoiceFilter(choices=[])

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ('cwe', 'cwe'),
            ('title', 'title'),
            ('numerical_severity', 'numerical_severity'),
        ),
        field_labels={
            'numerical_severity': 'Severity',
        }

    )

    class Meta:
        model = Finding_Template
        exclude = ['description', 'mitigation', 'impact',
                   'references', 'numerical_severity']

    def __init__(self, *args, **kwargs):
        super(TemplateFindingFilter, self).__init__(*args, **kwargs)
        cwe = dict()
        cwe = dict([finding.cwe, finding.cwe]
                   for finding in self.queryset.distinct()
                   if type(finding.cwe) is int and finding.cwe is not None and finding.cwe > 0 and finding.cwe not in cwe)
        cwe = collections.OrderedDict(sorted(cwe.items()))
        self.form.fields['cwe'].choices = list(cwe.items())

        self.form.fields['severity'].choices = (('Critical', 'Critical'),
                                                ('High', 'High'),
                                                ('Medium', 'Medium'),
                                                ('Low', 'Low'),
                                                ('Info', 'Info'))

        self.form.fields['numerical_severity'].choices = (('S0', 'S0'),
                                                          ('S1', 'S1'),
                                                          ('S2', 'S2'),
                                                          ('S3', 'S3'),
                                                          ('S4', 'S4'))


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

    def filter(self, qs, value):
        if get_earliest_finding() is not None:
            start_date = local_tz.localize(datetime.combine(
                get_earliest_finding().date, datetime.min.time())
            )
            self.start_date = _truncate(start_date - timedelta(days=1))
            self.end_date = _truncate(now() + timedelta(days=1))
        try:
            value = int(value)
        except (ValueError, TypeError):
            value = ''
        return self.options[value][1](self, qs, self.field_name)


class MetricsFindingFilter(FilterSet):
    date = MetricsDateRangeFilter()
    test__engagement__product__prod_type = ModelMultipleChoiceFilter(
        queryset=Product_Type.objects.all().order_by('name'),
        label="Product Type")
    severity = MultipleChoiceFilter(choices=SEVERITY_CHOICES)
    status = FindingStatusFilter(label='Status')

    def __init__(self, *args, **kwargs):
        super(MetricsFindingFilter, self).__init__(*args, **kwargs)
        self.form.fields['severity'].choices = self.queryset.order_by(
            'numerical_severity'
        ).values_list('severity', 'severity').distinct()

    class Meta:
        model = Finding
        exclude = ['url',
                   'description',
                   'mitigation',
                   'unsaved_endpoints',
                   'unsaved_request',
                   'unsaved_response',
                   'unsaved_tags',
                   'references',
                   'review_requested_by',
                   'reviewers',
                   'defect_review_requested_by',
                   'thread_id',
                   'notes',
                   'last_reviewed_by',
                   'images',
                   'endpoints',
                   'is_template',
                   'jira_creation',
                   'jira_change']


class EndpointFilter(DojoFilter):
    product = ModelMultipleChoiceFilter(
        queryset=Product.objects.all().order_by('name'),
        label="Product")
    host = CharFilter(lookup_expr='icontains')
    path = CharFilter(lookup_expr='icontains')
    query = CharFilter(lookup_expr='icontains')
    fragment = CharFilter(lookup_expr='icontains')
    remediated = CharFilter(lookup_expr='icontains')

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ('product', 'product'),
            ('host', 'host'),
        ),
    )

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
        exclude = ['remediated']


class EndpointReportFilter(DojoFilter):
    host = CharFilter(lookup_expr='icontains')
    path = CharFilter(lookup_expr='icontains')
    query = CharFilter(lookup_expr='icontains')
    fragment = CharFilter(lookup_expr='icontains')
    finding__severity = MultipleChoiceFilter(choices=SEVERITY_CHOICES)
    finding__mitigated = MitigatedDateRangeFilter()

    class Meta:
        model = Endpoint
        exclude = ['product']


class ReportFindingFilter(DojoFilter):
    title = CharFilter(lookup_expr='icontains', label='Name')
    severity = MultipleChoiceFilter(choices=SEVERITY_CHOICES)
    active = ReportBooleanFilter()
    mitigated = MitigatedDateRangeFilter()
    verified = ReportBooleanFilter()
    false_p = ReportBooleanFilter(label="False Positive")
    test__engagement__risk_acceptance = ReportRiskAcceptanceFilter(
        label="Risk Accepted")
    duplicate = ReportBooleanFilter()
    out_of_scope = ReportBooleanFilter()

    class Meta:
        model = Finding
        exclude = ['date', 'cwe', 'url', 'description', 'mitigation', 'impact',
                   'endpoint', 'references', 'test', 'is_template',
                   'thread_id', 'notes', 'endpoints',
                   'numerical_severity', 'reporter', 'last_reviewed', 'images', 'jira_creation', 'jira_change']


class ReportAuthedFindingFilter(DojoFilter):
    title = CharFilter(lookup_expr='icontains', label='Name')
    test__engagement__product = ModelMultipleChoiceFilter(
        queryset=Product.objects.for_user,
        label="Product")
    test__engagement__product__prod_type = ModelMultipleChoiceFilter(
        queryset=Product_Type.objects.all(),
        label="Product Type")
    severity = MultipleChoiceFilter(choices=SEVERITY_CHOICES)
    active = ReportBooleanFilter()
    mitigated = MitigatedDateRangeFilter()
    verified = ReportBooleanFilter()
    false_p = ReportBooleanFilter(label="False Positive")
    test__engagement__risk_acceptance = ReportRiskAcceptanceFilter(
        label="Risk Accepted")
    duplicate = ReportBooleanFilter()
    out_of_scope = ReportBooleanFilter()

    @property
    def qs(self):
        parent = super(ReportAuthedFindingFilter, self).qs
        return parent.filter(
            test__engagement__product__authorized_users__in=[self.request.user],
        )

    class Meta:
        model = Finding
        exclude = ['date', 'cwe', 'url', 'description', 'mitigation', 'impact',
                   'endpoint', 'references', 'test', 'is_template',
                   'thread_id', 'notes', 'endpoints',
                   'numerical_severity', 'reporter', 'last_reviewed', 'jira_creation', 'jira_change']


class UserFilter(DojoFilter):
    first_name = CharFilter(lookup_expr='icontains')
    last_name = CharFilter(lookup_expr='icontains')
    username = CharFilter(lookup_expr='icontains')

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ('username', 'username'),
            ('last_name', 'last_name'),
            ('first_name', 'first_name'),
            ('email', 'email'),
            ('is_active', 'is_active'),
            ('is_staff', 'is_staff'),
            ('is_superuser', 'is_superuser'),
        ),
        field_labels={
            'username': 'User Name',
            'is_active': 'Active',
            'is_staff': 'Staff',
            'is_superuser': 'Superuser',
        }

    )

    class Meta:
        model = Dojo_User
        fields = ['is_staff', 'is_superuser', 'is_active', 'first_name',
                  'last_name', 'username']
        exclude = ['password', 'last_login', 'groups', 'user_permissions',
                   'date_joined']


class ReportFilter(DojoFilter):
    name = CharFilter(lookup_expr='icontains')
    type = MultipleChoiceFilter(choices=[])
    format = MultipleChoiceFilter(choices=[])
    requester = ModelMultipleChoiceFilter(queryset=Dojo_User.objects.all())
    datetime = DateTimeFilter()
    status = MultipleChoiceFilter(choices=[])

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ('datetime', 'datetime'),
            ('name', 'name'),
            ('type', 'type'),
            ('format', 'format'),
            ('requester', 'requester'),
        ),
        field_labels={
            'datetime': 'Date',
        }

    )

    class Meta:
        model = Report
        exclude = ['task_id', 'file']

    def __init__(self, *args, **kwargs):
        super(ReportFilter, self).__init__(*args, **kwargs)
        type = dict()
        type = dict(
            [report.type, report.type] for report in self.queryset.distinct()
            if report.type is not None)
        type = collections.OrderedDict(sorted(type.items()))
        self.form.fields['type'].choices = list(type.items())

        status = dict()
        status = dict(
            [report.status, report.status] for report in
            self.queryset.distinct() if report.status is not None)
        status = collections.OrderedDict(sorted(status.items()))
        self.form.fields['status'].choices = list(status.items())


class EngineerFilter(DojoFilter):
    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ('username', 'username'),
            ('last_name', 'last_name'),
            ('first_name', 'first_name'),
            ('email', 'email'),
            ('is_active', 'is_active'),
            ('is_staff', 'is_staff'),
            ('is_superuser', 'is_superuser'),
        ),
        field_labels={
            'username': 'User Name',
            'is_active': 'Active',
            'is_staff': 'Staff',
            'is_superuser': 'Superuser',
        }

    )

    class Meta:
        model = Dojo_User
        fields = ['is_staff', 'is_superuser', 'is_active', 'username', 'email',
                  'last_name', 'first_name']
        exclude = ['password', 'last_login', 'groups', 'user_permissions',
                   'date_joined']


class LogEntryFilter(DojoFilter):
    from auditlog.models import LogEntry

    action = MultipleChoiceFilter(choices=LogEntry.Action.choices)
    actor = ModelMultipleChoiceFilter(queryset=Dojo_User.objects.all())
    timestamp = DateRangeFilter()

    class Meta:
        model = LogEntry
        exclude = ['content_type', 'object_pk', 'object_id', 'object_repr',
                   'changes', 'additional_data']


class ProductTypeFilter(DojoFilter):
    name = CharFilter(lookup_expr='icontains')

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ('name', 'name'),
        ),
    )

    class Meta:
        model = Product_Type
        exclude = []
        include = ('name',)


class TestTypeFilter(DojoFilter):
    name = CharFilter(lookup_expr='icontains')

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ('name', 'name'),
        ),
    )

    class Meta:
        model = Test_Type
        exclude = []
        include = ('name',)


class DevelopmentEnvironmentFilter(DojoFilter):
    name = CharFilter(lookup_expr='icontains')

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ('name', 'name'),
        ),
    )

    class Meta:
        model = Development_Environment
        exclude = []
        include = ('name',)


class NoteTypesFilter(DojoFilter):
    name = CharFilter(lookup_expr='icontains')

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ('name', 'name'),
            ('description', 'description'),
            ('is_single', 'is_single'),
            ('is_mandatory', 'is_mandatory'),
        ),
    )

    class Meta:
        model = Note_Type
        exclude = []
        include = ('name', 'is_single', 'description')

# ==============================
# Defect Dojo Engaegment Surveys
# ==============================


class SurveyFilter(FilterSet):
    name = CharFilter(lookup_expr='icontains')
    description = CharFilter(lookup_expr='icontains')
    active = BooleanFilter()

    class Meta:
        model = Engagement_Survey
        exclude = ['questions']

    survey_set = FilterSet


class QuestionTypeFilter(ChoiceFilter):
    def any(self, qs, name):
        return qs.all()

    def text_question(self, qs, name):
        return qs.filter(polymorphic_ctype=ContentType.objects.get_for_model(TextQuestion))

    def choice_question(self, qs, name):
        return qs.filter(polymorphic_ctype=ContentType.objects.get_for_model(ChoiceQuestion))

    options = {
        '': (_('Any'), any),
        1: (_('Text Question'), text_question),
        2: (_('Choice Question'), choice_question),
    }

    def __init__(self, *args, **kwargs):
        kwargs['choices'] = [
            (key, value[0]) for key, value in six.iteritems(self.options)]
        super(QuestionTypeFilter, self).__init__(*args, **kwargs)

    def filter(self, qs, value):
        try:
            value = int(value)
        except (ValueError, TypeError):
            value = ''
        return self.options[value][1](self, qs, self.options[value][0])


class QuestionFilter(FilterSet):
    text = CharFilter(lookup_expr='icontains')
    type = QuestionTypeFilter()

    class Meta:
        model = Question
        exclude = ['polymorphic_ctype', 'created', 'modified', 'order']

    question_set = FilterSet
