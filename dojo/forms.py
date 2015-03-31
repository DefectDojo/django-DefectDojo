import collections
from datetime import datetime, date
import re

from dateutil.relativedelta import relativedelta
from django import forms
from django.core import validators
from django.forms.widgets import Widget, Select
from django.utils.dates import MONTHS
from django.utils.safestring import mark_safe
from pytz import timezone


from dojo.models import Finding, Product_Type, Product, ScanSettings, VA, \
    Check_List, User, Engagement, Test, Test_Type, Notes, Risk_Acceptance, \
    Development_Environment, Dojo_User, Scan
from dojo.filters import DateRangeFilter
from dojo import settings


RE_DATE = re.compile(r'(\d{4})-(\d\d?)-(\d\d?)$')
localtz = timezone(settings.TIME_ZONE)

FINDING_STATUS = (('verified', 'Verified'),
                  ('false_p', 'False Positive'),
                  ('duplicate', 'Duplicate'),
                  ('out_of_scope', 'Out of Scope'))


class MonthYearWidget(Widget):
    """
    A Widget that splits date input into two <select> boxes for month and year,
    with 'day' defaulting to the first of the month.

    Based on SelectDateWidget, in

    django/trunk/django/forms/extras/widgets.py
    """
    none_value = (0, '---')
    month_field = '%s_month'
    year_field = '%s_year'

    def __init__(self, attrs=None, years=None, required=True):
        # years is an optional list/tuple of years to use in the
        # "year" select box.
        self.attrs = attrs or {}
        self.required = required
        if years:
            self.years = years
        else:
            this_year = date.today().year
            self.years = range(this_year - 10, this_year + 1)

    def render(self, name, value, attrs=None):
        try:
            year_val, month_val = value.year, value.month
        except AttributeError:
            year_val = month_val = None
            if isinstance(value, basestring):
                match = RE_DATE.match(value)
                if match:
                    year_val,
                    month_val,
                    day_val = [int(v) for v in match.groups()]

        output = []

        if 'id' in self.attrs:
            id_ = self.attrs['id']
        else:
            id_ = 'id_%s' % name

        month_choices = MONTHS.items()
        if not (self.required and value):
            month_choices.append(self.none_value)
        month_choices.sort()
        local_attrs = self.build_attrs(id=self.month_field % id_)
        s = Select(choices=month_choices)
        select_html = s.render(self.month_field % name, month_val, local_attrs)

        output.append(select_html)

        year_choices = [(i, i) for i in self.years]
        if not (self.required and value):
            year_choices.insert(0, self.none_value)
        local_attrs['id'] = self.year_field % id_
        s = Select(choices=year_choices)
        select_html = s.render(self.year_field % name, year_val, local_attrs)
        output.append(select_html)

        return mark_safe(u'\n'.join(output))

    def id_for_label(self, id_):
        return '%s_month' % id_

    id_for_label = classmethod(id_for_label)

    def value_from_datadict(self, data, files, name):
        y = data.get(self.year_field % name)
        m = data.get(self.month_field % name)
        if y == m == "0":
            return None
        if y and m:
            return '%s-%s-%s' % (y, m, 1)
        return data.get(name, None)


class Product_TypeForm(forms.ModelForm):
    class Meta:
        model = Product_Type
        fields = ['name']


class Test_TypeForm(forms.ModelForm):
    class Meta:
        model = Test_Type
        fields = ['name']


class Development_EnvironmentForm(forms.ModelForm):
    class Meta:
        model = Development_Environment
        fields = ['name']


class ProductForm(forms.ModelForm):
    name = forms.CharField(max_length=50, required=True)
    description = forms.CharField(widget=forms.Textarea(attrs={}),
                                  required=True)
    prod_type = forms.ModelChoiceField(label='Product Type',
                                       queryset=Product_Type.objects.all(),
                                       required=True)
    prod_manager = forms.CharField(max_length=30, label="Product Manager",
                                   required=False)
    tech_contact = forms.CharField(max_length=30, label="Technical Contact",
                                   required=False)
    manager = forms.CharField(max_length=30, label="Team Manager",
                              required=False)
    authorized_users = forms.ModelMultipleChoiceField(
        queryset=None,
        required=False, label="Authorized Users")

    def __init__(self, *args, **kwargs):
        non_staff = User.objects.exclude(is_staff=True) \
            .exclude(is_active=False)
        super(ProductForm, self).__init__(*args, **kwargs)
        self.fields['authorized_users'].queryset = non_staff

    class Meta:
        model = Product
        fields = ['name', 'description', 'prod_manager', 'tech_contact', 'manager', 'prod_type', 'authorized_users']


class Product_TypeProductForm(forms.ModelForm):
    name = forms.CharField(max_length=50, required=True)
    description = forms.CharField(widget=forms.Textarea(attrs={}),
                                  required=True)
    prod_manager = forms.CharField(max_length=30, label="Product Manager",
                                   required=False)
    tech_contact = forms.CharField(max_length=30, label="Technical Contact",
                                   required=False)
    manager = forms.CharField(max_length=30, label="Team Manager",
                              required=False)
    authorized_users = forms.ModelMultipleChoiceField(
        queryset=None,
        required=False, label="Authorized Users")

    def __init__(self, *args, **kwargs):
        non_staff = User.objects.exclude(is_staff=True)
        super(Product_TypeProductForm, self).__init__(*args, **kwargs)
        self.fields['authorized_users'].queryset = non_staff

    class Meta:
        model = Product
        fields = ['name', 'description', 'prod_manager', 'tech_contact', 'manager', 'prod_type', 'authorized_users']


class UploadFileForm(forms.Form):
    scan_date = forms.DateTimeField(
        required=True,
        label="Nessus Scan Date",
        help_text="Scan completion date will be used on all findings.",
        initial=datetime.now().strftime("%m/%d/%Y"),
        widget=forms.TextInput(attrs={'class': 'datepicker'}))
    file = forms.FileField(widget=forms.widgets.FileInput(
        attrs={"accept": ".txt,.csv"}),
                           label="Select Nessus Export")

    # date can only be today or in the past, not the future
    def clean_scan_date(self):
        date = self.cleaned_data['scan_date']
        if date.date() > datetime.today().date():
            raise forms.ValidationError("The date cannot be in the future!")
        return date


class DoneForm(forms.Form):
    done = forms.BooleanField()


class UploadThreatForm(forms.Form):
    file = forms.FileField(widget=forms.widgets.FileInput(
        attrs={"accept": ".jpg,.png,.pdf"}),
                            label="Select Threat Model")


class UploadRiskForm(forms.ModelForm):
    path = forms.FileField(label="Select File",
                           required=True,
                           widget=forms.widgets.FileInput(
                               attrs={"accept": ".jpg,.png,.pdf"}))
    accepted_findings = forms.ModelMultipleChoiceField(
        queryset=Finding.objects.all(), required=True,
        widget=forms.widgets.CheckboxSelectMultiple(),
        help_text=('Scroll for additional findings or '
                   '<a class="accept-all-findings">Check All</a>'))
    reporter = forms.ModelChoiceField(
        queryset=User.objects.exclude(username="root"))
    notes = forms.CharField(required=False, max_length=2400,
                            widget=forms.Textarea,
                            label='Notes:')

    class Meta:
        model = Risk_Acceptance
        fields = ['accepted_findings', 'path', 'reporter', 'notes']




class ReplaceRiskAcceptanceForm(forms.ModelForm):
    path = forms.FileField(label="Select File",
                           required=True,
                           widget=forms.widgets.FileInput(
                               attrs={"accept": ".jpg,.png,.pdf"}))

    class Meta:
        model = Risk_Acceptance
        exclude = ('reporter', 'accepted_findings', 'notes')


class AddFindingsRiskAcceptanceForm(forms.ModelForm):
    accepted_findings = forms.ModelMultipleChoiceField(
        queryset=Finding.objects.all(), required=True,
        widget=forms.CheckboxSelectMultiple(),
        label="")

    class Meta:
        model = Risk_Acceptance
        exclude = ('reporter', 'path', 'notes')


class ScanSettingsForm(forms.ModelForm):
    addHelpTxt = "Enter IP addresses in x.x.x.x format separated by commas"
    proHelpTxt = "UDP scans require root privs. See docs for more information"
    msg = 'Addresses must be x.x.x.x format, separated by commas'
    addresses = forms.CharField(
        max_length=2000,
        widget=forms.Textarea,
        help_text=addHelpTxt,
        validators=[
            validators.RegexValidator(
                regex='^\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+,*\s*)+\s*$',
                message=msg,
                code='invalid_address')])
    options = (('Weekly', 'Weekly'), ('Monthly', 'Monthly'),
               ('Quarterly', 'Quarterly'))
    frequency = forms.ChoiceField(choices=options)
    prots = [('TCP', 'TCP'), ('UDP', 'UDP')]
    protocol = forms.ChoiceField(
        choices=prots,
        help_text=proHelpTxt)

    class Meta:
        model = ScanSettings
        fields = ['addresses', 'frequency', 'email', 'protocol']


class DeleteIPScanForm(forms.ModelForm):
    id = forms.IntegerField(required=True,
                            widget=forms.widgets.HiddenInput())

    class Meta:
        model = Scan
        exclude = ('scan_settings',
                   'date',
                   'protocol',
                   'status',
                   'baseline')


class VaForm(forms.ModelForm):
    addresses = forms.CharField(max_length=2000, widget=forms.Textarea)
    options = (('Immediately', 'Immediately'),
               ('6AM', '6AM'),
               ('10PM', '10PM'))
    start = forms.ChoiceField(choices=options)

    class Meta:
        model = VA
        fields = ['start', 'addresses']


class CheckForm(forms.ModelForm):
    options = (('Pass', 'Pass'), ('Fail', 'Fail'), ('N/A', 'N/A'))
    session_management = forms.ChoiceField(choices=options)
    encryption_crypto = forms.ChoiceField(choices=options)
    configuration_management = forms.ChoiceField(choices=options)
    authentication = forms.ChoiceField(choices=options)
    authorization_and_access_control = forms.ChoiceField(choices=options)
    data_input_sanitization_validation = forms.ChoiceField(choices=options)
    sensitive_data = forms.ChoiceField(choices=options)
    other = forms.ChoiceField(choices=options)

    def __init__(self, *args, **kwargs):
        findings = kwargs.pop('findings')
        super(CheckForm, self).__init__(*args, **kwargs)
        self.fields['session_issues'].queryset = findings
        self.fields['crypto_issues'].queryset = findings
        self.fields['config_issues'].queryset = findings
        self.fields['auth_issues'].queryset = findings
        self.fields['author_issues'].queryset = findings
        self.fields['data_issues'].queryset = findings
        self.fields['sensitive_issues'].queryset = findings
        self.fields['other_issues'].queryset = findings

    class Meta:
        model = Check_List
        fields = ['session_management', 'session_issues', 'encryption_crypto', 'crypto_issues',
                  'configuration_management', 'config_issues', 'authentication', 'auth_issues',
                  'authorization_and_access_control', 'author_issues',
                  'data_input_sanitization_validation', 'data_issues',
                  'sensitive_data', 'sensitive_issues', 'other', 'other_issues', ]


class EngForm(forms.ModelForm):
    name = forms.CharField(
        max_length=300, required=False,
        help_text="Add a descriptive name to identify this engagement. " +
                  "Without a name the target start date will be used in " +
                  "listings.")
    target_start = forms.DateField(widget=forms.TextInput(
        attrs={'class': 'datepicker'}))
    target_end = forms.DateField(widget=forms.TextInput(
        attrs={'class': 'datepicker'}))
    threat_model = forms.BooleanField(required=False)
    api_test = forms.BooleanField(required=False, label='API Test')
    pen_test = forms.BooleanField(required=False)
    lead = forms.ModelChoiceField(
        queryset=User.objects.exclude(is_staff=False),
        required=True, label="Testing Lead")
    test_strategy = forms.URLField(required=True, label="Test Strategy URL")

    class Meta:
        model = Engagement
        exclude = ('first_contacted', 'version', 'eng_type', 'real_start',
                   'real_end', 'requester', 'reason', 'updated', 'report_type',
                   'product')


class EngForm2(forms.ModelForm):
    name = forms.CharField(max_length=300,
                           required=False,
                           help_text="Add a descriptive name to identify " +
                                     "this engagement. Without a name the target " +
                                     "start date will be used in listings.")
    product = forms.ModelChoiceField(queryset=Product.objects.all())
    target_start = forms.DateField(widget=forms.TextInput(
        attrs={'class': 'datepicker'}))
    target_end = forms.DateField(widget=forms.TextInput(
        attrs={'class': 'datepicker'}))
    test_options = (('API', 'API Test'), ('Static', 'Static Check'),
                    ('Pen', 'Pen Test'), ('Web App', 'Web Application Test'))
    lead = forms.ModelChoiceField(
        queryset=User.objects.exclude(is_staff=False),
        required=True, label="Testing Lead")
    test_strategy = forms.URLField(required=True, label="Test Strategy URL")

    class Meta:
        model = Engagement
        exclude = ('first_contacted', 'version', 'eng_type', 'real_start',
                   'real_end', 'requester', 'reason', 'updated', 'report_type')


class TestForm(forms.ModelForm):
    test_type = forms.ModelChoiceField(queryset=Test_Type.objects.all())
    environment = forms.ModelChoiceField(
        queryset=Development_Environment.objects.all())
    target_start = forms.DateTimeField(widget=forms.TextInput(
        attrs={'class': 'datepicker'}))
    target_end = forms.DateTimeField(widget=forms.TextInput(
        attrs={'class': 'datepicker'}))

    class Meta:
        model = Test
        fields = ['test_type', 'target_start', 'target_end', 'environment', 'percent_complete']


class DeleteTestForm(forms.ModelForm):
    id = forms.IntegerField(required=True,
                            widget=forms.widgets.HiddenInput())

    class Meta:
        model = Test
        exclude = ('test_type',
                   'environment',
                   'target_start',
                   'target_end',
                   'engagement')


class FindingForm(forms.ModelForm):
    title = forms.CharField(max_length=1000)
    date = forms.DateField(required=True,
                           widget=forms.TextInput(attrs={'class':
                                                             'datepicker'}))
    cwe = forms.IntegerField(required=False)
    severity_options = (('Low', 'Low'), ('Medium', 'Medium'),
                        ('High', 'High'), ('Critical', 'Critical'))
    description = forms.CharField(widget=forms.Textarea)
    severity = forms.ChoiceField(
        choices=severity_options,
        error_messages={
            'required': 'Select valid choice: In Progress, On Hold, Completed',
            'invalid_choice': 'Select valid choice: Critical,High,Medium,Low'})
    mitigation = forms.CharField(widget=forms.Textarea)
    impact = forms.CharField(widget=forms.Textarea)
    endpoint = forms.CharField(widget=forms.Textarea,
                               label='Systems / Endpoints')
    references = forms.CharField(widget=forms.Textarea, required=False)

    def clean(self):
        cleaned_data = super(FindingForm, self).clean()
        if ((cleaned_data['active'] or cleaned_data['verified'])
            and cleaned_data['duplicate']):
            raise forms.ValidationError('Duplicate findings cannot be'
                                        ' verified or active')
        if cleaned_data['false_p'] and cleaned_data['verified']:
            raise forms.ValidationError('False positive findings cannot '
                                        'be verified.')
        return cleaned_data

    class Meta:
        model = Finding
        order = ('title', 'severity', 'endpoint', 'description', 'impact')
        exclude = ('reporter', 'url', 'numerical_severity')


class NoteForm(forms.ModelForm):
    entry = forms.CharField(max_length=2400, widget=forms.Textarea,
                            label='Notes:')

    class Meta:
        model = Notes
        fields = ['entry']


class CloseFindingForm(forms.ModelForm):
    entry = forms.CharField(
        required=True, max_length=2400,
        widget=forms.Textarea, label='Notes:',
        error_messages={'required': ('The reason for closing a finding is '
                                     'required, please use the text area '
                                     'below to provide documentation.')})

    class Meta:
        model = Notes
        fields = ['entry']


class WeeklyMetricsForm(forms.Form):
    dates = forms.ChoiceField()

    def __init__(self, *args, **kwargs):
        super(WeeklyMetricsForm, self).__init__(*args, **kwargs)
        wmf_options = []

        for i in range(6):
            # Weeks start on Monday
            curr = datetime.now() - relativedelta(weeks=i)
            start_of_period = curr - relativedelta(weeks=1, weekday=0,
                                                   hour=0, minute=0, second=0)
            end_of_period = curr + relativedelta(weeks=0, weekday=0,
                                                 hour=0, minute=0, second=0)

            wmf_options.append((end_of_period.strftime("%b %d %Y %H %M %S %Z"),
                                start_of_period.strftime("%b %d") +
                                " - " + end_of_period.strftime("%b %d")))

        wmf_options = tuple(wmf_options)

        self.fields['dates'].choices = wmf_options


class SimpleMetricsForm(forms.Form):
    date = forms.DateField(
        label="",
        widget=MonthYearWidget())


class SimpleSearchForm(forms.Form):
    query = forms.CharField()


class DateRangeMetrics(forms.Form):
    start_date = forms.DateField(required=True, label="To",
                                 widget=forms.TextInput(attrs={'class':
                                                                   'datepicker'}))
    end_date = forms.DateField(required=True,
                               label="From",
                               widget=forms.TextInput(attrs={'class':
                                                                 'datepicker'}))


class MetricsFilterForm(forms.Form):
    start_date = forms.DateField(required=False,
                                 label="To",
                                 widget=forms.TextInput(attrs={'class':
                                                                   'datepicker'}))
    end_date = forms.DateField(required=False,
                               label="From",
                               widget=forms.TextInput(attrs={'class':
                                                                 'datepicker'}))
    finding_status = forms.MultipleChoiceField(
        required=False,
        widget=forms.CheckboxSelectMultiple,
        choices=FINDING_STATUS,
        label="Status")
    severity = forms.MultipleChoiceField(required=False,
                                         choices=(('Low', 'Low'),
                                                  ('Medium', 'Medium'),
                                                  ('High', 'High'),
                                                  ('Critical', 'Critical')),
                                         help_text=('Hold down "Control", or '
                                                    '"Command" on a Mac, to '
                                                    'select more than one.'))
    exclude_product_types = forms.ModelMultipleChoiceField(
        required=False, queryset=Product_Type.objects.all().order_by('name'))

    # add the ability to exclude the exclude_product_types field
    def __init__(self, *args, **kwargs):
        exclude_product_types = kwargs.get('exclude_product_types', False)
        if 'exclude_product_types' in kwargs:
            del kwargs['exclude_product_types']
        super(MetricsFilterForm, self).__init__(*args, **kwargs)
        if exclude_product_types:
            del self.fields['exclude_product_types']


class DojoUserForm(forms.ModelForm):
    class Meta:
        model = Dojo_User
        exclude = ['password', 'last_login', 'is_superuser', 'groups',
                   'username', 'is_staff', 'is_active', 'date_joined',
                   'user_permissions']
