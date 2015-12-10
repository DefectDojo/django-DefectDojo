import re
from datetime import datetime, date
from urlparse import urlsplit, urlunsplit
from dateutil.relativedelta import relativedelta
from django import forms
from django.core import validators
from django.core.validators import RegexValidator
from django.forms.widgets import Widget, Select
from django.utils.dates import MONTHS
from django.utils.safestring import mark_safe
from pytz import timezone
from dojo import settings
from dojo.models import Finding, Product_Type, Product, ScanSettings, VA, \
    Check_List, User, Engagement, Test, Test_Type, Notes, Risk_Acceptance, \
    Development_Environment, Dojo_User, Scan, Endpoint, Stub_Finding, Finding_Template, Report

RE_DATE = re.compile(r'(\d{4})-(\d\d?)-(\d\d?)$')
localtz = timezone(settings.TIME_ZONE)

FINDING_STATUS = (('verified', 'Verified'),
                  ('false_p', 'False Positive'),
                  ('duplicate', 'Duplicate'),
                  ('out_of_scope', 'Out of Scope'))

SEVERITY_CHOICES = (('Info', 'Info'), ('Low', 'Low'), ('Medium', 'Medium'),
                    ('High', 'High'), ('Critical', 'Critical'))


class SelectWithPop(forms.Select):
    def render(self, name, *args, **kwargs):
        html = super(SelectWithPop, self).render(name, *args, **kwargs)
        popup_plus = '<div class="input-group dojo-input-group">' + html + '<span class="input-group-btn"><a href="/' + name + '/add" class="btn btn-primary" class="add-another" id="add_id_' + name + '" onclick="return showAddAnotherPopup(this);"><span class="glyphicon glyphicon-plus"></span></a></span></div>'

        return mark_safe(popup_plus)


class MultipleSelectWithPop(forms.SelectMultiple):
    def render(self, name, *args, **kwargs):
        html = super(MultipleSelectWithPop, self).render(name, *args, **kwargs)
        popup_plus = '<div class="input-group dojo-input-group">' + html + '<span class="input-group-btn"><a href="/' + name + '/add" class="btn btn-primary" class="add-another" id="add_id_' + name + '" onclick="return showAddAnotherPopup(this);"><span class="glyphicon glyphicon-plus"></span></a></span></div>'

        return mark_safe(popup_plus)


class MultipleSelectWithPopPlusMinus(forms.SelectMultiple):
    def render(self, name, *args, **kwargs):
        html = super(MultipleSelectWithPopPlusMinus, self).render(name, *args, **kwargs)
        popup_plus = '<div class="input-group dojo-input-group">' + html + '<span class="input-group-btn"><a href="/' + name + '/add" class="btn btn-primary" class="add-another" id="add_id_' + name + '" onclick="return showAddAnotherPopup(this);"><span class="icon-plusminus"></span></a></span></div>'

        return mark_safe(popup_plus)


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


class DeleteProductForm(forms.ModelForm):
    id = forms.IntegerField(required=True,
                            widget=forms.widgets.HiddenInput())

    class Meta:
        model = Product
        exclude = ['name', 'description', 'prod_manager', 'tech_contact', 'manager', 'created',
                   'prod_type', 'updated', 'tid', 'authorized_users']


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


class ImportScanForm(forms.Form):
    SCAN_TYPE_CHOICES = (("Burp Scan", "Burp Scan"), ("Nessus Scan", "Nessus Scan"), ("Nexpose Scan", "Nexpose Scan"),
                         ("Veracode Scan", "Veracode Scan"), ("ZAP Scan", "ZAP Scan"))
    scan_date = forms.DateTimeField(
        required=True,
        label="Scan Completion Date",
        help_text="Scan completion date will be used on all findings.",
        initial=datetime.now().strftime("%m/%d/%Y"),
        widget=forms.TextInput(attrs={'class': 'datepicker'}))
    minimum_severity = forms.ChoiceField(help_text='Minimum severity level to be imported',
                                         required=True,
                                         choices=SEVERITY_CHOICES[0:4])
    scan_type = forms.ChoiceField(required=True, choices=SCAN_TYPE_CHOICES)
    file = forms.FileField(widget=forms.widgets.FileInput(
        attrs={"accept": ".xml, .csv, .nessus"}),
        label="Choose report file",
        required=True)

    # date can only be today or in the past, not the future
    def clean_scan_date(self):
        date = self.cleaned_data['scan_date']
        if date.date() > datetime.today().date():
            raise forms.ValidationError("The date cannot be in the future!")
        return date


class ReImportScanForm(forms.Form):
    scan_date = forms.DateTimeField(
        required=True,
        label="Scan Completion Date",
        help_text="Scan completion date will be used on all findings.",
        initial=datetime.now().strftime("%m/%d/%Y"),
        widget=forms.TextInput(attrs={'class': 'datepicker'}))
    minimum_severity = forms.ChoiceField(help_text='Minimum severity level to be imported',
                                         required=True,
                                         choices=SEVERITY_CHOICES[0:4])
    file = forms.FileField(widget=forms.widgets.FileInput(
        attrs={"accept": ".xml, .csv, .nessus"}),
        label="Choose report file",
        required=True)

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


class DeleteEngagementForm(forms.ModelForm):
    id = forms.IntegerField(required=True,
                            widget=forms.widgets.HiddenInput())

    class Meta:
        model = Engagement
        exclude = ['name', 'version', 'eng_type', 'first_contacted', 'target_start',
                   'target_end', 'lead', 'requester', 'reason', 'report_type',
                   'product', 'test_strategy', 'threat_model', 'api_test', 'pen_test',
                   'check_list', 'status']


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
                   'engagement',
                   'percent_complete')


class AddFindingForm(forms.ModelForm):
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
    endpoints = forms.ModelMultipleChoiceField(Endpoint.objects, required=False, label='Systems / Endpoints',
                                               widget=MultipleSelectWithPopPlusMinus(attrs={'size': '11'}))
    references = forms.CharField(widget=forms.Textarea, required=False)
    is_template = forms.BooleanField(label="Create Template?", required=False,
                                     help_text="A new finding template will be created from this finding.")

    def clean(self):
        # self.fields['endpoints'].queryset = Endpoint.objects.all()
        cleaned_data = super(AddFindingForm, self).clean()
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
        order = ('title', 'severity', 'endpoints', 'description', 'impact')
        exclude = ('reporter', 'url', 'numerical_severity', 'endpoint')


class PromoteFindingForm(forms.ModelForm):
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
    endpoints = forms.ModelMultipleChoiceField(Endpoint.objects, required=False, label='Systems / Endpoints',
                                               widget=MultipleSelectWithPopPlusMinus(attrs={'size': '11'}))
    references = forms.CharField(widget=forms.Textarea, required=False)

    class Meta:
        model = Finding
        order = ('title', 'severity', 'endpoints', 'description', 'impact')
        exclude = ('reporter', 'url', 'numerical_severity', 'endpoint', 'active', 'false_p', 'verified', 'is_template',
                   'duplicate', 'out_of_scope')


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
    endpoints = forms.ModelMultipleChoiceField(Endpoint.objects, required=False, label='Systems / Endpoints',
                                               widget=MultipleSelectWithPopPlusMinus(attrs={'size': '11'}))
    references = forms.CharField(widget=forms.Textarea, required=False)
    is_template = forms.BooleanField(label="Create Template?", required=False,
                                     help_text="A new finding template will be created from this finding.")


    def clean(self):
        cleaned_data = super(FindingForm, self).clean()
        if (cleaned_data['active'] or cleaned_data['verified']) and cleaned_data['duplicate']:
            raise forms.ValidationError('Duplicate findings cannot be'
                                        ' verified or active')
        if cleaned_data['false_p'] and cleaned_data['verified']:
            raise forms.ValidationError('False positive findings cannot '
                                        'be verified.')
        return cleaned_data

    class Meta:
        model = Finding
        order = ('title', 'severity', 'endpoints', 'description', 'impact')
        exclude = ('reporter', 'url', 'numerical_severity', 'endpoint')


class StubFindingForm(forms.ModelForm):
    title = forms.CharField(required=True, max_length=1000)

    class Meta:
        model = Stub_Finding
        order = ('title',)
        exclude = (
            'date', 'description', 'severity', 'reporter', 'test')

    def clean(self):
        cleaned_data = super(StubFindingForm, self).clean()
        if 'title' in cleaned_data:
            if len(cleaned_data['title']) <= 0:
                raise forms.ValidationError("The title is required.")
        else:
            raise forms.ValidationError("The title is required.")

        return cleaned_data


class FindingTemplateForm(forms.ModelForm):
    title = forms.CharField(max_length=1000, required=True)
    cwe = forms.IntegerField(label="CWE", required=False)
    severity_options = (('Low', 'Low'), ('Medium', 'Medium'),
                        ('High', 'High'), ('Critical', 'Critical'))
    severity = forms.ChoiceField(
        required=False,
        choices=severity_options,
        error_messages={
            'required': 'Select valid choice: In Progress, On Hold, Completed',
            'invalid_choice': 'Select valid choice: Critical,High,Medium,Low'})

    class Meta:
        model = Finding_Template
        order = ('title', 'cwe', 'severity', 'description', 'impact')
        exclude = ('numerical_severity',)


class DeleteFindingTemplateForm(forms.ModelForm):
    id = forms.IntegerField(required=True,
                            widget=forms.widgets.HiddenInput())

    class Meta:
        model = Finding_Template
        fields = ('id',)


class EditEndpointForm(forms.ModelForm):
    class Meta:
        model = Endpoint
        exclude = ['product']

    def __init__(self, *args, **kwargs):
        self.product = None
        self.endpoint_instance = None
        super(EditEndpointForm, self).__init__(*args, **kwargs)
        if 'instance' in kwargs:
            self.endpoint_instance = kwargs.pop('instance')
            self.product = self.endpoint_instance.product

    def clean(self):
        from django.core.validators import URLValidator, validate_ipv46_address

        port_re = "(:[0-9]{1,5}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])"
        cleaned_data = super(EditEndpointForm, self).clean()

        if 'host' in cleaned_data:
            host = cleaned_data['host']
        else:
            raise forms.ValidationError('Please enter a valid URL or IP address.',
                                        code='invalid')

        protocol = cleaned_data['protocol']
        path = cleaned_data['path']
        query = cleaned_data['query']
        fragment = cleaned_data['fragment']

        if protocol:
            endpoint = urlunsplit((protocol, host, path, query, fragment))
        else:
            endpoint = host

        try:
            url_validator = URLValidator()
            url_validator(endpoint)
        except forms.ValidationError:
            try:
                # do we have a port number?
                regex = re.compile(port_re)
                host = endpoint
                if regex.findall(endpoint):
                    for g in regex.findall(endpoint):
                        host = re.sub(port_re, '', host)
                validate_ipv46_address(host)
            except forms.ValidationError:
                try:
                    validate_hostname = RegexValidator(regex=r'[a-zA-Z0-9-_]*\.[a-zA-Z]{2,6}')
                    # do we have a port number?
                    regex = re.compile(port_re)
                    host = endpoint
                    if regex.findall(endpoint):
                        for g in regex.findall(endpoint):
                            host = re.sub(port_re, '', host)
                    validate_hostname(host)
                except:
                    raise forms.ValidationError(
                        'It does not appear as though this endpoint is a valid URL or IP address.',
                        code='invalid')

        endpoint = Endpoint.objects.filter(protocol=protocol,
                                           host=host,
                                           path=path,
                                           query=query,
                                           fragment=fragment,
                                           product=self.product)
        if endpoint.count() > 0:
            raise forms.ValidationError(
                'It appears as though an endpoint with this data already exists for this product.',
                code='invalid')

        return cleaned_data


class AddEndpointForm(forms.Form):
    endpoint = forms.CharField(max_length=5000, required=True, label="Endpoint(s)",
                               help_text="The IP address, host name or full URL. You may enter one endpoint per line. "
                                         "Each must be valid.",
                               widget=forms.widgets.Textarea(attrs={'rows': '15', 'cols': '400'}))
    product = forms.CharField(required=True,
                              widget=forms.widgets.HiddenInput(), help_text="The product this endpoint should be "
                                                                            "associated with.")

    def __init__(self, *args, **kwargs):
        product = None
        if 'product' in kwargs:
            product = kwargs.pop('product')
        super(AddEndpointForm, self).__init__(*args, **kwargs)
        if product is None:
            self.fields['product'] = forms.ModelChoiceField(queryset=Product.objects.all())
        else:
            self.fields['product'].initial = product.id

        self.product = product
        self.endpoints_to_process = []

    def save(self):
        processed_endpoints = []
        for e in self.endpoints_to_process:
            endpoint, created = Endpoint.objects.get_or_create(protocol=e[0],
                                                               host=e[1],
                                                               path=e[2],
                                                               query=e[3],
                                                               fragment=e[4],
                                                               product=self.product)
            processed_endpoints.append(endpoint)
        return processed_endpoints

    def clean(self):
        from django.core.validators import URLValidator, validate_ipv46_address

        port_re = "(:[0-9]{1,5}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])"
        cleaned_data = super(AddEndpointForm, self).clean()

        if 'endpoint' in cleaned_data and 'product' in cleaned_data:
            endpoint = cleaned_data['endpoint']
            product = cleaned_data['product']
            if isinstance(product, Product):
                self.product = product
            else:
                self.product = Product.objects.get(id=int(product))
        else:
            raise forms.ValidationError('Please enter a valid URL or IP address.',
                                        code='invalid')

        endpoints = endpoint.split()
        count = 0
        error = False
        for endpoint in endpoints:
            try:
                url_validator = URLValidator()
                url_validator(endpoint)
                protocol, host, path, query, fragment = urlsplit(endpoint)
                self.endpoints_to_process.append([protocol, host, path, query, fragment])
            except forms.ValidationError:
                try:
                    # do we have a port number?
                    host = endpoint
                    regex = re.compile(port_re)
                    if regex.findall(endpoint):
                        for g in regex.findall(endpoint):
                            host = re.sub(port_re, '', host)
                    validate_ipv46_address(host)
                    protocol, host, path, query, fragment = ("", endpoint, "", "", "")
                    self.endpoints_to_process.append([protocol, host, path, query, fragment])
                except forms.ValidationError:
                    try:
                        regex = re.compile(
                            r'^(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}(?<!-)\.?)|'  # domain...
                            r'localhost|'  # localhost...
                            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # ...or ipv4
                            r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ...or ipv6
                            r'(?::\d+)?'  # optional port
                            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
                        validate_hostname = RegexValidator(regex=regex)
                        validate_hostname(host)
                        protocol, host, path, query, fragment = (None, host, None, None, None)
                        if "/" in host or "?" in host or "#" in host:
                            # add a fake protocol just to join, wont use in update to database
                            host_with_protocol = "http://" + host
                            p, host, path, query, fragment = urlsplit(host_with_protocol)
                        self.endpoints_to_process.append([protocol, host, path, query, fragment])
                    except forms.ValidationError:
                        raise forms.ValidationError(
                            'Please check items entered, one or more do not appear to be a valid URL or IP address.',
                            code='invalid')

        return cleaned_data


class DeleteEndpointForm(forms.ModelForm):
    id = forms.IntegerField(required=True,
                            widget=forms.widgets.HiddenInput())

    class Meta:
        model = Endpoint
        exclude = ('protocol',
                   'host',
                   'path',
                   'query',
                   'fragment',
                   'product')


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


class AddDojoUserForm(forms.ModelForm):
    authorized_products = forms.ModelMultipleChoiceField(
        queryset=Product.objects.all(), required=False,
        help_text='Select the products this user should have access to.')

    class Meta:
        model = Dojo_User
        fields = ['username', 'first_name', 'last_name', 'email', 'is_active',
                  'is_staff', 'is_superuser']
        exclude = ['password', 'last_login', 'groups',
                   'date_joined', 'user_permissions']


class DeleteUserForm(forms.ModelForm):
    id = forms.IntegerField(required=True,
                            widget=forms.widgets.HiddenInput())

    class Meta:
        model = User
        exclude = ['username', 'first_name', 'last_name', 'email', 'is_active',
                   'is_staff', 'is_superuser', 'password', 'last_login', 'groups',
                   'date_joined', 'user_permissions']


def get_years():
    now = datetime.now(tz=localtz)
    return [(now.year, now.year), (now.year - 1, now.year - 1), (now.year - 2, now.year - 2)]


class ProductTypeCountsForm(forms.Form):
    month = forms.ChoiceField(choices=MONTHS.items(), required=True, error_messages={
        'required': '*'})
    year = forms.ChoiceField(choices=get_years, required=True, error_messages={
        'required': '*'})
    product_type = forms.ModelChoiceField(required=True,
                                          queryset=Product_Type.objects.all(),
                                          error_messages={
                                              'required': '*'})


class APIKeyForm(forms.ModelForm):
    id = forms.IntegerField(required=True,
                            widget=forms.widgets.HiddenInput())

    class Meta:
        model = User
        exclude = ['username', 'first_name', 'last_name', 'email', 'is_active',
                   'is_staff', 'is_superuser', 'password', 'last_login', 'groups',
                   'date_joined', 'user_permissions']


class ReportOptionsForm(forms.Form):
    yes_no = (('0', 'No'), ('1', 'Yes'))
    include_finding_notes = forms.ChoiceField(choices=yes_no, label="Finding Notes")
    include_executive_summary = forms.ChoiceField(choices=yes_no, label="Executive Summary")
    include_table_of_contents = forms.ChoiceField(choices=yes_no, label="Table of Contents")
    report_type = forms.ChoiceField(choices=(('AsciiDoc', 'AsciiDoc'), ('PDF', 'PDF')))


class DeleteReportForm(forms.ModelForm):
    id = forms.IntegerField(required=True,
                            widget=forms.widgets.HiddenInput())

    class Meta:
        model = Report
        fields = ('id',)

