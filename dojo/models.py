import base64
import hashlib
import logging
import os
import re
from datetime import datetime
from uuid import uuid4
from django.conf import settings
from watson import search as watson
from auditlog.registry import auditlog
from django.contrib import admin
from django.contrib.auth import get_user_model
from django.core.urlresolvers import reverse
from django.core.validators import RegexValidator
from django.db import models
from django.db.models import Q
from django.utils.timezone import now
from imagekit.models import ImageSpecField
from imagekit.processors import ResizeToCover
from django.utils import timezone
from pytz import all_timezones
from tagging.registry import register as tag_register
from multiselectfield import MultiSelectField
from django import forms
from django.utils.translation import gettext as _

fmt = getattr(settings, 'LOG_FORMAT', None)
lvl = getattr(settings, 'LOG_LEVEL', logging.DEBUG)

logging.basicConfig(format=fmt, level=lvl)


class Regulation(models.Model):
    PRIVACY_CATEGORY = 'privacy'
    FINANCE_CATEGORY = 'finance'
    EDUCATION_CATEGORY = 'education'
    MEDICAL_CATEGORY = 'medical'
    OTHER_CATEGORY = 'other'
    CATEGORY_CHOICES = (
        (PRIVACY_CATEGORY, _('Privacy')),
        (FINANCE_CATEGORY, _('Finance')),
        (EDUCATION_CATEGORY, _('Education')),
        (MEDICAL_CATEGORY, _('Medical')),
        (OTHER_CATEGORY, _('Other')),
    )

    name = models.CharField(max_length=128, help_text=_('The name of the legislation.'))
    acronym = models.CharField(max_length=20, unique=True, help_text=_('A shortened representation of the name.'))
    category = models.CharField(max_length=9, choices=CATEGORY_CHOICES, help_text=_('The subject of the regulation.'))
    jurisdiction = models.CharField(max_length=64, help_text=_('The territory over which the regulation applies.'))
    description = models.TextField(blank=True, help_text=_('Information about the regulation\'s purpose.'))
    reference = models.URLField(blank=True, help_text=_('An external URL for more information.'))

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.acronym + ' (' + self.jurisdiction + ')'


class System_Settings(models.Model):
    enable_deduplication = models.BooleanField(
        default=False,
        blank=False,
        verbose_name='Deduplicate findings',
        help_text="With this setting turned on, Dojo deduplicates findings by "
                  "comparing endpoints, cwe fields, and titles. "
                  "If two findings share a URL and have the same CWE or "
                  "title, Dojo marks the less recent finding as a duplicate. "
                  "When deduplication is enabled, a list of "
                  "deduplicated findings is added to the engagement view.")
    delete_dupulicates = models.BooleanField(default=False, blank=False)
    max_dupes = models.IntegerField(blank=True, null=True,
                                    verbose_name='Max Duplicates',
                                    help_text="When enabled, if a single "
                                              "issue reaches the maximum "
                                              "number of duplicates, the "
                                              "oldest will be deleted.")
    enable_jira = models.BooleanField(default=False,
                                      verbose_name='Enable JIRA integration',
                                      blank=False)
    jira_choices = (('Critical', 'Critical'),
                    ('High', 'High'),
                    ('Medium', 'Medium'),
                    ('Low', 'Low'))
    jira_minimum_severity = models.CharField(max_length=20, blank=True,
                                             null=True, choices=jira_choices,
                                             default='None')
    jira_labels = models.CharField(max_length=200, blank=True, null=True,
                                   help_text='JIRA issue labels space seperated')
    enable_slack_notifications = \
        models.BooleanField(default=False,
                            verbose_name='Enable Slack notifications',
                            blank=False)
    slack_channel = models.CharField(max_length=100, default='', blank=True)
    slack_token = models.CharField(max_length=100, default='', blank=True,
                                   help_text='Token required for interacting '
                                             'with Slack. Get one at '
                                             'https://api.slack.com/tokens')
    slack_username = models.CharField(max_length=100, default='', blank=True)
    enable_hipchat_notifications = \
        models.BooleanField(default=False,
                            verbose_name='Enable HipChat notifications',
                            blank=False)
    hipchat_site = models.CharField(max_length=100, default='', blank=True,
                                    help_text='The full fqdn of your '
                                              'hipchat site, e.g. '
                                              '"yoursite.hipchat.com"')
    hipchat_channel = models.CharField(max_length=100, default='', blank=True)
    hipchat_token = \
        models.CharField(max_length=100, default='', blank=True,
                         help_text='Token required for interacting with '
                                   'HipChat. Get one at '
                                   'https://patriktest.hipchat.com/addons/')
    enable_mail_notifications = models.BooleanField(default=False, blank=False)
    mail_notifications_from = models.CharField(max_length=200,
                                               default='from@example.com',
                                               blank=True)
    mail_notifications_to = models.CharField(max_length=200, default='',
                                             blank=True)
    s_finding_severity_naming = \
        models.BooleanField(default=False, blank=False,
                            help_text='With this setting turned on, Dojo '
                                      'will display S0, S1, S2, etc in most '
                                      'places, whereas if turned off '
                                      'Critical, High, Medium, etc will '
                                      'be displayed.')
    false_positive_history = models.BooleanField(default=False)

    url_prefix = models.CharField(max_length=300, default='', blank=True, help_text="URL prefix if DefectDojo is installed in it's own virtual subdirectory.")
    team_name = models.CharField(max_length=100, default='', blank=True)
    time_zone = models.CharField(max_length=50,
                                 choices=[(tz, tz) for tz in all_timezones],
                                 default='UTC', blank=False)
    display_endpoint_uri = models.BooleanField(default=False, verbose_name="Display Endpoint Full URI", help_text="Displays the full endpoint URI in the endpoint view.")
    enable_product_grade = models.BooleanField(default=False, verbose_name="Enable Product Grading", help_text="Displays a grade letter next to a product to show the overall health.")
    product_grade = models.CharField(max_length=800, blank=True)
    product_grade_a = models.IntegerField(default=90,
                                          verbose_name="Grade A",
                                          help_text="Percentage score for an "
                                                    "'A' >=")
    product_grade_b = models.IntegerField(default=80,
                                          verbose_name="Grade B",
                                          help_text="Percentage score for a "
                                                    "'B' >=")
    product_grade_c = models.IntegerField(default=70,
                                          verbose_name="Grade C",
                                          help_text="Percentage score for a "
                                                    "'C' >=")
    product_grade_d = models.IntegerField(default=60,
                                          verbose_name="Grade D",
                                          help_text="Percentage score for a "
                                                    "'D' >=")
    product_grade_f = models.IntegerField(default=59,
                                          verbose_name="Grade F",
                                          help_text="Percentage score for an "
                                                    "'F' <=")
    enable_benchmark = models.BooleanField(
        default=True,
        blank=False,
        verbose_name="Enable Benchmarks",
        help_text="Enables Benchmarks such as the OWASP ASVS "
                  "(Application Security Verification Standard)")


class SystemSettingsFormAdmin(forms.ModelForm):
    product_grade = forms.CharField(widget=forms.Textarea)

    class Meta:
        model = System_Settings
        fields = ['product_grade']


class System_SettingsAdmin(admin.ModelAdmin):
    form = SystemSettingsFormAdmin
    fields = ('product_grade',)


def get_current_date():
    return timezone.now().date()


def get_current_datetime():
    return timezone.now()


User = get_user_model()


# proxy class for convenience and UI
class Dojo_User(User):
    class Meta:
        proxy = True

    def get_full_name(self):
        """
        Returns the first_name plus the last_name, with a space in between.
        """
        full_name = '%s %s (%s)' % (self.first_name,
                                    self.last_name,
                                    self.username)
        return full_name.strip()

    def __unicode__(self):
        return self.get_full_name()


class UserContactInfo(models.Model):
    user = models.OneToOneField(User)
    title = models.CharField(blank=True, null=True, max_length=150)
    phone_regex = RegexValidator(regex=r'^\+?1?\d{9,15}$',
                                 message="Phone number must be entered in the format: '+999999999'. "
                                         "Up to 15 digits allowed.")
    phone_number = models.CharField(validators=[phone_regex], blank=True,
                                    max_length=15,
                                    help_text="Phone number must be entered in the format: '+999999999'. "
                                              "Up to 15 digits allowed.")
    cell_number = models.CharField(validators=[phone_regex], blank=True,
                                   max_length=15,
                                   help_text="Phone number must be entered in the format: '+999999999'. "
                                             "Up to 15 digits allowed.")
    twitter_username = models.CharField(blank=True, null=True, max_length=150)
    github_username = models.CharField(blank=True, null=True, max_length=150)
    slack_username = models.CharField(blank=True, null=True, max_length=150, help_text="Email address associated with your slack account", verbose_name="Slack Email Address")
    slack_user_id = models.CharField(blank=True, null=True, max_length=25)
    hipchat_username = models.CharField(blank=True, null=True, max_length=150)
    block_execution = models.BooleanField(default=False, help_text="Instead of async deduping a finding the findings will be deduped synchronously and will 'block' the user until completion.")


class Contact(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    team = models.CharField(max_length=100)
    is_admin = models.BooleanField(default=False)
    is_globally_read_only = models.BooleanField(default=False)
    updated = models.DateTimeField(editable=False)


class Product_Type(models.Model):
    name = models.CharField(max_length=300)
    critical_product = models.BooleanField(default=False)
    key_product = models.BooleanField(default=False)

    def critical_present(self):
        c_findings = Finding.objects.filter(
            test__engagement__product__prod_type=self, severity='Critical')
        if c_findings.count() > 0:
            return True

    def high_present(self):
        c_findings = Finding.objects.filter(
            test__engagement__product__prod_type=self, severity='High')
        if c_findings.count() > 0:
            return True

    def calc_health(self):
        h_findings = Finding.objects.filter(
            test__engagement__product__prod_type=self, severity='High')
        c_findings = Finding.objects.filter(
            test__engagement__product__prod_type=self, severity='Critical')
        health = 100
        if c_findings.count() > 0:
            health = 40
            health = health - ((c_findings.count() - 1) * 5)
        if h_findings.count() > 0:
            if health == 100:
                health = 60
            health = health - ((h_findings.count() - 1) * 2)
        if health < 5:
            return 5
        else:
            return health

    def findings_count(self):
        return Finding.objects.filter(mitigated__isnull=True,
                                      verified=True,
                                      false_p=False,
                                      duplicate=False,
                                      out_of_scope=False,
                                      test__engagement__product__prod_type=self).filter(
            Q(severity="Critical") |
            Q(severity="High") |
            Q(severity="Medium") |
            Q(severity="Low")).count()

    def products_count(self):
        return Product.objects.filter(prod_type=self).count()

    def __unicode__(self):
        return self.name

    def get_breadcrumbs(self):
        bc = [{'title': self.__unicode__(),
               'url': reverse('edit_product_type', args=(self.id,))}]
        return bc


class Product_Line(models.Model):
    name = models.CharField(max_length=300)
    description = models.CharField(max_length=2000)

    def __unicode__(self):
        return self.name


class Report_Type(models.Model):
    name = models.CharField(max_length=255)


class Test_Type(models.Model):
    name = models.CharField(max_length=200)
    static_tool = models.BooleanField(default=False)
    dynamic_tool = models.BooleanField(default=False)

    def __unicode__(self):
        return self.name

    def get_breadcrumbs(self):
        bc = [{'title': self.__unicode__(),
               'url': None}]
        return bc


class Product(models.Model):
    WEB_PLATFORM = 'web'
    IOT = 'iot'
    DESKTOP_PLATFORM = 'desktop'
    MOBILE_PLATFORM = 'mobile'
    WEB_SERVICE_PLATFORM = 'web service'
    PLATFORM_CHOICES = (
        (WEB_SERVICE_PLATFORM, _('API')),
        (DESKTOP_PLATFORM, _('Desktop')),
        (IOT, _('Internet of Things')),
        (MOBILE_PLATFORM, _('Mobile')),
        (WEB_PLATFORM, _('Web')),
    )

    CONSTRUCTION = 'construction'
    PRODUCTION = 'production'
    RETIREMENT = 'retirement'
    LIFECYCLE_CHOICES = (
        (CONSTRUCTION, _('Construction')),
        (PRODUCTION, _('Production')),
        (RETIREMENT, _('Retirement')),
    )

    THIRD_PARTY_LIBRARY_ORIGIN = 'third party library'
    PURCHASED_ORIGIN = 'purchased'
    CONTRACTOR_ORIGIN = 'contractor'
    INTERNALLY_DEVELOPED_ORIGIN = 'internal'
    OPEN_SOURCE_ORIGIN = 'open source'
    OUTSOURCED_ORIGIN = 'outsourced'
    ORIGIN_CHOICES = (
        (THIRD_PARTY_LIBRARY_ORIGIN, _('Third Party Library')),
        (PURCHASED_ORIGIN, _('Purchased')),
        (CONTRACTOR_ORIGIN, _('Contractor Developed')),
        (INTERNALLY_DEVELOPED_ORIGIN, _('Internally Developed')),
        (OPEN_SOURCE_ORIGIN, _('Open Source')),
        (OUTSOURCED_ORIGIN, _('Outsourced')),
    )

    VERY_HIGH_CRITICALITY = 'very high'
    HIGH_CRITICALITY = 'high'
    MEDIUM_CRITICALITY = 'medium'
    LOW_CRITICALITY = 'low'
    VERY_LOW_CRITICALITY = 'very low'
    NONE_CRITICALITY = 'none'
    BUSINESS_CRITICALITY_CHOICES = (
        (VERY_HIGH_CRITICALITY, _('Very High')),
        (HIGH_CRITICALITY, _('High')),
        (MEDIUM_CRITICALITY, _('Medium')),
        (LOW_CRITICALITY, _('Low')),
        (VERY_LOW_CRITICALITY, _('Very Low')),
        (NONE_CRITICALITY, _('None')),
    )

    name = models.CharField(max_length=255)
    description = models.CharField(max_length=4000)

    '''
    The following three fields are deprecated and no longer in use.
    They remain in model for backwards compatibility and will be removed
    in a future release.  prod_manager, tech_contact, manager

    The admin script migrate_product_contacts should be used to migrate data
    from these fields to their replacements.
    ./manage.py migrate_product_contacts
    '''
    prod_manager = models.CharField(default=0, max_length=200)  # unused
    tech_contact = models.CharField(default=0, max_length=200)  # unused
    manager = models.CharField(default=0, max_length=200)  # unused

    product_manager = models.ForeignKey(Dojo_User, null=True, blank=True,
                                        related_name='product_manager')
    technical_contact = models.ForeignKey(Dojo_User, null=True, blank=True,
                                          related_name='technical_contact')
    team_manager = models.ForeignKey(Dojo_User, null=True, blank=True,
                                     related_name='team_manager')

    created = models.DateTimeField(editable=False, null=True, blank=True)
    prod_type = models.ForeignKey(Product_Type, related_name='prod_type',
                                  null=True, blank=True)
    updated = models.DateTimeField(editable=False, null=True, blank=True)
    tid = models.IntegerField(default=0, editable=False)
    authorized_users = models.ManyToManyField(User, blank=True)
    prod_numeric_grade = models.IntegerField(null=True, blank=True)

    # Metadata
    business_criticality = models.CharField(max_length=9, choices=BUSINESS_CRITICALITY_CHOICES, blank=True, null=True)
    platform = models.CharField(max_length=11, choices=PLATFORM_CHOICES, blank=True, null=True)
    lifecycle = models.CharField(max_length=12, choices=LIFECYCLE_CHOICES, blank=True, null=True)
    origin = models.CharField(max_length=19, choices=ORIGIN_CHOICES, blank=True, null=True)
    user_records = models.PositiveIntegerField(blank=True, null=True, help_text=_('Estimate the number of user records within the application.'))
    revenue = models.DecimalField(max_digits=15, decimal_places=2, blank=True, null=True, help_text=_('Estimate the application\'s revenue.'))
    external_audience = models.BooleanField(default=False, help_text=_('Specify if the application is used by people outside the organization.'))
    internet_accessible = models.BooleanField(default=False, help_text=_('Specify if the application is accessible from the public internet.'))
    regulations = models.ManyToManyField(Regulation, blank=True)

    def __unicode__(self):
        return self.name

    class Meta:
        ordering = ('name',)

    @property
    def findings_count(self):
        return Finding.objects.filter(mitigated__isnull=True,
                                      verified=True,
                                      false_p=False,
                                      duplicate=False,
                                      out_of_scope=False,
                                      test__engagement__product=self).count()

    @property
    def active_engagement_count(self):
        return Engagement.objects.filter(active=True, product=self).count()

    @property
    def closed_engagement_count(self):
        return Engagement.objects.filter(active=False, product=self).count()

    @property
    def last_engagement_date(self):
        return Engagement.objects.filter(product=self).first()

    @property
    def endpoint_count(self):
        endpoints = Endpoint.objects.filter(
            finding__test__engagement__product=self,
            finding__active=True,
            finding__verified=True,
            finding__mitigated__isnull=True)

        hosts = []
        ids = []
        for e in endpoints:
            if ":" in e.host:
                host_no_port = e.host[:e.host.index(':')]
            else:
                host_no_port = e.host

            if host_no_port in hosts:
                continue
            else:
                hosts.append(host_no_port)
                ids.append(e.id)

        return len(hosts)

    def open_findings(self, start_date=None, end_date=None):
        if start_date is None or end_date is None:
            return {}
        else:
            critical = Finding.objects.filter(test__engagement__product=self,
                                              mitigated__isnull=True,
                                              verified=True,
                                              false_p=False,
                                              duplicate=False,
                                              out_of_scope=False,
                                              severity="Critical",
                                              date__range=[start_date,
                                                           end_date]).count()
            high = Finding.objects.filter(test__engagement__product=self,
                                          mitigated__isnull=True,
                                          verified=True,
                                          false_p=False,
                                          duplicate=False,
                                          out_of_scope=False,
                                          severity="High",
                                          date__range=[start_date,
                                                       end_date]).count()
            medium = Finding.objects.filter(test__engagement__product=self,
                                            mitigated__isnull=True,
                                            verified=True,
                                            false_p=False,
                                            duplicate=False,
                                            out_of_scope=False,
                                            severity="Medium",
                                            date__range=[start_date,
                                                         end_date]).count()
            low = Finding.objects.filter(test__engagement__product=self,
                                         mitigated__isnull=True,
                                         verified=True,
                                         false_p=False,
                                         duplicate=False,
                                         out_of_scope=False,
                                         severity="Low",
                                         date__range=[start_date,
                                                      end_date]).count()
            return {'Critical': critical,
                    'High': high,
                    'Medium': medium,
                    'Low': low,
                    'Total': (critical + high + medium + low)}

    def get_breadcrumbs(self):
        bc = [{'title': self.__unicode__(),
               'url': reverse('view_product', args=(self.id,))}]
        return bc

    @property
    def get_product_type(self):
        return self.prod_type if self.prod_type is not None else 'unknown'


class ScanSettings(models.Model):
    product = models.ForeignKey(Product, default=1, editable=False)
    addresses = models.TextField(default="none")
    user = models.ForeignKey(User, editable=False)
    date = models.DateTimeField(editable=False, blank=True,
                                default=get_current_datetime)
    frequency = models.CharField(max_length=10000, null=True,
                                 blank=True)
    email = models.CharField(max_length=512)
    protocol = models.CharField(max_length=10, default='TCP')

    def addresses_as_list(self):
        if self.addresses:
            return [a.strip() for a in self.addresses.split(',')]
        return []

    def get_breadcrumbs(self):
        bc = self.product.get_breadcrumbs()
        bc += [{'title': "Scan Settings",
                'url': reverse('view_scan_settings',
                               args=(self.product.id, self.id,))}]
        return bc


"""
Modified by Fatimah and Micheal
removed ip_scans field
"""


class Scan(models.Model):
    scan_settings = models.ForeignKey(ScanSettings, default=1, editable=False)
    date = models.DateTimeField(editable=False, blank=True,
                                default=get_current_datetime)
    protocol = models.CharField(max_length=10, default='TCP')
    status = models.CharField(max_length=10, default='Pending', editable=False)
    baseline = models.BooleanField(default=False,
                                   verbose_name="Current Baseline")

    def __unicode__(self):
        return self.scan_settings.protocol + " Scan " + str(self.date)

    def get_breadcrumbs(self):
        bc = self.scan_settings.get_breadcrumbs()
        bc += [{'title': self.__unicode__(),
                'url': reverse('view_scan', args=(self.id,))}]
        return bc


"""
Modified by Fatimah and Micheal
Changed services from a ManytToMany field to a formatted string
"port,protocol,status"
Added scan_id
"""


class IPScan(models.Model):
    address = models.TextField(editable=False, default="none")
    services = models.CharField(max_length=800, null=True)
    scan = models.ForeignKey(Scan, default=1, editable=False)


class Engagement_Type(models.Model):
    name = models.CharField(max_length=200)


class Engagement(models.Model):
    name = models.CharField(max_length=300, null=True, blank=True)
    description = models.CharField(max_length=2000, null=True, blank=True)
    version = models.CharField(max_length=100, null=True, blank=True)
    eng_type = models.ForeignKey(Engagement_Type, null=True, blank=True)
    first_contacted = models.DateField(null=True, blank=True)
    target_start = models.DateField(null=False, blank=False)
    target_end = models.DateField(null=False, blank=False)
    lead = models.ForeignKey(User, editable=True, null=True)
    requester = models.ForeignKey(Contact, null=True, blank=True)
    reason = models.CharField(max_length=2000, null=True, blank=True)
    report_type = models.ForeignKey(Report_Type, null=True, blank=True)
    product = models.ForeignKey(Product)
    updated = models.DateTimeField(editable=False, null=True, blank=True)
    active = models.BooleanField(default=True, editable=False)
    test_strategy = models.URLField(editable=True, blank=True, null=True)
    threat_model = models.BooleanField(default=True)
    api_test = models.BooleanField(default=True)
    pen_test = models.BooleanField(default=True)
    check_list = models.BooleanField(default=True)
    status = models.CharField(editable=True, max_length=2000, default='',
                              null=True,
                              choices=(('In Progress', 'In Progress'),
                                       ('On Hold', 'On Hold'),
                                       ('Completed', 'Completed')))
    progress = models.CharField(max_length=100,
                                default='threat_model', editable=False)
    tmodel_path = models.CharField(max_length=1000, default='none',
                                   editable=False, blank=True, null=True)
    risk_path = models.CharField(max_length=1000, default='none',
                                 editable=False, blank=True, null=True)
    risk_acceptance = models.ManyToManyField("Risk_Acceptance",
                                             default=None,
                                             editable=False,
                                             blank=True)
    done_testing = models.BooleanField(default=False, editable=False)

    class Meta:
        ordering = ['-target_start']

    def __unicode__(self):
        return "Engagement: %s (%s)" % (self.name if self.name else '',
                                        self.target_start.strftime(
                                            "%b %d, %Y"))

    def get_breadcrumbs(self):
        bc = self.product.get_breadcrumbs()
        bc += [{'title': self.__unicode__(),
                'url': reverse('view_engagement', args=(self.id,))}]
        return bc


class CWE(models.Model):
    url = models.CharField(max_length=1000)
    description = models.CharField(max_length=2000)
    number = models.IntegerField()


class Endpoint_Params(models.Model):
    param = models.CharField(max_length=150)
    value = models.CharField(max_length=150)
    method_type = (('GET', 'GET'),
                   ('POST', 'POST'))
    method = models.CharField(max_length=20, blank=False, null=True, choices=method_type)


class Endpoint(models.Model):
    protocol = models.CharField(null=True, blank=True, max_length=10,
                                help_text="The communication protocol such as 'http', 'ftp', etc.")
    host = models.CharField(null=True, blank=True, max_length=500,
                            help_text="The host name or IP address, you can also include the port number. For example"
                                      "'127.0.0.1', '127.0.0.1:8080', 'localhost', 'yourdomain.com'.")
    fqdn = models.CharField(null=True, blank=True, max_length=500)
    port = models.IntegerField(null=True, blank=True,
                               help_text="The network port associated with the endpoint.")
    path = models.CharField(null=True, blank=True, max_length=500,
                            help_text="The location of the resource, it should start with a '/'. For example"
                                      "/endpoint/420/edit")
    query = models.CharField(null=True, blank=True, max_length=5000,
                             help_text="The query string, the question mark should be omitted."
                                       "For example 'group=4&team=8'")
    fragment = models.CharField(null=True, blank=True, max_length=500,
                                help_text="The fragment identifier which follows the hash mark. The hash mark should "
                                          "be omitted. For example 'section-13', 'paragraph-2'.")
    product = models.ForeignKey(Product, null=True, blank=True, )
    endpoint_params = models.ManyToManyField(Endpoint_Params, blank=True,
                                             editable=False)

    class Meta:
        ordering = ['product', 'protocol', 'host', 'path', 'query', 'fragment']

    def __unicode__(self):
        from urlparse import uses_netloc

        netloc = self.host
        port = self.port
        scheme = self.protocol
        url = self.path if self.path else ''
        query = self.query
        fragment = self.fragment

        if port:
            netloc += ':%s' % port

        if netloc or (scheme and scheme in uses_netloc and url[:2] != '//'):
            if url and url[:1] != '/':
                url = '/' + url
            if scheme and scheme in uses_netloc and url[:2] != '//':
                url = '//' + (netloc or '') + url
            else:
                url = (netloc or '') + url
        if scheme:
            url = scheme + ':' + url
        if query:
            url = url + '?' + query
        if fragment:
            url = url + '#' + fragment
        return url

    def __eq__(self, other):
        if isinstance(other, Endpoint):
            return self.__unicode__() == other.__unicode__()
        else:
            return NotImplemented

    def finding_count(self):
        host = self.host_no_port

        endpoints = Endpoint.objects.filter(host__regex="^" + host + ":?",
                                            product=self.product).distinct()

        findings = Finding.objects.filter(endpoints__in=endpoints,
                                          active=True,
                                          verified=True,
                                          out_of_scope=False).distinct()

        return findings.count()

    def active_findings(self):
        host = self.host_no_port

        endpoints = Endpoint.objects.filter(host__regex="^" + host + ":?",
                                            product=self.product).distinct()
        return Finding.objects.filter(endpoints__in=endpoints,
                                      active=True,
                                      verified=True,
                                      mitigated__isnull=True,
                                      false_p=False,
                                      duplicate=False).distinct().order_by(
            'numerical_severity')

    def finding_count_endpoint(self):
        findings = Finding.objects.filter(endpoints=self,
                                          active=True,
                                          verified=True,
                                          out_of_scope=False).distinct()

        return findings.count()

    def get_breadcrumbs(self):
        bc = self.product.get_breadcrumbs()
        bc += [{'title': self.host_no_port,
                'url': reverse('view_endpoint', args=(self.id,))}]
        return bc

    @staticmethod
    def from_uri(uri):
        return Endpoint()

    @property
    def host_no_port(self):
        if ":" in self.host:
            return self.host[:self.host.index(":")]
        else:
            return self.host


class Notes(models.Model):
    entry = models.CharField(max_length=2400)
    date = models.DateTimeField(null=False, editable=False,
                                default=get_current_datetime)
    author = models.ForeignKey(User, editable=False)

    class Meta:
        ordering = ['-date']

    def __unicode__(self):
        return self.entry


class Development_Environment(models.Model):
    name = models.CharField(max_length=200)

    def __unicode__(self):
        return self.name

    def get_breadcrumbs(self):
        return [{"title": self.__unicode__(),
                 "url": reverse("edit_dev_env", args=(self.id,))}]


class Test(models.Model):
    engagement = models.ForeignKey(Engagement, editable=False)
    lead = models.ForeignKey(User, editable=True, null=True)
    test_type = models.ForeignKey(Test_Type)
    target_start = models.DateTimeField()
    target_end = models.DateTimeField()
    estimated_time = models.TimeField(null=True, blank=True, editable=False)
    actual_time = models.TimeField(null=True, blank=True, editable=False, )
    percent_complete = models.IntegerField(null=True, blank=True,
                                           editable=True)
    notes = models.ManyToManyField(Notes, blank=True,
                                   editable=False)
    environment = models.ForeignKey(Development_Environment, null=True,
                                    blank=False)

    def __unicode__(self):
        return "%s (%s)" % (self.test_type,
                            self.target_start.strftime("%b %d, %Y"))

    def get_breadcrumbs(self):
        bc = self.engagement.get_breadcrumbs()
        bc += [{'title': self.__unicode__(),
                'url': reverse('view_test', args=(self.id,))}]
        return bc

    def verified_finding_count(self):
        return Finding.objects.filter(test=self, verified=True).count()


class VA(models.Model):
    address = models.TextField(editable=False, default="none")
    user = models.ForeignKey(User, editable=False)
    result = models.ForeignKey(Test, editable=False, null=True, blank=True)
    status = models.BooleanField(default=False, editable=False)
    start = models.CharField(max_length=100)


class Finding(models.Model):
    title = models.TextField(max_length=1000)
    date = models.DateField(default=get_current_date)
    cwe = models.IntegerField(default=0, null=True, blank=True)
    url = models.TextField(null=True, blank=True, editable=False)
    severity = models.CharField(max_length=200)
    description = models.TextField()
    mitigation = models.TextField()
    impact = models.TextField()
    endpoints = models.ManyToManyField(Endpoint, blank=True, )
    unsaved_endpoints = []
    unsaved_request = None
    unsaved_response = None
    unsaved_tags = None
    references = models.TextField(null=True, blank=True, db_column="refs")
    test = models.ForeignKey(Test, editable=False)
    # TODO: Will be deprecated soon
    is_template = models.BooleanField(default=False)
    active = models.BooleanField(default=True)
    verified = models.BooleanField(default=True)
    false_p = models.BooleanField(default=False, verbose_name="False Positive")
    duplicate = models.BooleanField(default=False)
    duplicate_finding = models.ForeignKey('self', editable=False, null=True,
                                          related_name='original_finding',
                                          blank=True)
    duplicate_list = models.ManyToManyField("self", editable=False, blank=True)
    out_of_scope = models.BooleanField(default=False)
    under_review = models.BooleanField(default=False)
    review_requested_by = models.ForeignKey(Dojo_User, null=True, blank=True,
                                            related_name='review_requested_by')
    reviewers = models.ManyToManyField(User, blank=True)

    # Defect Tracking Review
    under_defect_review = models.BooleanField(default=False)
    defect_review_requested_by = models.ForeignKey(Dojo_User, null=True, blank=True,
                                                   related_name='defect_review_requested_by')

    thread_id = models.IntegerField(default=0, editable=False)
    mitigated = models.DateTimeField(editable=False, null=True, blank=True)
    mitigated_by = models.ForeignKey(User, null=True, editable=False,
                                     related_name="mitigated_by")
    reporter = models.ForeignKey(User, editable=False, related_name='reporter')
    notes = models.ManyToManyField(Notes, blank=True,
                                   editable=False)
    numerical_severity = models.CharField(max_length=4)
    last_reviewed = models.DateTimeField(null=True, editable=False)
    last_reviewed_by = models.ForeignKey(User, null=True, editable=False,
                                         related_name='last_reviewed_by')
    images = models.ManyToManyField('FindingImage', blank=True)

    line_number = models.CharField(null=True, blank=True, max_length=200,
                                   editable=False)  # Deprecated will be removed, use line
    sourcefilepath = models.TextField(null=True, blank=True, editable=False)
    sourcefile = models.TextField(null=True, blank=True, editable=False)
    param = models.TextField(null=True, blank=True, editable=False)
    payload = models.TextField(null=True, blank=True, editable=False)
    hash_code = models.TextField(null=True, blank=True, editable=False)

    line = models.IntegerField(null=True, blank=True,
                               verbose_name="Line number")
    file_path = models.CharField(null=True, blank=True, max_length=1000)
    found_by = models.ManyToManyField(Test_Type, editable=False)
    static_finding = models.BooleanField(default=False)
    dynamic_finding = models.BooleanField(default=False)

    SEVERITIES = {'Info': 4, 'Low': 3, 'Medium': 2,
                  'High': 1, 'Critical': 0}

    class Meta:
        ordering = ('numerical_severity', '-date', 'title')

    def get_hash_code(self):
        hash_string = self.title + self.description + str(self.line) + str(
            self.file_path)
        return hashlib.sha256(hash_string.encode('utf-8')).hexdigest()

    @staticmethod
    def get_numerical_severity(severity):
        if severity == 'Critical':
            return 'S0'
        elif severity == 'High':
            return 'S1'
        elif severity == 'Medium':
            return 'S2'
        elif severity == 'Low':
            return 'S3'
        else:
            return 'S4'

    @staticmethod
    def get_number_severity(severity):
        if severity == 'Critical':
            return 4
        elif severity == 'High':
            return 3
        elif severity == 'Medium':
            return 2
        elif severity == 'Low':
            return 1
        else:
            return 5

    def __unicode__(self):
        return self.title

    def status(self):
        status = []
        if self.active:
            status += ['Active']
        else:
            status += ['Inactive']
        if self.verified:
            status += ['Verified']
        if self.mitigated:
            status += ['Mitigated']
        if self.false_p:
            status += ['False Positive']
        if self.out_of_scope:
            status += ['Out Of Scope']
        if self.duplicate:
            status += ['Duplicate']
        if len(self.risk_acceptance_set.all()) > 0:
            status += ['Accepted']

        if not len(status):
            status += ['Initial']

        return ", ".join([str(s) for s in status])

    def age(self):
        if self.mitigated:
            days = (self.mitigated.date() - datetime.combine(self.date,
                                                             datetime.min.time()).date()).days
        else:
            days = (get_current_date() - datetime.combine(self.date,
                                                          datetime.min.time()).date()).days

        return days if days > 0 else 0

    def jira(self):
        try:
            jissue = JIRA_Issue.objects.get(finding=self)
        except:
            jissue = None
            pass
        return jissue

    def jira_conf(self):
        try:
            jpkey = JIRA_PKey.objects.get(product=self.test.engagement.product)
            jconf = jpkey.conf
        except:
            jconf = None
            pass
        return jconf

    def long_desc(self):
        long_desc = ''
        long_desc += '*' + self.title + '*\n\n'
        long_desc += '*Severity:* ' + self.severity + '\n\n'
        long_desc += '*Systems*: \n'
        for e in self.endpoints.all():
            long_desc += str(e) + '\n\n'
        long_desc += '*Description*: \n' + self.description + '\n\n'
        long_desc += '*Mitigation*: \n' + self.mitigation + '\n\n'
        long_desc += '*Impact*: \n' + self.impact + '\n\n'
        long_desc += '*References*:' + self.references
        return long_desc

    def save(self, dedupe_option=True, *args, **kwargs):
        super(Finding, self).save(*args, **kwargs)
        self.found_by.add(self.test.test_type)
        self.hash_code = self.get_hash_code()
        if self.test.test_type.static_tool:
            self.static_finding = True
        else:
            self.dyanmic_finding = True

        from dojo.utils import calculate_grade
        calculate_grade(self.test.engagement.product)

        super(Finding, self).save()
        if (dedupe_option):
            system_settings = System_Settings.objects.get()
            if system_settings.enable_deduplication:
                from dojo.tasks import async_dedupe
                from dojo.utils import sync_dedupe
                try:
                    if self.reporter.usercontactinfo.block_execution:
                        sync_dedupe(self, *args, **kwargs)
                    else:
                        async_dedupe.delay(self, *args, **kwargs)
                except:
                    async_dedupe.delay(self, *args, **kwargs)
                    pass

            if system_settings.false_positive_history:
                from dojo.tasks import async_false_history
                from dojo.utils import sync_false_history
                if self.reporter.usercontactinfo.block_execution:
                    sync_false_history(self, *args, **kwargs)
                else:
                    async_false_history.delay(self, *args, **kwargs)

    def delete(self, *args, **kwargs):
        super(Finding, self).delete(*args, **kwargs)
        from dojo.utils import calculate_grade
        calculate_grade(self.test.engagement.product)

    def clean(self):
        no_check = ["test", "reporter"]
        bigfields = ["description", "mitigation", "references", "impact",
                     "url"]
        for field_obj in self._meta.fields:
            field = field_obj.name
            if field not in no_check:
                val = getattr(self, field)
                if not val and field == "title":
                    setattr(self, field, "No title given")
                if not val and field in bigfields:
                    setattr(self, field, "No %s given" % field)

    def severity_display(self):
        try:
            system_settings = System_Settings.objects.get()
            if system_settings.s_finding_severity_naming:
                return self.numerical_severity
            else:
                return self.severity

        except:
            return self.severity

    def get_breadcrumbs(self):
        bc = self.test.get_breadcrumbs()
        bc += [{'title': self.__unicode__(),
                'url': reverse('view_finding', args=(self.id,))}]
        return bc

    def get_report_requests(self):
        if self.burprawrequestresponse_set.count() >= 3:
            return BurpRawRequestResponse.objects.filter(finding=self)[0:3]
        elif self.burprawrequestresponse_set.count() > 0:
            return BurpRawRequestResponse.objects.filter(finding=self)

    def get_request(self):
        if self.burprawrequestresponse_set.count() > 0:
            reqres = BurpRawRequestResponse.objects.filter(finding=self)[0]
        return base64.b64decode(reqres.burpRequestBase64)

    def get_response(self):
        if self.burprawrequestresponse_set.count() > 0:
            reqres = BurpRawRequestResponse.objects.filter(finding=self)[0]
        res = base64.b64decode(reqres.burpResponseBase64)
        # Removes all blank lines
        res = re.sub(r'\n\s*\n', '\n', res)
        return res

    def get_found_by(self):
        scanners = self.found_by.all().distinct()
        return ", ".join([str(scanner) for scanner in scanners])


Finding.endpoints.through.__unicode__ = lambda \
    x: "Endpoint: " + x.endpoint.host


class Stub_Finding(models.Model):
    title = models.TextField(max_length=1000, blank=False, null=False)
    date = models.DateField(default=get_current_date, blank=False, null=False)
    severity = models.CharField(max_length=200, blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    test = models.ForeignKey(Test, editable=False)
    reporter = models.ForeignKey(User, editable=False)

    class Meta:
        ordering = ('-date', 'title')

    def __unicode__(self):
        return self.title

    def get_breadcrumbs(self):
        bc = self.test.get_breadcrumbs()
        bc += [{'title': "Potential Finding: " + self.__unicode__(),
                'url': reverse('view_potential_finding', args=(self.id,))}]
        return bc


class Finding_Template(models.Model):
    title = models.TextField(max_length=1000)
    cwe = models.IntegerField(default=None, null=True, blank=True)
    severity = models.CharField(max_length=200, null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    mitigation = models.TextField(null=True, blank=True)
    impact = models.TextField(null=True, blank=True)
    references = models.TextField(null=True, blank=True, db_column="refs")
    numerical_severity = models.CharField(max_length=4, null=True, blank=True,
                                          editable=False)

    SEVERITIES = {'Info': 4, 'Low': 3, 'Medium': 2,
                  'High': 1, 'Critical': 0}

    class Meta:
        ordering = ['-cwe']

    def __unicode__(self):
        return self.title

    def get_breadcrumbs(self):
        bc = [{'title': self.__unicode__(),
               'url': reverse('view_template', args=(self.id,))}]
        return bc


class Check_List(models.Model):
    session_management = models.CharField(max_length=50, default='none')
    session_issues = models.ManyToManyField(Finding,
                                            related_name='session_issues',
                                            blank=True)
    encryption_crypto = models.CharField(max_length=50, default='none')
    crypto_issues = models.ManyToManyField(Finding,
                                           related_name='crypto_issues',
                                           blank=True)
    configuration_management = models.CharField(max_length=50, default='')
    config_issues = models.ManyToManyField(Finding,
                                           related_name='config_issues',
                                           blank=True)
    authentication = models.CharField(max_length=50, default='none')
    auth_issues = models.ManyToManyField(Finding,
                                         related_name='auth_issues',
                                         blank=True)
    authorization_and_access_control = models.CharField(max_length=50,
                                                        default='none')
    author_issues = models.ManyToManyField(Finding,
                                           related_name='author_issues',
                                           blank=True)
    data_input_sanitization_validation = models.CharField(max_length=50,
                                                          default='none')
    data_issues = models.ManyToManyField(Finding, related_name='data_issues',
                                         blank=True)
    sensitive_data = models.CharField(max_length=50, default='none')
    sensitive_issues = models.ManyToManyField(Finding,
                                              related_name='sensitive_issues',
                                              blank=True)
    other = models.CharField(max_length=50, default='none')
    other_issues = models.ManyToManyField(Finding, related_name='other_issues',
                                          blank=True)
    engagement = models.ForeignKey(Engagement, editable=False,
                                   related_name='eng_for_check')

    @staticmethod
    def get_status(pass_fail):
        if pass_fail == 'Pass':
            return 'success'
        elif pass_fail == 'Fail':
            return 'danger'
        else:
            return 'warning'

    def get_breadcrumb(self):
        bc = self.engagement.get_breadcrumb()
        bc += [{'title': "Check List",
                'url': reverse('complete_checklist',
                               args=(self.engagement.id,))}]
        return bc


class BurpRawRequestResponse(models.Model):
    finding = models.ForeignKey(Finding, blank=True, null=True)
    burpRequestBase64 = models.BinaryField()
    burpResponseBase64 = models.BinaryField()

    def get_request(self):
        return base64.b64decode(self.burpRequestBase64).decode("utf-8")

    def get_response(self):
        res = base64.b64decode(self.burpResponseBase64).decode("utf-8")
        # Removes all blank lines
        res = re.sub(r'\n\s*\n', '\n', res)
        return res


class Risk_Acceptance(models.Model):
    path = models.FileField(upload_to='risk/%Y/%m/%d',
                            editable=False, null=False,
                            blank=False, verbose_name="Risk Acceptance File")
    accepted_findings = models.ManyToManyField(Finding)
    reporter = models.ForeignKey(User, editable=False)
    notes = models.ManyToManyField(Notes, editable=False)
    created = models.DateTimeField(null=False, editable=False,
                                   default=now)

    def __unicode__(self):
        return "Risk Acceptance added on %s" % self.created.strftime(
            "%b %d, %Y")

    def filename(self):
        return os.path.basename(self.path.name) \
            if self.path is not None else ''

    def get_breadcrumbs(self):
        bc = self.engagement_set.first().get_breadcrumbs()
        bc += [{'title': self.__unicode__(),
                'url': reverse('view_risk', args=(
                    self.engagement_set.first().product.id, self.id,))}]
        return bc


class Report(models.Model):
    name = models.CharField(max_length=200)
    type = models.CharField(max_length=100, default='Finding')
    format = models.CharField(max_length=15, default='AsciiDoc')
    requester = models.ForeignKey(User)
    task_id = models.CharField(max_length=50)
    file = models.FileField(upload_to='reports/%Y/%m/%d',
                            verbose_name='Report File', null=True)
    status = models.CharField(max_length=10, default='requested')
    options = models.TextField()
    datetime = models.DateTimeField(auto_now_add=True)
    done_datetime = models.DateTimeField(null=True)

    def __unicode__(self):
        return self.name

    def get_url(self):
        return reverse('download_report', args=(self.id,))

    class Meta:
        ordering = ['-datetime']


class FindingImage(models.Model):
    image = models.ImageField(upload_to='finding_images', null=True)
    image_thumbnail = ImageSpecField(source='image',
                                     processors=[ResizeToCover(100, 100)],
                                     format='JPEG',
                                     options={'quality': 70})
    image_small = ImageSpecField(source='image',
                                 processors=[ResizeToCover(640, 480)],
                                 format='JPEG',
                                 options={'quality': 100})
    image_medium = ImageSpecField(source='image',
                                  processors=[ResizeToCover(800, 600)],
                                  format='JPEG',
                                  options={'quality': 100})
    image_large = ImageSpecField(source='image',
                                 processors=[ResizeToCover(1024, 768)],
                                 format='JPEG',
                                 options={'quality': 100})

    def __unicode__(self):
        return self.image.name or u'No Image'


class FindingImageAccessToken(models.Model):
    """This will allow reports to request the images without exposing the
    media root to the world without
    authentication"""
    user = models.ForeignKey(User, null=False, blank=False)
    image = models.ForeignKey(FindingImage, null=False, blank=False)
    token = models.CharField(max_length=255)
    size = models.CharField(max_length=9,
                            choices=(
                                ('small', 'Small'),
                                ('medium', 'Medium'),
                                ('large', 'Large'),
                                ('thumbnail', 'Thumbnail'),
                                ('original', 'Original')),
                            default='medium')

    def save(self, *args, **kwargs):
        if not self.token:
            self.token = uuid4()
        return super(FindingImageAccessToken, self).save(*args, **kwargs)


class JIRA_Conf(models.Model):
    url = models.URLField(max_length=2000, verbose_name="JIRA URL", help_text="For configuring Jira, view: https://defectdojo.readthedocs.io/en/latest/features.html#jira-integration")
    #    product = models.ForeignKey(Product)
    username = models.CharField(max_length=2000)
    password = models.CharField(max_length=2000)
    #    project_key = models.CharField(max_length=200,null=True, blank=True)
    #    enabled = models.BooleanField(default=True)
    default_issue_type = models.CharField(max_length=9,
                                          choices=(
                                              ('Task', 'Task'),
                                              ('Story', 'Story'),
                                              ('Epic', 'Epic'),
                                              ('Spike', 'Spike'),
                                              ('Bug', 'Bug')),
                                          default='Bug')
    epic_name_id = models.IntegerField(help_text="To obtain the 'Epic name id' visit https://<YOUR JIRA URL>/rest/api/2/field and search for Epic Name. Copy the number out of cf[number] and paste it here.")
    open_status_key = models.IntegerField(help_text="To obtain the 'open status key' visit https://<YOUR JIRA URL>/rest/api/latest/issue/<ANY VALID ISSUE KEY>/transitions?expand=transitions.fields")
    close_status_key = models.IntegerField(help_text="To obtain the 'open status key' visit https://<YOUR JIRA URL>/rest/api/latest/issue/<ANY VALID ISSUE KEY>/transitions?expand=transitions.fields")
    low_mapping_severity = models.CharField(max_length=200, help_text="Maps to the 'Priority' field in Jira. For example: Low")
    medium_mapping_severity = models.CharField(max_length=200, help_text="Maps to the 'Priority' field in Jira. For example: Medium")
    high_mapping_severity = models.CharField(max_length=200, help_text="Maps to the 'Priority' field in Jira. For example: High")
    critical_mapping_severity = models.CharField(max_length=200, help_text="Maps to the 'Priority' field in Jira. For example: Critical")
    finding_text = models.TextField(null=True, blank=True, help_text="Additional text that will be added to the finding in Jira. For example including how the finding was created or who to contact for more information.")

    def __unicode__(self):
        return self.url + " | " + self.username

    def get_priority(self, status):
        if status == 'Low':
            return self.low_mapping_severity
        elif status == 'Medium':
            return self.medium_mapping_severity
        elif status == 'High':
            return self.high_mapping_severity
        elif status == 'Critical':
            return self.critical_mapping_severity
        else:
            return 'N/A'


class JIRA_Issue(models.Model):
    jira_id = models.CharField(max_length=200)
    jira_key = models.CharField(max_length=200)
    finding = models.OneToOneField(Finding, null=True, blank=True)
    engagement = models.OneToOneField(Engagement, null=True, blank=True)


class JIRA_Clone(models.Model):
    jira_id = models.CharField(max_length=200)
    jira_clone_id = models.CharField(max_length=200)


class JIRA_Details_Cache(models.Model):
    jira_id = models.CharField(max_length=200)
    jira_key = models.CharField(max_length=200)
    jira_status = models.CharField(max_length=200)
    jira_resolution = models.CharField(max_length=200)


class JIRA_PKey(models.Model):
    project_key = models.CharField(max_length=200, blank=True)
    product = models.ForeignKey(Product)
    conf = models.ForeignKey(JIRA_Conf, verbose_name="JIRA Configuration",
                             null=True, blank=True)
    component = models.CharField(max_length=200, blank=True)
    push_all_issues = models.BooleanField(default=False, blank=True)
    enable_engagement_epic_mapping = models.BooleanField(default=False,
                                                         blank=True)
    push_notes = models.BooleanField(default=False, blank=True)


NOTIFICATION_CHOICES = (
    ("slack", "slack"), ("hipchat", "hipchat"), ("mail", "mail"),
    ("alert", "alert"))


class Notifications(models.Model):
    product_added = MultiSelectField(choices=NOTIFICATION_CHOICES, default='alert', blank=True)
    engagement_added = MultiSelectField(choices=NOTIFICATION_CHOICES, default='alert', blank=True)
    test_added = MultiSelectField(choices=NOTIFICATION_CHOICES, default='alert', blank=True)
    results_added = MultiSelectField(choices=NOTIFICATION_CHOICES, default='alert', blank=True)
    report_created = MultiSelectField(choices=NOTIFICATION_CHOICES, default='alert', blank=True)
    jira_update = MultiSelectField(choices=NOTIFICATION_CHOICES, default='alert', blank=True)
    upcoming_engagement = MultiSelectField(choices=NOTIFICATION_CHOICES, default='alert', blank=True)
    user_mentioned = MultiSelectField(choices=NOTIFICATION_CHOICES, default='alert', blank=True)
    code_review = MultiSelectField(choices=NOTIFICATION_CHOICES, default='alert', blank=True)
    review_requested = MultiSelectField(choices=NOTIFICATION_CHOICES, default='alert', blank=True)
    other = MultiSelectField(choices=NOTIFICATION_CHOICES, default='alert', blank=True)
    user = models.ForeignKey(User, default=None, null=True, editable=False)


class Tool_Type(models.Model):
    name = models.CharField(max_length=200)
    description = models.CharField(max_length=2000, null=True)

    class Meta:
        ordering = ['name']

    def __unicode__(self):
        return self.name


class Tool_Configuration(models.Model):
    name = models.CharField(max_length=200, null=False)
    description = models.CharField(max_length=2000, null=True, blank=True)
    url = models.CharField(max_length=2000, null=True)
    tool_type = models.ForeignKey(Tool_Type, related_name='tool_type')
    authentication_type = models.CharField(max_length=15,
                                           choices=(
                                               ('API', 'API Key'),
                                               ('Password',
                                                'Username/Password'),
                                               ('SSH', 'SSH')),
                                           null=True, blank=True)
    username = models.CharField(max_length=200, null=True, blank=True)
    password = models.CharField(max_length=600, null=True, blank=True)
    auth_title = models.CharField(max_length=200, null=True, blank=True,
                                  verbose_name="Title for SSH/API Key")
    ssh = models.CharField(max_length=6000, null=True, blank=True)
    api_key = models.CharField(max_length=600, null=True, blank=True,
                               verbose_name="API Key")

    class Meta:
        ordering = ['name']

    def __unicode__(self):
        return self.name


class Tool_Product_Settings(models.Model):
    name = models.CharField(max_length=200, null=False)
    description = models.CharField(max_length=2000, null=True, blank=True)
    url = models.CharField(max_length=2000, null=True, blank=True)
    product = models.ForeignKey(Product, default=1, editable=False)
    tool_configuration = models.ForeignKey(Tool_Configuration, null=False,
                                           related_name='tool_configuration')
    tool_project_id = models.CharField(max_length=200, null=True, blank=True)
    notes = models.ManyToManyField(Notes, blank=True, editable=False)

    class Meta:
        ordering = ['name']


class Tool_Product_History(models.Model):
    product = models.ForeignKey(Tool_Product_Settings, editable=False)
    last_scan = models.DateTimeField(null=False, editable=False, default=now)
    succesfull = models.BooleanField(default=True, verbose_name="Succesfully")
    configuration_details = models.CharField(max_length=2000, null=True,
                                             blank=True)


class Alerts(models.Model):
    title = models.CharField(max_length=100, default='', null=False)
    description = models.CharField(max_length=2000, null=True)
    url = models.URLField(max_length=2000, null=True)
    source = models.CharField(max_length=100, default='Generic')
    icon = models.CharField(max_length=25, default='icon-user-check')
    user_id = models.ForeignKey(User, null=True, editable=False)
    created = models.DateTimeField(null=False, editable=False, default=now)

    class Meta:
        ordering = ['-created']


class Cred_User(models.Model):
    name = models.CharField(max_length=200, null=False)
    username = models.CharField(max_length=200, null=False)
    password = models.CharField(max_length=600, null=False)
    role = models.CharField(max_length=200, null=False)
    authentication = models.CharField(max_length=15,
                                      choices=(
                                          ('Form', 'Form Authentication'),
                                          ('SSO', 'SSO Redirect')),
                                      default='Form')
    http_authentication = models.CharField(max_length=15,
                                           choices=(
                                               ('Basic', 'Basic'),
                                               ('NTLM', 'NTLM')),
                                           null=True, blank=True)
    description = models.CharField(max_length=2000, null=True, blank=True)
    url = models.URLField(max_length=2000, null=False)
    environment = models.ForeignKey(Development_Environment, null=False)
    login_regex = models.CharField(max_length=200, null=True, blank=True)
    logout_regex = models.CharField(max_length=200, null=True, blank=True)
    notes = models.ManyToManyField(Notes, blank=True, editable=False)
    is_valid = models.BooleanField(default=True, verbose_name="Login is valid")

    # selenium_script = models.CharField(max_length=1000, default='none',
    #    editable=False, blank=True, null=True,
    #    verbose_name="Selenium Script File")

    class Meta:
        ordering = ['name']

    def __unicode__(self):
        return self.name + " (" + self.role + ")"


class Cred_Mapping(models.Model):
    cred_id = models.ForeignKey(Cred_User, null=False,
                                related_name="cred_user",
                                verbose_name="Credential")
    product = models.ForeignKey(Product, null=True, blank=True,
                                related_name="product")
    finding = models.ForeignKey(Finding, null=True, blank=True,
                                related_name="finding")
    engagement = models.ForeignKey(Engagement, null=True, blank=True,
                                   related_name="engagement")
    test = models.ForeignKey(Test, null=True, blank=True, related_name="test")
    is_authn_provider = models.BooleanField(default=False,
                                            verbose_name="Authentication Provider")
    url = models.URLField(max_length=2000, null=True, blank=True)

    def __unicode__(self):
        return self.cred_id.name + " (" + self.cred_id.role + ")"


class Language_Type(models.Model):
    language = models.CharField(max_length=100, null=False)
    color = models.CharField(max_length=7, null=True, verbose_name='HTML color')

    def __unicode__(self):
        return self.language


class Languages(models.Model):
    language = models.ForeignKey(Language_Type)
    product = models.ForeignKey(Product)
    user = models.ForeignKey(User, editable=True)
    files = models.IntegerField(blank=True, null=True, verbose_name='Number of files')
    blank = models.IntegerField(blank=True, null=True, verbose_name='Number of blank lines')
    comment = models.IntegerField(blank=True, null=True, verbose_name='Number of comment lines')
    code = models.IntegerField(blank=True, null=True, verbose_name='Number of code lines')
    created = models.DateTimeField(null=False, editable=False, default=now)

    def __unicode__(self):
        return self.language.language


class App_Analysis(models.Model):
    product = models.ForeignKey(Product)
    name = models.CharField(max_length=200, null=False)
    user = models.ForeignKey(User, editable=True)
    confidence = models.IntegerField(blank=True, null=True, verbose_name='Confidence level')
    version = models.CharField(max_length=200, null=True, blank=True, verbose_name='Version Number')
    icon = models.CharField(max_length=200, null=True, blank=True)
    website = models.URLField(max_length=400, null=True, blank=True)
    website_found = models.URLField(max_length=400, null=True, blank=True)
    created = models.DateTimeField(null=False, editable=False, default=now)

    def __unicode__(self):
        return self.name + " | " + self.product.name


class Objects_Review(models.Model):
    name = models.CharField(max_length=100, null=True)
    created = models.DateTimeField(null=False, editable=False, default=now)

    def __unicode__(self):
        return self.name


class Objects(models.Model):
    product = models.ForeignKey(Product)
    name = models.CharField(max_length=100, null=True, blank=True)
    path = models.CharField(max_length=600, verbose_name='Full file path',
                            null=True, blank=True)
    folder = models.CharField(max_length=400, verbose_name='Folder',
                              null=True, blank=True)
    artifact = models.CharField(max_length=400, verbose_name='Artifact',
                                null=True, blank=True)
    review_status = models.ForeignKey(Objects_Review)
    created = models.DateTimeField(null=False, editable=False, default=now)

    def __unicode__(self):
        name = None
        if self.path is not None:
            name = self.path
        elif self.folder is not None:
            name = self.folder
        elif self.artifact is not None:
            name = self.artifact

        return name

    class Meta:
        unique_together = [('product', 'path')]


class Objects_Engagement(models.Model):
    engagement = models.ForeignKey(Engagement)
    object_id = models.ForeignKey(Objects)
    build_id = models.CharField(max_length=150, null=True)
    created = models.DateTimeField(null=False, editable=False, default=now)
    full_url = models.URLField(max_length=400, null=True, blank=True)
    type = models.CharField(max_length=30, null=True)
    percentUnchanged = models.CharField(max_length=10, null=True)

    def __unicode__(self):
        data = ""
        if self.object_id.path:
            data = self.object_id.path
        elif self.object_id.folder:
            data = self.object_id.folder
        elif self.object_id.artifact:
            data = self.object_id.artifact

        return data + " | " + self.engagement.name + " | " + str(self.engagement.id)


class Testing_Guide_Category(models.Model):
    name = models.CharField(max_length=300)
    created = models.DateTimeField(null=False, editable=False, default=now)
    updated = models.DateTimeField(editable=False, default=now)

    class Meta:
        ordering = ('name',)

    def __unicode__(self):
        return self.name


class Testing_Guide(models.Model):
    testing_guide_category = models.ForeignKey(Testing_Guide_Category)
    identifier = models.CharField(max_length=20, blank=True, null=True, help_text="Test Unique Identifier")
    name = models.CharField(max_length=400, help_text="Name of the test")
    summary = models.CharField(max_length=800, help_text="Summary of the test")
    objective = models.CharField(max_length=800, help_text="Objective of the test")
    how_to_test = models.TextField(default=None, help_text="How to test the objective")
    results_expected = models.CharField(max_length=800, help_text="What the results look like for a test")
    created = models.DateTimeField(null=False, editable=False, default=now)
    updated = models.DateTimeField(editable=False, default=now)

    def __unicode__(self):
        return self.testing_guide_category.name + ': ' + self.name


class Benchmark_Type(models.Model):
    name = models.CharField(max_length=300)
    version = models.CharField(max_length=15)
    source = (('PCI', 'PCI'),
              ('OWASP ASVS', 'OWASP ASVS'),
              ('OWASP Mobile ASVS', 'OWASP Mobile ASVS'))
    benchmark_source = models.CharField(max_length=20, blank=False,
                                        null=True, choices=source,
                                        default='OWASP ASVS')
    created = models.DateTimeField(null=False, editable=False, default=now)
    updated = models.DateTimeField(editable=False, default=now)
    enabled = models.BooleanField(default=True)

    def __unicode__(self):
        return self.name + " " + self.version


class Benchmark_Category(models.Model):
    type = models.ForeignKey(Benchmark_Type, verbose_name='Benchmark Type')
    name = models.CharField(max_length=300)
    objective = models.TextField()
    references = models.TextField(blank=True, null=True)
    enabled = models.BooleanField(default=True)
    created = models.DateTimeField(null=False, editable=False, default=now)
    updated = models.DateTimeField(editable=False, default=now)

    class Meta:
        ordering = ('name',)

    def __unicode__(self):
        return self.name + ': ' + self.type.name


class Benchmark_Requirement(models.Model):
    category = models.ForeignKey(Benchmark_Category)
    objective_number = models.CharField(max_length=15, null=True)
    objective = models.TextField()
    references = models.TextField(blank=True, null=True)
    level_1 = models.BooleanField(default=False)
    level_2 = models.BooleanField(default=False)
    level_3 = models.BooleanField(default=False)
    enabled = models.BooleanField(default=True)
    cwe_mapping = models.ManyToManyField(CWE, blank=True)
    testing_guide = models.ManyToManyField(Testing_Guide, blank=True)
    created = models.DateTimeField(null=False, editable=False, default=now)
    updated = models.DateTimeField(editable=False, default=now)

    def __unicode__(self):
        return str(self.objective_number) + ': ' + self.category.name


class Benchmark_Product(models.Model):
    product = models.ForeignKey(Product)
    control = models.ForeignKey(Benchmark_Requirement)
    pass_fail = models.BooleanField(default=False, verbose_name='Pass',
                                    help_text='Does the product meet the requirement?')
    enabled = models.BooleanField(default=True,
                                  help_text='Applicable for this specific product.')
    notes = models.ManyToManyField(Notes, blank=True, editable=False)
    created = models.DateTimeField(null=False, editable=False, default=now)
    updated = models.DateTimeField(editable=False, default=now)

    def __unicode__(self):
        return self.product.name + ': ' + self.control.objective_number + ': ' + self.control.category.name

    class Meta:
        unique_together = [('product', 'control')]


class Benchmark_Product_Summary(models.Model):
    product = models.ForeignKey(Product)
    benchmark_type = models.ForeignKey(Benchmark_Type)
    asvs_level = (('Level 1', 'Level 1'),
                    ('Level 2', 'Level 2'),
                    ('Level 3', 'Level 3'))
    desired_level = models.CharField(max_length=15,
                                     null=False, choices=asvs_level,
                                     default='Level 1')
    current_level = models.CharField(max_length=15, blank=True,
                                     null=True, choices=asvs_level,
                                     default='None')
    asvs_level_1_benchmark = models.IntegerField(null=False, default=0, help_text="Total number of active benchmarks for this application.")
    asvs_level_1_score = models.IntegerField(null=False, default=0, help_text="ASVS Level 1 Score")
    asvs_level_2_benchmark = models.IntegerField(null=False, default=0, help_text="Total number of active benchmarks for this application.")
    asvs_level_2_score = models.IntegerField(null=False, default=0, help_text="ASVS Level 2 Score")
    asvs_level_3_benchmark = models.IntegerField(null=False, default=0, help_text="Total number of active benchmarks for this application.")
    asvs_level_3_score = models.IntegerField(null=False, default=0, help_text="ASVS Level 3 Score")
    publish = models.BooleanField(default=False, help_text='Publish score to Product.')
    created = models.DateTimeField(null=False, editable=False, default=now)
    updated = models.DateTimeField(editable=False, default=now)

    def __unicode__(self):
        return self.product.name + ': ' + self.benchmark_type.name

    class Meta:
        unique_together = [('product', 'benchmark_type')]


# Register for automatic logging to database
auditlog.register(Dojo_User)
auditlog.register(Endpoint)
auditlog.register(Engagement)
auditlog.register(Finding)
auditlog.register(Product)
auditlog.register(Test)
auditlog.register(Risk_Acceptance)
auditlog.register(Finding_Template)
auditlog.register(Cred_User)

# Register tagging for models
tag_register(Product)
tag_register(Test)
tag_register(Finding)
tag_register(Engagement)
tag_register(Endpoint)
tag_register(Finding_Template)
tag_register(App_Analysis)
tag_register(Objects)

# Benchmarks
admin.site.register(Benchmark_Type)
admin.site.register(Benchmark_Requirement)
admin.site.register(Benchmark_Category)
admin.site.register(Benchmark_Product)
admin.site.register(Benchmark_Product_Summary)

# Testing
admin.site.register(Testing_Guide_Category)
admin.site.register(Testing_Guide)

admin.site.register(Objects)
admin.site.register(Objects_Review)
admin.site.register(Objects_Engagement)
admin.site.register(Languages)
admin.site.register(Language_Type)
admin.site.register(App_Analysis)
admin.site.register(Test)
admin.site.register(Finding)
admin.site.register(FindingImage)
admin.site.register(FindingImageAccessToken)
admin.site.register(Stub_Finding)
admin.site.register(Engagement)
admin.site.register(Risk_Acceptance)
admin.site.register(Check_List)
admin.site.register(Test_Type)
admin.site.register(Endpoint)
admin.site.register(Product)
admin.site.register(Product_Type)
admin.site.register(Dojo_User)
admin.site.register(UserContactInfo)
admin.site.register(Notes)
admin.site.register(Report)
admin.site.register(Scan)
admin.site.register(ScanSettings)
admin.site.register(IPScan)
admin.site.register(Alerts)
admin.site.register(JIRA_Issue)
admin.site.register(JIRA_Conf)
admin.site.register(JIRA_PKey)
admin.site.register(Tool_Configuration)
admin.site.register(Tool_Product_Settings)
admin.site.register(Tool_Type)
admin.site.register(Cred_User)
admin.site.register(Cred_Mapping)
admin.site.register(System_Settings, System_SettingsAdmin)
admin.site.register(CWE)
admin.site.register(Regulation)

# Watson
watson.register(Product)
watson.register(Test)
watson.register(Finding)
watson.register(Finding_Template)
watson.register(Endpoint)
watson.register(Engagement)
watson.register(App_Analysis)
