from datetime import datetime
import os
from django.conf import settings
from django.contrib import admin
from django.contrib.auth.models import User
from django.core.urlresolvers import reverse
from django.db import models
from django.db.models import Q
from django.utils.timezone import now
from pytz import timezone
from auditlog.registry import auditlog
import watson

localtz = timezone(settings.TIME_ZONE)


def get_current_date():
    return localtz.normalize(now()).date()


def get_current_datetime():
    return localtz.normalize(now())


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


class Contact(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    team = models.CharField(max_length=100)
    is_admin = models.BooleanField(default=False)
    is_globally_read_only = models.BooleanField(default=False)
    updated = models.DateTimeField(editable=False)


class Product_Type(models.Model):
    name = models.CharField(max_length=300)

    def findings_count(self):
        return Finding.objects.filter(mitigated__isnull=True,
                                      verified=True,
                                      false_p=False,
                                      duplicate=False,
                                      out_of_scope=False,
                                      test__engagement__product__prod_type=self).filter(Q(severity="Critical") |
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
    name = models.CharField(max_length=300)


class Test_Type(models.Model):
    name = models.CharField(max_length=200)

    def __unicode__(self):
        return self.name

    def get_breadcrumbs(self):
        bc = [{'title': self.__unicode__(),
               'url': None}]
        return bc


class Product(models.Model):
    name = models.CharField(max_length=300)
    description = models.CharField(max_length=2000)
    prod_manager = models.CharField(default=0, max_length=200)
    tech_contact = models.CharField(default=0, max_length=200)
    manager = models.CharField(default=0, max_length=200)
    created = models.DateTimeField(editable=False, null=True, blank=True)
    prod_type = models.ForeignKey(Product_Type, related_name='prod_type',
                                  null=True, blank=True)
    updated = models.DateTimeField(editable=False, null=True, blank=True)
    tid = models.IntegerField(default=0, editable=False)
    authorized_users = models.ManyToManyField(User, blank=True)

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
    def endpoint_count(self):
        endpoints = Endpoint.objects.filter(finding__test__engagement__product=self,
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
                'url': reverse('view_scan_settings', args=(self.product.id, self.id,))}]
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


class Endpoint(models.Model):
    protocol = models.CharField(null=True, blank=True, max_length=10,
                                help_text="The communication protocl such as 'http', 'ftp', etc.")
    host = models.CharField(null=True, blank=True, max_length=500,
                            help_text="The host name or IP address, you can also include the port number. For example"
                                      "'127.0.0.1', '127.0.0.1:8080', 'localhost', 'yourdomain.com'.")
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

    class Meta:
        ordering = ['product', 'protocol', 'host', 'path', 'query', 'fragment']

    def __unicode__(self):
        from urlparse import uses_netloc

        netloc = self.host
        scheme = self.protocol
        url = self.path if self.path else ''
        query = self.query
        fragment = self.fragment

        if netloc or (scheme and scheme in uses_netloc and url[:2] != '//'):
            if url and url[:1] != '/': url = '/' + url
            if scheme:
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
        return Finding.objects.filter(endpoints__in=[self],
                                      active=True,
                                      verified=True,
                                      mitigated__isnull=True,
                                      false_p=False,
                                      duplicate=False,
                                      is_template=False).order_by('numerical_severity')

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
        return [{"title": self.__unicode__(), "url": reverse("edit_dev_env", args=(self.id,))}]


class Test(models.Model):
    engagement = models.ForeignKey(Engagement, editable=False)
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
    references = models.TextField(null=True, blank=True, db_column="refs")
    test = models.ForeignKey(Test, editable=False)
    is_template = models.BooleanField(default=False)
    active = models.BooleanField(default=True)
    verified = models.BooleanField(default=True)
    false_p = models.BooleanField(default=False, verbose_name="False Positive")
    duplicate = models.BooleanField(default=False)
    out_of_scope = models.BooleanField(default=False)
    thread_id = models.IntegerField(default=0, editable=False)
    mitigated = models.DateTimeField(editable=False, null=True, blank=True)
    mitigated_by = models.ForeignKey(User, null=True, editable=False, related_name="mitigated_by")
    reporter = models.ForeignKey(User, editable=False, related_name='reporter')
    notes = models.ManyToManyField(Notes, blank=True,
                                   editable=False)
    numerical_severity = models.CharField(max_length=4)
    last_reviewed = models.DateTimeField(null=True, editable=False)
    last_reviewed_by = models.ForeignKey(User, null=True, editable=False, related_name='last_reviewed_by')

    SEVERITIES = {'Info': 4, 'Low': 3, 'Medium': 2,
                  'High': 1, 'Critical': 0}

    class Meta:
        ordering = ('numerical_severity', '-date', 'title')

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
            days = (self.mitigated.date() - localtz.localize(datetime.combine(self.date,
                                                                              datetime.min.time())).date()).days
        else:
            days = (get_current_date() - localtz.localize(datetime.combine(self.date, datetime.min.time())).date()).days

        return days if days > 0 else 0

    def long_desc(self):
        long_desc = ''
        long_desc += '=== ' + self.title + ' ===\n\n'
        long_desc += '*Severity:* ' + self.severity + '\n\n'
        long_desc += '*Systems*: \n'
        for e in self.endpoints.all():
            long_desc += str(e) + '\n\n'
        long_desc += '*Description*: \n' + self.description + '\n\n'
        long_desc += '*Impact*: \n' + self.impact + '\n\n'
        long_desc += '*References*:' + self.references
        return long_desc

    def clean(self):
        no_check = ["test", "reporter"]
        bigfields = ["description", "mitigation", "references", "impact",
                     "endpoint", "url"]
        for field_obj in self._meta.fields:
            field = field_obj.name
            if field not in no_check:
                val = getattr(self, field)
                if not val and field == "title":
                    setattr(self, field, "No title given")
                if not val and field in bigfields:
                    setattr(self, field, "No %s given" % field)

    def get_breadcrumbs(self):
        bc = self.test.get_breadcrumbs()
        bc += [{'title': self.__unicode__(),
                'url': reverse('view_finding', args=(self.id,))}]
        return bc


class Stub_Finding(models.Model):
    title = models.TextField(max_length=1000, blank=False, null=False)
    date = models.DateField(default=get_current_date, blank=False, null=False)
    severity = models.CharField(max_length=200, blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    test = models.ForeignKey(Test, editable=False)
    reporter = models.ForeignKey(User, editable=False)

    def __unicode__(self):
        return self.title

    def get_breadcrumbs(self):
        bc = self.test.get_breadcrumbs()
        bc += [{'title': "Potential Finding: " + self.__unicode__(),
                'url': reverse('view_potential_finding', args=(self.id,))}]
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
                'url': reverse('complete_checklist', args=(self.engagement.id,))}]
        return bc


class BurpRawRequestResponse(models.Model):
    finding = models.ForeignKey(Finding, blank=True, null=True)
    burpRequestBase64 = models.BinaryField()
    burpResponseBase64 = models.BinaryField()


class Risk_Acceptance(models.Model):
    path = models.FileField(upload_to='risk/%Y/%m/%d',
                            editable=False, null=False,
                            blank=False, verbose_name="Risk Acceptance File")
    accepted_findings = models.ManyToManyField(Finding, null=False)
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
                'url': reverse('view_risk', args=(self.engagement_set.first().product.id, self.id,))}]
        return bc


# Register for automatic logging to database
auditlog.register(Dojo_User)
auditlog.register(Endpoint)
auditlog.register(Engagement)
auditlog.register(Finding)
auditlog.register(Product)
auditlog.register(Test)
auditlog.register(Risk_Acceptance)

admin.site.register(Test)
admin.site.register(Finding)
admin.site.register(Stub_Finding)
admin.site.register(Engagement)
admin.site.register(Risk_Acceptance)
admin.site.register(Check_List)
admin.site.register(Test_Type)
admin.site.register(Endpoint)
admin.site.register(Product)
admin.site.register(Dojo_User)
admin.site.register(Notes)
admin.site.register(Scan)
admin.site.register(ScanSettings)

watson.register(Product)
watson.register(Test)
watson.register(Finding)
