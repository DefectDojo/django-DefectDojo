from dojo.models import Product, Engagement, Test, Finding, \
    User, ScanSettings, IPScan, Scan, Stub_Finding, Risk_Acceptance, \
    Finding_Template, Test_Type, Development_Environment, NoteHistory, \
    JIRA_Issue, Tool_Product_Settings, Tool_Configuration, Tool_Type, \
    Product_Type, JIRA_Conf, Endpoint, BurpRawRequestResponse, JIRA_PKey, \
    Notes, DojoMeta, FindingImage
from dojo.forms import ImportScanForm, SEVERITY_CHOICES
from dojo.tools import requires_file
from dojo.tools.factory import import_parser_factory
from dojo.utils import max_safe
from dojo.notifications.helper import create_notification
from django.urls import reverse
from tagging.models import Tag
from django.core.validators import URLValidator, validate_ipv46_address
from django.conf import settings
from rest_framework import serializers
from django.core.exceptions import ValidationError
from django.utils import timezone
import base64
import datetime
import six
from django.utils.translation import ugettext_lazy as _
import json


class TagList(list):
    def __init__(self, *args, **kwargs):
        pretty_print = kwargs.pop("pretty_print", True)
        list.__init__(self, *args, **kwargs)
        self.pretty_print = pretty_print

    def __add__(self, rhs):
        return TagList(list.__add__(self, rhs))

    def __getitem__(self, item):
        result = list.__getitem__(self, item)
        try:
            return TagList(result)
        except TypeError:
            return result

    def __str__(self):
        if self.pretty_print:
            return json.dumps(
                self, sort_keys=True, indent=4, separators=(',', ': '))
        else:
            return json.dumps(self)


class TagListSerializerField(serializers.ListField):
    child = serializers.CharField()
    default_error_messages = {
        'not_a_list': _(
            'Expected a list of items but got type "{input_type}".'),
        'invalid_json': _('Invalid json list. A tag list submitted in string'
                          ' form must be valid json.'),
        'not_a_str': _('All list items must be of string type.')
    }
    order_by = None

    def __init__(self, **kwargs):
        pretty_print = kwargs.pop("pretty_print", True)

        style = kwargs.pop("style", {})
        kwargs["style"] = {'base_template': 'textarea.html'}
        kwargs["style"].update(style)

        super(TagListSerializerField, self).__init__(**kwargs)

        self.pretty_print = pretty_print

    def to_internal_value(self, data):
        if isinstance(data, six.string_types):
            if not data:
                data = []
            try:
                data = json.loads(data)
            except ValueError:
                self.fail('invalid_json')

        if not isinstance(data, list):
            self.fail('not_a_list', input_type=type(data).__name__)

        for s in data:
            if not isinstance(s, six.string_types):
                self.fail('not_a_str')

            self.child.run_validation(s)

        return data

    def to_representation(self, value):
        if not isinstance(value, TagList):
            if not isinstance(value, list):
                # this will trigger when a queryset is found...
                if self.order_by:
                    tags = value.all().order_by(*self.order_by)
                else:
                    tags = value.all()
                value = [tag.name for tag in tags]
            elif len(value) > 0 and isinstance(value[0], Tag):
                # .. but sometimes the queryset already has been converted into a list, i.e. by prefetch_related
                tags = value
                value = [tag.name for tag in tags]
                if self.order_by:
                    # the only possible ordering is by name, so we order after creating the list
                    value = sorted(value)
            value = TagList(value, pretty_print=self.pretty_print)
        return value


class TaggitSerializer(serializers.Serializer):
    def create(self, validated_data):
        to_be_tagged, validated_data = self._pop_tags(validated_data)

        tag_object = super(TaggitSerializer, self).create(validated_data)

        return self._save_tags(tag_object, to_be_tagged)

    def update(self, instance, validated_data):
        to_be_tagged, validated_data = self._pop_tags(validated_data)

        tag_object = super(TaggitSerializer, self).update(
            instance, validated_data)

        return self._save_tags(tag_object, to_be_tagged)

    def _save_tags(self, tag_object, tags):
        for key in list(tags.keys()):
            tag_values = tags.get(key)
            tag_object.tags = ", ".join(tag_values)

        return tag_object

    def _pop_tags(self, validated_data):
        to_be_tagged = {}

        for key in list(self.fields.keys()):
            field = self.fields[key]
            if isinstance(field, TagListSerializerField):
                if key in validated_data:
                    to_be_tagged[key] = validated_data.pop(key)

        return (to_be_tagged, validated_data)


class MetaSerializer(serializers.ModelSerializer):
    product = serializers.PrimaryKeyRelatedField(queryset=Product.objects.all(),
                                                 required=False,
                                                 default=None,
                                                 allow_null=True)
    endpoint = serializers.PrimaryKeyRelatedField(queryset=Endpoint.objects.all(),
                                                  required=False,
                                                  default=None,
                                                  allow_null=True)

    def validate(self, data):
        DojoMeta(**data).clean()
        return data

    class Meta:
        model = DojoMeta
        fields = '__all__'


class ProductMetaSerializer(serializers.ModelSerializer):
    class Meta:
        model = DojoMeta
        fields = ('name', 'value')


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'first_name', 'last_name', 'last_login')


class ProductSerializer(TaggitSerializer, serializers.ModelSerializer):
    findings_count = serializers.SerializerMethodField()
    findings_list = serializers.SerializerMethodField()

    tags = TagListSerializerField(required=False)
    product_meta = ProductMetaSerializer(read_only=True, many=True)

    class Meta:
        model = Product
        exclude = ('tid', 'manager', 'prod_manager', 'tech_contact',
                   'updated')
        extra_kwargs = {
            'authorized_users': {'queryset': User.objects.exclude(is_staff=True).exclude(is_active=False)}
        }

    def get_findings_count(self, obj):
        return obj.findings_count

    def get_findings_list(self, obj):
        return obj.open_findings_list()


class ProductTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product_Type
        fields = '__all__'


class EngagementSerializer(TaggitSerializer, serializers.ModelSerializer):
    tags = TagListSerializerField(required=False)

    class Meta:
        model = Engagement
        fields = '__all__'

    def validate(self, data):
        if self.context['request'].method == 'POST':
            if data['target_start'] > data['target_end']:
                raise serializers.ValidationError(
                    'Your target start date exceeds your target end date')
        return data


class ToolTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tool_Type
        fields = '__all__'


class ToolConfigurationSerializer(serializers.ModelSerializer):
    configuration_url = serializers.CharField(source='url')

    class Meta:
        model = Tool_Configuration
        fields = '__all__'


class ToolProductSettingsSerializer(serializers.ModelSerializer):
    setting_url = serializers.CharField(source='url')

    class Meta:
        model = Tool_Product_Settings
        fields = '__all__'


class EndpointSerializer(TaggitSerializer, serializers.ModelSerializer):
    tags = TagListSerializerField(required=False)

    class Meta:
        model = Endpoint
        fields = '__all__'

    def validate(self, data):
        # print('EndpointSerialize.validate')
        port_re = "(:[0-9]{1,5}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}" \
                  "|655[0-2][0-9]|6553[0-5])"

        if not self.context['request'].method == 'PATCH':
            if ('host' not in data or
                    'protocol' not in data or
                    'path' not in data or
                    'query' not in data or
                    'fragment' not in data):
                raise serializers.ValidationError(
                    'Please provide valid host, protocol, path, query and '
                    'fragment')
            protocol = data['protocol']
            path = data['path']
            query = data['query']
            fragment = data['fragment']
            host = data['host']
        else:
            protocol = data.get('protocol', self.instance.protocol)
            path = data.get('path', self.instance.path)
            query = data.get('query', self.instance.query)
            fragment = data.get('fragment', self.instance.fragment)
            host = data.get('host', self.instance.host)
        product = data.get('product', None)

        from urllib.parse import urlunsplit
        if protocol:
            endpoint = urlunsplit((protocol, host, path, query, fragment))
        else:
            endpoint = host

        from django.core import exceptions
        from django.core.validators import RegexValidator
        import re
        try:
            url_validator = URLValidator()
            url_validator(endpoint)
        except exceptions.ValidationError:
            try:
                # do we have a port number?
                regex = re.compile(port_re)
                host = endpoint
                if regex.findall(endpoint):
                    for g in regex.findall(endpoint):
                        host = re.sub(port_re, '', host)
                validate_ipv46_address(host)
            except exceptions.ValidationError:
                try:
                    validate_hostname = RegexValidator(
                        regex=r'[a-zA-Z0-9-_]*\.[a-zA-Z]{2,6}')
                    # do we have a port number?
                    regex = re.compile(port_re)
                    host = endpoint
                    if regex.findall(endpoint):
                        for g in regex.findall(endpoint):
                            host = re.sub(port_re, '', host)
                    validate_hostname(host)
                except:  # noqa
                    raise serializers.ValidationError(
                        'It does not appear as though this endpoint is a '
                        'valid URL or IP address.',
                        code='invalid')

        endpoint = Endpoint.objects.filter(protocol=protocol,
                                           host=host,
                                           path=path,
                                           query=query,
                                           fragment=fragment,
                                           product=product)
        if endpoint.count() > 0 and not self.instance:
            raise serializers.ValidationError(
                'It appears as though an endpoint with this data already '
                'exists for this product.',
                code='invalid')

        return data


class JIRAIssueSerializer(serializers.ModelSerializer):
    class Meta:
        model = JIRA_Issue
        fields = '__all__'


class JIRAConfSerializer(serializers.ModelSerializer):
    class Meta:
        model = JIRA_Conf
        fields = '__all__'


class JIRASerializer(serializers.ModelSerializer):
    class Meta:
        model = JIRA_PKey
        fields = '__all__'


class DevelopmentEnvironmentSerializer(serializers.ModelSerializer):

    class Meta:
        model = Development_Environment
        fields = '__all__'


class TestSerializer(TaggitSerializer, serializers.ModelSerializer):
    tags = TagListSerializerField(required=False)
    test_type_name = serializers.ReadOnlyField()

    class Meta:
        model = Test
        fields = '__all__'


class TestCreateSerializer(TaggitSerializer, serializers.ModelSerializer):
    engagement = serializers.PrimaryKeyRelatedField(
        queryset=Engagement.objects.all())
    notes = serializers.PrimaryKeyRelatedField(
        allow_null=True,
        default=[],
        queryset=Notes.objects.all(),
        many=True)
    tags = TagListSerializerField(required=False)

    class Meta:
        model = Test
        fields = '__all__'


class TestTypeSerializer(TaggitSerializer, serializers.ModelSerializer):
    tags = TagListSerializerField(required=False)

    class Meta:
        model = Test_Type
        fields = '__all__'


class RiskAcceptanceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Risk_Acceptance
        fields = '__all__'


class FindingImageSerializer(serializers.ModelSerializer):
    base64 = serializers.SerializerMethodField()

    class Meta:
        model = FindingImage
        fields = ["base64", "caption", "id"]

    def get_base64(self, obj):
        return base64.b64encode(obj.image.read())


class FindingSerializer(TaggitSerializer, serializers.ModelSerializer):
    images = FindingImageSerializer(many=True, read_only=True)
    tags = TagListSerializerField(required=False)
    accepted_risks = RiskAcceptanceSerializer(many=True, read_only=True, source='risk_acceptance_set')
    push_to_jira = serializers.BooleanField(default=False)

    class Meta:
        model = Finding
        fields = '__all__'

    def validate(self, data):
        if self.context['request'].method == 'PATCH':
            is_active = data.get('active', self.instance.active)
            is_verified = data.get('verified', self.instance.verified)
            is_duplicate = data.get('duplicate', self.instance.duplicate)
            is_false_p = data.get('false_p', self.instance.false_p)
        else:
            is_active = data.get('active', True)
            is_verified = data.get('verified', True)
            is_duplicate = data.get('duplicate', False)
            is_false_p = data.get('false_p', False)
        if ((is_active or is_verified) and is_duplicate):
            raise serializers.ValidationError('Duplicate findings cannot be'
                                              ' verified or active')
        if is_false_p and is_verified:
            raise serializers.ValidationError('False positive findings cannot '
                                              'be verified.')
        return data

    def build_relational_field(self, field_name, relation_info):
        if field_name == 'notes':
            return NoteSerializer, {'many': True, 'read_only': True}
        return super().build_relational_field(field_name, relation_info)


class FindingCreateSerializer(TaggitSerializer, serializers.ModelSerializer):
    notes = serializers.PrimaryKeyRelatedField(
        read_only=True,
        allow_null=True,
        default=[],
        many=True)
    test = serializers.PrimaryKeyRelatedField(
        queryset=Test.objects.all())
    thread_id = serializers.IntegerField(default=0)
    found_by = serializers.PrimaryKeyRelatedField(
        queryset=Test_Type.objects.all(),
        many=True)
    url = serializers.CharField(
        allow_null=True,
        default=None)
    tags = TagListSerializerField(required=False)
    push_to_jira = serializers.BooleanField(default=False)

    class Meta:
        model = Finding
        exclude = ['images']
        extra_kwargs = {
            'reporter': {'default': serializers.CurrentUserDefault()},
        }

    # Overriding this to push add Push to JIRA functionality
    def create(self, validated_data):
        to_be_tagged, validated_data = self._pop_tags(validated_data)
        push_to_jira = validated_data.pop('push_to_jira')
        # Somewhere in the below line finding.save() is called, but I'm not sure how to get
        # push_to_jira to it.
        tag_object = super(TaggitSerializer, self).create(validated_data)

        has_jira_config = tag_object.test.engagement.product.jira_pkey_set.first() is not None
        if not push_to_jira and has_jira_config:
            push_to_jira = tag_object.test.engagement.product.jira_pkey_set.first().push_all_issues

        # No need to save the finding twice if we're not pushing to JIRA
        if push_to_jira:
            # Saving again with push_to_jira context
            tag_object.save(push_to_jira=push_to_jira)
        return self._save_tags(tag_object, to_be_tagged)
        pass

    def validate(self, data):
        if ((data['active'] or data['verified']) and data['duplicate']):
            raise serializers.ValidationError('Duplicate findings cannot be'
                                              ' verified or active')
        if data['false_p'] and data['verified']:
            raise serializers.ValidationError('False positive findings cannot '
                                              'be verified.')
        return data


class FindingTemplateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Finding_Template
        fields = '__all__'


class StubFindingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Stub_Finding
        fields = '__all__'


class StubFindingCreateSerializer(serializers.ModelSerializer):
    test = serializers.PrimaryKeyRelatedField(
        queryset=Test.objects.all())

    class Meta:
        model = Stub_Finding
        fields = '__all__'
        extra_kwargs = {
            'reporter': {'default': serializers.CurrentUserDefault()},
        }


class ScanSettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanSettings
        fields = '__all__'


class ScanSettingsCreateSerializer(serializers.ModelSerializer):
    user = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all())
    product = serializers.PrimaryKeyRelatedField(
        queryset=Product.objects.all())
    data = serializers.DateTimeField(required=False)

    class Meta:
        model = ScanSettings
        fields = '__all__'


class IPScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = IPScan
        fields = '__all__'


class ScanSerializer(serializers.ModelSerializer):
    # scan_settings_link = serializers.PrimaryKeyRelatedField(
    #     read_only=True,
    #     source='scan_settings')
    # scan_settings = serializers.PrimaryKeyRelatedField(
    #     queryset=ScanSettings.objects.all(),
    #     write_only=True,
    #     )
    # ipscan_links = serializers.PrimaryKeyRelatedField(
    #     read_only=True,
    #     many=True,
    #     source='ipscan_set')

    class Meta:
        model = Scan
        fields = '__all__'


class ImportScanSerializer(TaggitSerializer, serializers.Serializer):
    scan_date = serializers.DateField(default=datetime.date.today)

    minimum_severity = serializers.ChoiceField(
        choices=SEVERITY_CHOICES,
        default='Info')
    active = serializers.BooleanField(default=True)
    verified = serializers.BooleanField(default=True)
    scan_type = serializers.ChoiceField(
        choices=ImportScanForm.SCAN_TYPE_CHOICES)
    endpoint_to_add = serializers.PrimaryKeyRelatedField(queryset=Endpoint.objects.all(),
                                                         required=False,
                                                         default=None)
    test_type = serializers.CharField(required=False)
    file = serializers.FileField(required=False)
    engagement = serializers.PrimaryKeyRelatedField(
        queryset=Engagement.objects.all())
    lead = serializers.PrimaryKeyRelatedField(
        allow_null=True,
        default=None,
        queryset=User.objects.all())
    tags = TagListSerializerField(required=False)
    close_old_findings = serializers.BooleanField(required=False, default=False)
    push_to_jira = serializers.BooleanField(default=False)

    def save(self, push_to_jira=False):
        data = self.validated_data
        close_old_findings = data['close_old_findings']
        active = data['active']
        verified = data['verified']
        test_type, created = Test_Type.objects.get_or_create(
            name=data.get('test_type', data['scan_type']))
        endpoint_to_add = data['endpoint_to_add']
        environment, created = Development_Environment.objects.get_or_create(
            name='Development')
        scan_date = data['scan_date']
        scan_date_time = datetime.datetime.combine(scan_date, timezone.now().time())
        if settings.USE_TZ:
            scan_date_time = timezone.make_aware(scan_date_time, timezone.get_default_timezone())

        test = Test(
            engagement=data['engagement'],
            lead=data['lead'],
            test_type=test_type,
            target_start=data['scan_date'],
            target_end=data['scan_date'],
            environment=environment,
            percent_complete=100)
        try:
            test.full_clean()
        except ValidationError:
            pass

        test.save()
        # return the id of the created test, can't find a better way because this is not a ModelSerializer....
        self.fields['test'] = serializers.IntegerField(read_only=True, default=test.id)

        test.engagement.updated = max_safe([scan_date_time, test.engagement.updated])

        if test.engagement.engagement_type == 'CI/CD':
            test.engagement.target_end = max_safe([scan_date, test.engagement.target_end])

        test.engagement.save()

        if 'tags' in data:
            test.tags = ' '.join(data['tags'])
        try:
            parser = import_parser_factory(data.get('file'),
                                           test,
                                           active,
                                           verified,
                                           data['scan_type'],)
        except ValueError:
            raise Exception('FileParser ValueError')

        new_findings = []
        skipped_hashcodes = []
        try:
            for item in parser.items:
                sev = item.severity
                if sev == 'Information' or sev == 'Informational':
                    sev = 'Info'

                item.severity = sev

                if (Finding.SEVERITIES[sev] >
                        Finding.SEVERITIES[data['minimum_severity']]):
                    continue

                item.test = test
                item.date = test.target_start
                item.reporter = self.context['request'].user
                item.last_reviewed = timezone.now()
                item.last_reviewed_by = self.context['request'].user
                item.active = data['active']
                item.verified = data['verified']
                item.save(dedupe_option=False)

                if (hasattr(item, 'unsaved_req_resp') and
                        len(item.unsaved_req_resp) > 0):
                    for req_resp in item.unsaved_req_resp:
                        burp_rr = BurpRawRequestResponse(
                            finding=item,
                            burpRequestBase64=req_resp["req"],
                            burpResponseBase64=req_resp["resp"])
                        burp_rr.clean()
                        burp_rr.save()

                if (item.unsaved_request is not None and
                        item.unsaved_response is not None):
                    burp_rr = BurpRawRequestResponse(
                        finding=item,
                        burpRequestBase64=item.unsaved_request,
                        burpResponseBase64=item.unsaved_response)
                    burp_rr.clean()
                    burp_rr.save()

                for endpoint in item.unsaved_endpoints:
                    ep, created = Endpoint.objects.get_or_create(
                        protocol=endpoint.protocol,
                        host=endpoint.host,
                        path=endpoint.path,
                        query=endpoint.query,
                        fragment=endpoint.fragment,
                        product=test.engagement.product)

                    item.endpoints.add(ep)

                if endpoint_to_add:
                    item.endpoints.add(endpoint_to_add)

                if item.unsaved_tags is not None:
                    item.tags = item.unsaved_tags

                item.save(push_to_jira=push_to_jira)
                new_findings.append(item)

        except SyntaxError:
            raise Exception('Parser SyntaxError')

        old_findings = []
        if close_old_findings:
            # Close old active findings that are not reported by this scan.
            new_hash_codes = test.finding_set.values('hash_code')

            if test.engagement.deduplication_on_engagement:
                old_findings = Finding.objects.exclude(test=test) \
                                              .exclude(hash_code__in=new_hash_codes) \
                                              .exclude(hash_code__in=skipped_hashcodes) \
                                              .filter(test__engagement=test.engagement,
                                                  test__test_type=test_type,
                                                  active=True)
            else:
                old_findings = Finding.objects.exclude(test=test) \
                                              .exclude(hash_code__in=new_hash_codes) \
                                              .exclude(hash_code__in=skipped_hashcodes) \
                                              .filter(test__engagement__product=test.engagement.product,
                                                  test__test_type=test_type,
                                                  active=True)

            for old_finding in old_findings:
                old_finding.active = False
                old_finding.mitigated = datetime.datetime.combine(
                    test.target_start,
                    timezone.now().time())
                if settings.USE_TZ:
                    old_finding.mitigated = timezone.make_aware(
                        old_finding.mitigated,
                        timezone.get_default_timezone())
                old_finding.mitigated_by = self.context['request'].user
                old_finding.notes.create(author=self.context['request'].user,
                                         entry="This finding has been automatically closed"
                                         " as it is not present anymore in recent scans.")
                Tag.objects.add_tag(old_finding, 'stale')
                old_finding.save()

        title = 'Test created for ' + str(test.engagement.product) + ': ' + str(test.engagement.name) + ': ' + str(test)
        create_notification(event='test_added', title=title, test=test, engagement=test.engagement, product=test.engagement.product,
                            url=reverse('view_test', args=(test.id,)))

        updated_count = len(new_findings) + len(old_findings)
        if updated_count > 0:
            title = 'Created ' + str(updated_count) + " findings for " + str(test.engagement.product) + ': ' + str(test.engagement.name) + ': ' + str(test)
            create_notification(initiator=self.context['request'].user, event='scan_added', title=title, findings_new=new_findings, findings_mitigated=old_findings,
                                finding_count=updated_count, test=test, engagement=test.engagement, product=test.engagement.product,
                                url=reverse('view_test', args=(test.id,)))

        return test

    def validate(self, data):
        scan_type = data.get("scan_type")
        file = data.get("file")
        if not file and requires_file(scan_type):
            raise serializers.ValidationError('Uploading a Report File is required for {}'.format(scan_type))
        return data

    def validate_scan_data(self, value):
        if value.date() > datetime.today().date():
            raise serializers.ValidationError(
                'The date cannot be in the future!')
        return value


class ReImportScanSerializer(TaggitSerializer, serializers.Serializer):
    scan_date = serializers.DateField()
    minimum_severity = serializers.ChoiceField(
        choices=SEVERITY_CHOICES,
        default='Info')
    active = serializers.BooleanField(default=True)
    verified = serializers.BooleanField(default=True)
    scan_type = serializers.ChoiceField(
        choices=ImportScanForm.SCAN_TYPE_CHOICES)
    endpoint_to_add = serializers.PrimaryKeyRelatedField(queryset=Endpoint.objects.all(),
                                                          default=None,
                                                          required=False)
    file = serializers.FileField(required=False)
    test = serializers.PrimaryKeyRelatedField(
        queryset=Test.objects.all())
    push_to_jira = serializers.BooleanField(default=False)

    def save(self, push_to_jira=False):
        data = self.validated_data
        test = data['test']
        scan_type = data['scan_type']
        endpoint_to_add = data['endpoint_to_add']
        min_sev = data['minimum_severity']
        scan_date = data['scan_date']
        scan_date_time = datetime.datetime.combine(scan_date, timezone.now().time())
        if settings.USE_TZ:
            scan_date_time = timezone.make_aware(scan_date_time, timezone.get_default_timezone())
        verified = data['verified']
        active = data['active']

        try:
            parser = import_parser_factory(data.get('file'),
                                           test,
                                           active,
                                           verified,
                                           data['scan_type'],)
        except ValueError:
            raise Exception("Parser ValueError")

        try:
            items = parser.items
            original_items = list(test.finding_set.all())
            new_items = []
            mitigated_count = 0
            finding_count = 0
            finding_added_count = 0
            reactivated_count = 0
            reactivated_items = []
            unchanged_count = 0
            unchanged_items = []

            for item in items:
                sev = item.severity
                if sev == 'Information' or sev == 'Informational':
                    sev = 'Info'

                if (Finding.SEVERITIES[sev] >
                        Finding.SEVERITIES[min_sev]):
                    continue

                if scan_type == 'Veracode Scan' or scan_type == 'Arachni Scan':
                    findings = Finding.objects.filter(
                        title=item.title,
                        test=test,
                        severity=sev,
                        numerical_severity=Finding.get_numerical_severity(sev),
                        description=item.description).all()
                else:
                    findings = Finding.objects.filter(
                        title=item.title,
                        test=test,
                        severity=sev,
                        numerical_severity=Finding.get_numerical_severity(sev)).all()

                if findings:
                    # existing finding found
                    finding = findings[0]
                    if finding.mitigated or finding.is_Mitigated:
                        finding.mitigated = None
                        finding.is_Mitigated = False
                        finding.mitigated_by = None
                        finding.active = True
                        finding.verified = verified
                        finding.save()
                        note = Notes(
                            entry="Re-activated by %s re-upload." % scan_type,
                            author=self.context['request'].user)
                        note.save()
                        finding.notes.add(note)
                        reactivated_items.append(finding)
                        reactivated_count += 1
                    else:
                        unchanged_items.append(finding)
                        unchanged_count += 1
                else:
                    # no existing finding found
                    item.test = test
                    item.date = scan_date
                    item.reporter = self.context['request'].user
                    item.last_reviewed = timezone.now()
                    item.last_reviewed_by = self.context['request'].user
                    item.verified = verified
                    item.active = active
                    item.save(dedupe_option=False)
                    finding_added_count += 1
                    new_items.append(item)
                    finding = item

                    if hasattr(item, 'unsaved_req_resp'):
                        for req_resp in item.unsaved_req_resp:
                            burp_rr = BurpRawRequestResponse(
                                finding=finding,
                                burpRequestBase64=req_resp['req'],
                                burpResponseBase64=req_resp['resp'])
                            burp_rr.clean()
                            burp_rr.save()

                    if item.unsaved_request and item.unsaved_response:
                        burp_rr = BurpRawRequestResponse(
                            finding=finding,
                            burpRequestBase64=item.unsaved_request,
                            burpResponseBase64=item.unsaved_response)
                        burp_rr.clean()
                        burp_rr.save()

                if finding:
                    finding_count += 1
                    for endpoint in item.unsaved_endpoints:
                        ep, created = Endpoint.objects.get_or_create(
                            protocol=endpoint.protocol,
                            host=endpoint.host,
                            path=endpoint.path,
                            query=endpoint.query,
                            fragment=endpoint.fragment,
                            product=test.engagement.product)
                        finding.endpoints.add(ep)
                    if endpoint_to_add:
                        finding.endpoints.add(endpoint_to_add)
                    if item.unsaved_tags:
                        finding.tags = item.unsaved_tags

                    finding.save(push_to_jira=push_to_jira)

            to_mitigate = set(original_items) - set(reactivated_items) - set(unchanged_items)
            mitigated_findings = []
            for finding in to_mitigate:
                if not finding.mitigated or not finding.is_Mitigated:
                    finding.mitigated = scan_date_time
                    finding.is_Mitigated = True
                    finding.mitigated_by = self.context['request'].user
                    finding.active = False
                    finding.save(push_to_jira=push_to_jira)
                    note = Notes(entry="Mitigated by %s re-upload." % scan_type,
                                author=self.context['request'].user)
                    note.save()
                    finding.notes.add(note)
                    mitigated_findings.append(finding)
                    mitigated_count += 1

            untouched = set(unchanged_items) - set(to_mitigate)

            test.updated = max_safe([scan_date_time, test.updated])
            test.engagement.updated = max_safe([scan_date_time, test.engagement.updated])

            if test.engagement.engagement_type == 'CI/CD':
                test.target_end = max_safe([scan_date_time, test.target_end])
                test.engagement.target_end = max_safe([scan_date, test.engagement.target_end])

            test.save()
            test.engagement.save()

            print(len(new_items))
            print(reactivated_count)
            print(mitigated_count)
            print(unchanged_count - mitigated_count)

            updated_count = mitigated_count + reactivated_count + len(new_items)
            if updated_count > 0:
                # new_items = original_items
                title = 'Updated ' + str(updated_count) + " findings for " + str(test.engagement.product) + ': ' + str(test.engagement.name) + ': ' + str(test)
                create_notification(initiator=self.context['request'].user, event='scan_added', title=title, findings_new=new_items, findings_mitigated=mitigated_findings, findings_reactivated=reactivated_items,
                                    finding_count=updated_count, test=test, engagement=test.engagement, product=test.engagement.product, findings_untouched=untouched,
                                    url=reverse('view_test', args=(test.id,)))

        except SyntaxError:
            raise Exception("Parser SyntaxError")

        return test

    def validate(self, data):
        scan_type = data.get("scan_type")
        file = data.get("file")
        if not file and requires_file(scan_type):
            raise serializers.ValidationError('Uploading a Report File is required for {}'.format(scan_type))
        return data

    def validate_scan_data(self, value):
        if value.date() > datetime.today().date():
            raise serializers.ValidationError(
                'The date cannot be in the future!')
        return value


class NoteHistorySerializer(serializers.ModelSerializer):
    current_editor = UserSerializer(read_only=True)

    class Meta:
        model = NoteHistory
        fields = '__all__'


class NoteSerializer(serializers.ModelSerializer):
    author = UserSerializer(
        many=False, read_only=False)
    editor = UserSerializer(
        read_only=False, many=False, allow_null=True)

    history = NoteHistorySerializer(read_only=True, many=True)

    class Meta:
        model = Notes
        fields = '__all__'


class AddNewNoteOptionSerializer(serializers.ModelSerializer):

    class Meta:
        model = Notes
        fields = ['entry', 'private', 'note_type']


class FindingToFindingImagesSerializer(serializers.Serializer):
    finding_id = serializers.PrimaryKeyRelatedField(queryset=Finding.objects.all(), many=False, allow_null=True)
    images = FindingImageSerializer(many=True)


class FindingToNotesSerializer(serializers.Serializer):
    finding_id = serializers.PrimaryKeyRelatedField(queryset=Finding.objects.all(), many=False, allow_null=True)
    notes = NoteSerializer(many=True)


class ReportGenerateOptionSerializer(serializers.Serializer):
    include_finding_notes = serializers.BooleanField(default=False)
    include_finding_images = serializers.BooleanField(default=False)
    include_executive_summary = serializers.BooleanField(default=False)
    include_table_of_contents = serializers.BooleanField(default=False)


class ExecutiveSummarySerializer(serializers.Serializer):
    engagement_name = serializers.CharField(max_length=200)
    engagement_target_start = serializers.DateField()
    engagement_target_end = serializers.DateField()
    test_type_name = serializers.CharField(max_length=200)
    test_target_start = serializers.DateTimeField()
    test_target_end = serializers.DateTimeField()
    test_environment_name = serializers.CharField(max_length=200)
    test_strategy_ref = serializers.URLField(max_length=200, min_length=None, allow_blank=True)
    total_findings = serializers.IntegerField()


class ReportGenerateSerializer(serializers.Serializer):
    executive_summary = ExecutiveSummarySerializer(many=False, allow_null=True)
    product_type = ProductTypeSerializer(many=False, read_only=True)
    product = ProductSerializer(many=False, read_only=True)
    engagement = EngagementSerializer(many=False, read_only=True)
    report_name = serializers.CharField(max_length=200)
    report_info = serializers.CharField(max_length=200)
    test = TestSerializer(many=False, read_only=True)
    endpoint = EndpointSerializer(many=False, read_only=True)
    endpoints = EndpointSerializer(many=True, read_only=True)
    findings = FindingSerializer(many=True, read_only=True)
    user = UserSerializer(many=False, read_only=True)
    team_name = serializers.CharField(max_length=200)
    title = serializers.CharField(max_length=200)
    user_id = serializers.IntegerField()
    host = serializers.CharField(max_length=200)
    finding_images = FindingToFindingImagesSerializer(many=True, allow_null=True)
    finding_notes = FindingToNotesSerializer(many=True, allow_null=True)


class TagSerializer(serializers.Serializer):
    tags = TagListSerializerField(required=True)
