from dojo.models import Product, Engagement_Type, Engagement, Test, Finding, \
    User, ScanSettings, IPScan, Scan, Stub_Finding, Risk_Acceptance, \
    Finding_Template, Test_Type, Development_Environment, Report_Type, \
    JIRA_Issue, Tool_Product_Settings, Tool_Configuration, Tool_Type, \
    Product_Type, JIRA_Conf, Endpoint, BurpRawRequestResponse, JIRA_PKey, \
    Notes, Dojo_User, Regulation
from dojo.forms import ImportScanForm, SEVERITY_CHOICES
from dojo.tools.factory import import_parser_factory
from django.core.validators import URLValidator, validate_ipv46_address
from rest_framework import serializers
from django.core.exceptions import ValidationError
from django.utils import timezone
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

    def to_internal_value(self, value):
        if isinstance(value, six.string_types):
            if not value:
                value = "[]"
            try:
                value = json.loads(value)
            except ValueError:
                self.fail('invalid_json')

        if not isinstance(value, list):
            self.fail('not_a_list', input_type=type(value).__name__)

        for s in value:
            if not isinstance(s, six.string_types):
                self.fail('not_a_str')

            self.child.run_validation(s)

        return value

    def to_representation(self, value):
        if not isinstance(value, TagList):
            if not isinstance(value, list):
                if self.order_by:
                    tags = value.all().order_by(*self.order_by)
                else:
                    tags = value.all()
                value = [tag.name for tag in tags]
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
        for key in tags.keys():
            tag_values = tags.get(key)
            tag_object.tags = ", ".join(tag_values)

        return tag_object

    def _pop_tags(self, validated_data):
        to_be_tagged = {}

        for key in self.fields.keys():
            field = self.fields[key]
            if isinstance(field, TagListSerializerField):
                if key in validated_data:
                    to_be_tagged[key] = validated_data.pop(key)

        return (to_be_tagged, validated_data)


class UserSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        fields = ('url', 'username', 'first_name', 'last_name', 'last_login')


class ProductSerializer(TaggitSerializer, serializers.HyperlinkedModelSerializer):
    findings_count = serializers.SerializerMethodField()
    product_manager = serializers.HyperlinkedRelatedField(
        queryset=User.objects.all(),
        view_name='user-detail',
        format='html', required=False)
    technical_contact = serializers.HyperlinkedRelatedField(
        queryset=User.objects.all(),
        view_name='user-detail',
        format='html', required=False)
    team_manager = serializers.HyperlinkedRelatedField(
        queryset=User.objects.all(),
        view_name='user-detail',
        format='html', required=False)
    authorized_users = serializers.HyperlinkedRelatedField(
        many=True,
        queryset=User.objects.exclude(is_staff=True).exclude(is_active=False),
        view_name='user-detail',
        format='html', required=False)
    prod_type = serializers.PrimaryKeyRelatedField(
        queryset=Product_Type.objects.all())
    regulations = serializers.PrimaryKeyRelatedField(
        queryset=Regulation.objects.all(), many=True, required=False)
    tags = TagListSerializerField(required=False)

    class Meta:
        model = Product
        exclude = ('tid', 'manager', 'prod_manager', 'tech_contact',
                   'updated')

    def get_findings_count(self, obj):
        return obj.findings_count


class EngagementSerializer(TaggitSerializer, serializers.HyperlinkedModelSerializer):
    eng_type = serializers.PrimaryKeyRelatedField(
        queryset=Engagement_Type.objects.all(), required=False)
    report_type = serializers.PrimaryKeyRelatedField(
        queryset=Report_Type.objects.all(), required=False)
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


class ToolTypeSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Tool_Type
        fields = '__all__'


class ToolConfigurationSerializer(serializers.HyperlinkedModelSerializer):
    configuration_url = serializers.CharField(source='url')
    url = serializers.HyperlinkedIdentityField(
        view_name='tool_configuration-detail')

    class Meta:
        model = Tool_Configuration
        fields = '__all__'


class ToolProductSettingsSerializer(serializers.HyperlinkedModelSerializer):
    setting_url = serializers.CharField(source='url')
    url = serializers.HyperlinkedIdentityField(
        view_name='tool_product_settings-detail')

    class Meta:
        model = Tool_Product_Settings
        fields = '__all__'


class EndpointSerializer(TaggitSerializer, serializers.HyperlinkedModelSerializer):
    tags = TagListSerializerField(required=False)

    class Meta:
        model = Endpoint
        fields = '__all__'

    def validate(self, data):
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

        from urlparse import urlunsplit
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


class JIRAIssueSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = JIRA_Issue
        fields = '__all__'


class JIRAConfSerializer(serializers.HyperlinkedModelSerializer):
    url = serializers.HyperlinkedIdentityField(
        view_name='jira_conf-detail')
    jira_url = serializers.CharField(
        source='url')

    class Meta:
        model = JIRA_Conf
        fields = '__all__'


class JIRASerializer(serializers.HyperlinkedModelSerializer):

    class Meta:
        model = JIRA_PKey
        fields = '__all__'


class TestSerializer(TaggitSerializer, serializers.HyperlinkedModelSerializer):
    engagement = serializers.HyperlinkedRelatedField(
        read_only=True,
        view_name='engagement-detail',
        format='html')
    test_type = serializers.PrimaryKeyRelatedField(
        queryset=Test_Type.objects.all())
    environment = serializers.PrimaryKeyRelatedField(
        queryset=Development_Environment.objects.all())
    notes = serializers.PrimaryKeyRelatedField(
        queryset=Notes.objects.all(),
        many=True)
    tags = TagListSerializerField(required=False)

    class Meta:
        model = Test
        fields = '__all__'


class TestCreateSerializer(TaggitSerializer, serializers.HyperlinkedModelSerializer):
    test_type = serializers.PrimaryKeyRelatedField(
        queryset=Test_Type.objects.all())
    environment = serializers.PrimaryKeyRelatedField(
        queryset=Development_Environment.objects.all())
    engagement = serializers.HyperlinkedRelatedField(
        queryset=Engagement.objects.all(),
        view_name='engagement-detail',
        format='html')
    estimated_time = serializers.TimeField()
    actual_time = serializers.TimeField()
    notes = serializers.PrimaryKeyRelatedField(
        queryset=Notes.objects.all(),
        many=True)
    tags = TagListSerializerField(required=False)

    class Meta:
        model = Test
        fields = '__all__'


class RiskAcceptanceSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Risk_Acceptance
        fields = '__all__'


class FindingSerializer(TaggitSerializer, serializers.HyperlinkedModelSerializer):
    review_requested_by = serializers.HyperlinkedRelatedField(
        queryset=Dojo_User.objects.all(),
        view_name='user-detail',
        format='html')
    reviewers = serializers.HyperlinkedRelatedField(
        queryset=Dojo_User.objects.all(),
        view_name='user-detail',
        format='html',
        many=True)
    reporter = serializers.HyperlinkedRelatedField(
        read_only=True,
        view_name='user-detail',
        format='html')
    defect_review_requested_by = serializers.HyperlinkedRelatedField(
        queryset=Dojo_User.objects.all(),
        view_name='user-detail',
        format='html')
    notes = serializers.SlugRelatedField(
        read_only=True,
        slug_field='entry',
        many=True)
    found_by = serializers.PrimaryKeyRelatedField(
        read_only=True,
        many=True)
    finding_url = serializers.CharField(
        source='url',
        read_only=True)
    url = serializers.HyperlinkedIdentityField(view_name='finding-detail')
    tags = TagListSerializerField(required=False)

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


class FindingCreateSerializer(TaggitSerializer, serializers.HyperlinkedModelSerializer):
    review_requested_by = serializers.HyperlinkedRelatedField(
        queryset=Dojo_User.objects.all(),
        view_name='user-detail',
        format='html')
    reviewers = serializers.HyperlinkedRelatedField(
        queryset=Dojo_User.objects.all(),
        view_name='user-detail',
        format='html',
        many=True)
    defect_review_requested_by = serializers.HyperlinkedRelatedField(
        queryset=Dojo_User.objects.all(),
        view_name='user-detail',
        format='html')
    notes = serializers.SlugRelatedField(
        read_only=True,
        slug_field='entry',
        many=True)
    test = serializers.HyperlinkedRelatedField(
        queryset=Test.objects.all(),
        view_name='test-detail',
        format='html')
    thread_id = serializers.IntegerField()
    reporter = serializers.HyperlinkedRelatedField(
        queryset=Dojo_User.objects.all(),
        format='html',
        view_name='user-detail')
    found_by = serializers.PrimaryKeyRelatedField(
        queryset=Test_Type.objects.all(),
        many=True)
    url = serializers.CharField()
    tags = TagListSerializerField(required=False)

    class Meta:
        model = Finding
        fields = '__all__'

    def validate(self, data):
        if ((data['active'] or data['verified']) and data['duplicate']):
            raise serializers.ValidationError('Duplicate findings cannot be'
                                              ' verified or active')
        if data['false_p'] and data['verified']:
            raise serializers.ValidationError('False positive findings cannot '
                                              'be verified.')
        return data


class FindingTemplateSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Finding_Template
        fields = '__all__'


class StubFindingSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Stub_Finding
        fields = '__all__'


class StubFindingCreateSerializer(serializers.HyperlinkedModelSerializer):
    reporter = serializers.HyperlinkedRelatedField(
        queryset=User.objects.all(),
        view_name='user-detail')
    test = serializers.HyperlinkedRelatedField(
        queryset=Test.objects.all(),
        view_name='test-detail')

    class Meta:
        model = Stub_Finding
        fields = '__all__'


class ScanSettingsSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = ScanSettings
        fields = '__all__'


class ScanSettingsCreateSerializer(serializers.HyperlinkedModelSerializer):
    user = serializers.HyperlinkedRelatedField(
        queryset=User.objects.all(),
        view_name='user-detail')
    product = serializers.HyperlinkedRelatedField(
        queryset=Product.objects.all(),
        view_name='product-detail')
    data = serializers.DateTimeField(required=False)

    class Meta:
        model = ScanSettings
        fields = '__all__'


class IPScanSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = IPScan
        fields = '__all__'


class ScanSerializer(serializers.HyperlinkedModelSerializer):
    # scan_settings_link = serializers.HyperlinkedRelatedField(
    #     read_only=True,
    #     source='scan_settings',
    #     view_name='scan_settings-detail',
    #     format='html')
    # scan_settings = serializers.PrimaryKeyRelatedField(
    #     queryset=ScanSettings.objects.all(),
    #     write_only=True,
    #     )
    # ipscan_links = serializers.HyperlinkedRelatedField(
    #     read_only=True,
    #     many=True,
    #     source='ipscan_set',
    #     view_name='ipscan-detail',
    #     format='html')

    class Meta:
        model = Scan
        fields = '__all__'


class ImportScanSerializer(TaggitSerializer, serializers.Serializer):
    scan_date = serializers.DateField()
    minimum_severity = serializers.ChoiceField(
        choices=SEVERITY_CHOICES,
        default='Info')
    active = serializers.BooleanField(default=True)
    verified = serializers.BooleanField(default=True)
    scan_type = serializers.ChoiceField(
        choices=ImportScanForm.SCAN_TYPE_CHOICES)
    file = serializers.FileField()
    engagement = serializers.HyperlinkedRelatedField(
        view_name='engagement-detail',
        queryset=Engagement.objects.all())
    lead = serializers.HyperlinkedRelatedField(
        view_name='user-detail',
        queryset=User.objects.all())
    tags = TagListSerializerField(required=False)

    def save(self):
        data = self.validated_data
        test_type, created = Test_Type.objects.get_or_create(
            name=data['scan_type'])
        environment, created = Development_Environment.objects.get_or_create(
            name='Development')
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
        try:
            parser = import_parser_factory(data['file'],
                                           test,
                                           data['scan_type'],)
        except ValueError:
            raise Exception('FileParser ValueError')

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
                item.save()

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

                # if item.unsaved_tags is not None:
                #    item.tags = item.unsaved_tags
        except SyntaxError:
            raise Exception('Parser SyntaxError')

        return test

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
    tags = TagListSerializerField(required=False)
    file = serializers.FileField()
    test = serializers.HyperlinkedRelatedField(
        view_name='test-detail',
        queryset=Test.objects.all())

    def save(self):
        data = self.validated_data
        test = data['test']
        scan_type = data['scan_type']
        min_sev = data['minimum_severity']
        scan_date = data['scan_date']
        verified = data['verified']
        active = data['active']

        try:
            parser = import_parser_factory(data['file'],
                                           test,
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
                    finding = findings[0]
                    if finding.mitigated:
                        finding.mitigated = None
                        finding.mitigated_by = None
                        finding.active = True
                        finding.verified = verified
                        finding.save()
                        note = Notes(
                            entry="Re-activated by %s re-upload." % scan_type,
                            author=self.context['request'].user)
                        note.save()
                        finding.notes.add(note)
                        reactivated_count += 1
                    new_items.append(finding)
                else:
                    item.test = test
                    item.date = test.target_start
                    item.reporter = self.context['request'].user
                    item.last_reviewed = timezone.now()
                    item.last_reviewed_by = self.context['request'].user
                    item.verified = verified
                    item.active = active
                    item.save()
                    finding_added_count += 1
                    new_items.append(item.id)
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

                    # if item.unsaved_tags:
                    #    finding.tags = item.unsaved_tags

            to_mitigate = set(original_items) - set(new_items)
            for finding in to_mitigate:
                finding.mitigated = datetime.datetime.combine(
                    scan_date,
                    timezone.now().time())
                finding.mitigated_by = self.context['request'].user
                finding.active = False
                finding.save()
                note = Notes(entry="Mitigated by %s re-upload." % scan_type,
                             author=self.context['request'].user)
                note.save()
                finding.notes.add(note)
                mitigated_count += 1

        except SyntaxError:
            raise Exception("Parser SyntaxError")

        return test

    def validate_scan_data(self, value):
        if value.date() > datetime.today().date():
            raise serializers.ValidationError(
                'The date cannot be in the future!')
        return value
