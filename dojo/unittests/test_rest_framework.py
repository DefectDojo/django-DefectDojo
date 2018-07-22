from dojo.models import Product, Engagement, Test, Finding, \
    JIRA_Issue, Tool_Product_Settings, Tool_Configuration, Tool_Type, \
    User, ScanSettings, Scan, Stub_Finding, Endpoint, JIRA_PKey, JIRA_Conf, \
    Finding_Template

from dojo.api_v2.views import EndPointViewSet, EngagementViewSet, \
    FindingTemplatesViewSet, FindingViewSet, JiraConfigurationsViewSet, \
    JiraIssuesViewSet, JiraViewSet, ProductViewSet, ScanSettingsViewSet, \
    ScansViewSet, StubFindingsViewSet, TestsViewSet, \
    ToolConfigurationsViewSet, ToolProductSettingsViewSet, ToolTypesViewSet, \
    UsersViewSet, ImportScanView

from django.core.urlresolvers import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APITestCase, APIClient
from urlparse import urlparse


def skipIfNotSubclass(baseclass_name):
    def decorate(f):
        def wrapper(self, *args, **kwargs):
            if baseclass_name not in self.view_mixins:
                self.skipTest('This view is not %s' % baseclass_name)
            else:
                f(self, *args, **kwargs)
        return wrapper
    return decorate


class BaseClass():
    class RESTEndpointTest(APITestCase):
        def __init__(self, *args, **kwargs):
            APITestCase.__init__(self, *args, **kwargs)
            self.view_mixins = map(
                (lambda x: x.__name__), self.viewset.__bases__)

        def setUp(self):
            testuser = User.objects.get(username='admin')
            token = Token.objects.get(user=testuser)
            self.client = APIClient()
            self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)

        @skipIfNotSubclass('ListModelMixin')
        def test_list(self):
            response = self.client.get(
                reverse(self.viewname + '-list'), format='json')
            self.assertEqual(200, response.status_code)

        @skipIfNotSubclass('CreateModelMixin')
        def test_create(self):
            length = self.endpoint_model.objects.count()
            response = self.client.post(
                reverse(self.viewname + '-list'),
                self.payload)
            self.assertEqual(201, response.status_code)
            self.assertEqual(self.endpoint_model.objects.count(), length + 1)

        @skipIfNotSubclass('RetrieveModelMixin')
        def test_detail(self):
            current_objects = self.client.get(
                reverse(self.viewname + '-list'), format='json').data
            relative_url = urlparse(current_objects['results'][0]['url']).path
            response = self.client.get(relative_url)
            self.assertEqual(200, response.status_code)

        @skipIfNotSubclass('DestroyModelMixin')
        def test_delete(self):
            current_objects = self.client.get(
                reverse(self.viewname + '-list'), format='json').data
            relative_url = urlparse(current_objects['results'][0]['url']).path
            response = self.client.delete(relative_url)
            self.assertEqual(204, response.status_code)

        @skipIfNotSubclass('UpdateModelMixin')
        def test_update(self):
            current_objects = self.client.get(
                reverse(self.viewname + '-list'), format='json').data
            relative_url = urlparse(current_objects['results'][0]['url']).path
            response = self.client.patch(
                relative_url, self.update_fields)
            for key, value in self.update_fields.iteritems():
                self.assertEqual(value, response.data[key])
            response = self.client.put(
                relative_url, self.payload)
            self.assertEqual(200, response.status_code)


class EndpointTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Endpoint
        self.viewname = 'endpoint'
        self.viewset = EndPointViewSet
        self.payload = {
            'protocol': 'http',
            'host': '127.0.0.1',
            'path': '/',
            'query': 'test=true',
            'fragment': 'test-1',
            'product': 'http://testserver/api/v2/products/1/'
        }
        self.update_fields = {'protocol': 'ftp'}
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class EngagementTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Engagement
        self.viewname = 'engagement'
        self.viewset = EngagementViewSet
        self.payload = {
            "eng_type": 1,
            "report_type": 1,
            "name": "",
            "description": "",
            "version": "",
            "target_start": '1937-01-01',
            "target_end": '1937-01-01',
            "reason": "",
            "test_strategy": "",
            "product": "http://testserver/api/v2/products/1/"
        }
        self.update_fields = {'version': 'latest'}
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class FindingsTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Finding
        self.viewname = 'finding'
        self.viewset = FindingViewSet
        self.payload = {
            "review_requested_by": "http://testserver/api/v2/users/2/",
            "reviewers": [
                "http://testserver/api/v2/users/2/",
                "http://testserver/api/v2/users/3/"],
            "defect_review_requested_by": "http://testserver/api/v2/users/2/",
            "test": "http://testserver/api/v2/tests/3/",
            "url": "http://www.example.com",
            "thread_id": 1,
            "reporter": "http://testserver/api/v2/users/2/",
            "found_by": [],
            "title": "DUMMY FINDING",
            "date": "2017-12-31",
            "cwe": 1,
            "severity": "HIGH",
            "description": "TEST finding",
            "mitigation": "MITIGATION",
            "impact": "HIGH",
            "references": "",
            "is_template": False,
            "active": False,
            "verified": False,
            "false_p": False,
            "duplicate": False,
            "out_of_scope": False,
            "under_review": False,
            "under_defect_review": False,
            "numerical_severity": "S0",
            "line": 100,
            "file_path": "",
            "static_finding": False,
            "dynamic_finding": False,
            "endpoints": [
                "http://testserver/api/v2/endpoints/1/",
                "http://testserver/api/v2/endpoints/2/"],
            "images": []}
        self.update_fields = {'active': True}
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class FindingTemplatesTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Finding_Template
        self.viewname = 'finding_template'
        self.viewset = FindingTemplatesViewSet
        self.payload = {
            "title": "Test template",
            "cwe": 0,
            "severity": "MEDIUM",
            "description": "test template",
            "mitigation": "None",
            "impact": "MEDIUM",
            "references": ""
        }
        self.update_fields = {'references': 'some reference'}
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class JiraConfigurationsTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = JIRA_Conf
        self.viewname = 'jira_conf'
        self.viewset = JiraConfigurationsViewSet
        self.payload = {
            "jira_url": "http://www.example.com",
            "username": "testuser",
            "password": "testuser",
            "default_issue_type": "Story",
            "epic_name_id": 1111,
            "open_status_key": 111,
            "close_status_key": 111,
            "low_mapping_severity": "LOW",
            "medium_mapping_severity": "LOW",
            "high_mapping_severity": "LOW",
            "critical_mapping_severity": "LOW",
            "finding_text": ""
        }
        self.update_fields = {'epic_name_id': 1}
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class JiraIssuesTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = JIRA_Issue
        self.viewname = 'jira_issue'
        self.viewset = JiraIssuesViewSet
        self.payload = {
            "jira_id": "JIRA 1",
            "jira_key": "SOME KEY",
            "finding": "http://testserver/api/v2/findings/2/",
            "engagement": 'http://testserver/api/v2/engagements/2/'
        }
        self.update_fields = {
            'finding': 'http://testserver/api/v2/findings/2/'}
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class JiraTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = JIRA_PKey
        self.viewname = 'jira_pkey'
        self.viewset = JiraViewSet
        self.payload = {
            "project_key": "TEST KEY",
            "component": "",
            "push_all_issues": False,
            "enable_engagement_epic_mapping": False,
            "push_notes": False,
            "product": 'http://testserver/api/v2/products/1/',
            "conf": "http://testserver/api/v2/jira_configurations/2/"
        }
        self.update_fields = {
            'conf': "http://testserver/api/v2/jira_configurations/3/"}
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class ProductTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Product
        self.viewname = 'product'
        self.viewset = ProductViewSet
        self.payload = {
            "product_manager": "http://testserver/api/v2/users/2/",
            "technical_contact": "http://testserver/api/v2/users/3/",
            "team_manager": "http://testserver/api/v2/users/2/",
            "authorized_users": [
                "http://testserver/api/v2/users/2/",
                "http://testserver/api/v2/users/3/"],
            "prod_type": 1,
            "name": "Test Product",
            "description": "test product"
        }
        self.update_fields = {'prod_type': 2}
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class ScanSettingsTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = ScanSettings
        self.viewname = 'scansettings'
        self.viewset = ScanSettingsViewSet
        self.payload = {
            "addresses": "127.0.0.1",
            "frequency": "Weekly",
            "email": "test@dojo.com",
            "protocol": "TCP",
            "product": "http://testserver/api/v2/products/1/",
            "user": "http://testserver/api/v2/users/3/"
        }
        self.update_fields = {'protocol': 'ftp'}
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class ScansTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Scan
        self.viewname = 'scan'
        self.viewset = ScansViewSet
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class StubFindingsTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Stub_Finding
        self.viewname = 'stub_finding'
        self.viewset = StubFindingsViewSet
        self.payload = {
            "title": "Stub Finding 1",
            "date": "2017-12-31",
            "severity": "HIGH",
            "description": "test stub finding",
            "reporter": "http://testserver/api/v2/users/3/",
            "test": "http://testserver/api/v2/tests/3/"
        }
        self.update_fields = {'severity': 'LOW'}
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class TestsTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Test
        self.viewname = 'test'
        self.viewset = TestsViewSet
        self.payload = {
            "test_type": 1,
            "environment": 1,
            "engagement": "http://testserver/api/v2/engagements/2/",
            "estimated_time": "0:30:20",
            "actual_time": "0:20:30",
            "notes": [],
            "target_start": "2017-01-12T00:00",
            "target_end": "2017-01-12T00:00",
            "percent_complete": 0,
            "lead": "http://testserver/api/v2/users/2/"
        }
        self.update_fields = {'percent_complete': 100}
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class ToolConfigurationsTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Tool_Configuration
        self.viewname = 'tool_configuration'
        self.viewset = ToolConfigurationsViewSet
        self.payload = {
            "configuration_url": "http://www.example.com",
            "name": "Tool Configuration",
            "description": "",
            "authentication_type": "API",
            "username": "",
            "password": "",
            "auth_title": "",
            "ssh": "",
            "api_key": "test key",
            "tool_type": 'http://127.0.0.1:8000/api/v2/tool_types/1/'
        }
        self.update_fields = {'ssh': 'test string'}
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class ToolProductSettingsTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Tool_Product_Settings
        self.viewname = 'tool_product_settings'
        self.viewset = ToolProductSettingsViewSet
        self.payload = {
            "setting_url": "http://www.example.com",
            "name": "Tool Product Setting",
            "description": "test tool product setting",
            "tool_project_id": "1",
            "tool_configuration":
                "http://127.0.0.1:8000/api/v2/tool_configurations/3/"
        }
        self.update_fields = {'tool_project_id': '2'}
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class ToolTypesTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Tool_Type
        self.viewname = 'tool_type'
        self.viewset = ToolTypesViewSet
        self.payload = {
            "name": "Tool Type",
            "description": "test tool type"
        }
        self.update_fields = {'description': 'changed description'}
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class UsersTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = User
        self.viewname = 'user'
        self.viewset = UsersViewSet
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class ProductPermissionTest(APITestCase):
    fixtures = ['dojo_testdata.json']

    def setUp(self):
        testuser = User.objects.get(username='user1')
        token = Token.objects.get(user=testuser)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)

    def test_user_should_not_have_access_to_product_3_in_list(self):
        response = self.client.get(
            reverse('product-list'), format='json')
        for obj in response.data['results']:
            self.assertNotEqual(
                obj['url'],
                'http://testserver/api/v2/products/3/')

    def test_user_should_not_have_access_to_product_3_in_detail(self):
        response = self.client.get('http://testserver/api/v2/products/3/')
        self.assertEqual(response.status_code, 404)


class ScanSettingsPermissionTest(APITestCase):
    fixtures = ['dojo_testdata.json']

    def setUp(self):
        testuser = User.objects.get(username='user1')
        token = Token.objects.get(user=testuser)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)

    def test_user_should_not_have_access_to_setting_3_in_list(self):
        response = self.client.get(
            reverse('scansettings-list'), format='json')
        for obj in response.data['results']:
            self.assertNotEqual(
                obj['url'],
                'http://testserver/api/v2/scan_settings/3/')

    def test_user_should_not_have_access_to_setting_3_in_detail(self):
        response = self.client.get('http://testserver/api/v2/scan_settings/3/')
        self.assertEqual(response.status_code, 404)


class ScansPermissionTest(APITestCase):
    fixtures = ['dojo_testdata.json']

    def setUp(self):
        testuser = User.objects.get(username='user1')
        token = Token.objects.get(user=testuser)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)

    def test_user_should_not_have_access_to_scan_3_in_list(self):
        response = self.client.get(
            reverse('scan-list'), format='json')
        for obj in response.data['results']:
            self.assertNotEqual(
                obj['url'],
                'http://testserver/api/v2/scans/3/')

    def test_user_should_not_have_access_to_scan_3_in_detail(self):
        response = self.client.get('http://testserver/api/v2/scans/3/')
        self.assertEqual(response.status_code, 404)


class ImportScanTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Test
        self.viewname = 'importscan'
        self.viewset = ImportScanView
        self.payload = {
            "scan_date": '2017-12-30',
            "minimum_severity": 'Low',
            "active": False,
            "verified": True,
            "scan_type": 'ZAP Scan',
            "tags": "test",
            "file": open('tests/zap_sample.xml'),
            "engagement": 'http://testserver/api/v2/engagements/1/',
            "lead": 'http://testserver/api/v2/users/2/'
        }
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class ReimportScanTest(APITestCase):
    fixtures = ['dojo_testdata.json']

    def setUp(self):
            testuser = User.objects.get(username='admin')
            token = Token.objects.get(user=testuser)
            self.client = APIClient()
            self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)

    def test_import_zap_xml(self):
        length = Test.objects.all().count()
        response = self.client.post(
            reverse('reimportscan-list'), {
                "scan_date": '2017-12-30',
                "minimum_severity": 'Low',
                "active": True,
                "verified": True,
                "scan_type": 'ZAP Scan',
                "tags": "test",
                "file": open('tests/zap_sample.xml'),
                "test": 'http://testserver/api/v2/tests/3/'})
        self.assertEqual(length, Test.objects.all().count())
        self.assertEqual(201, response.status_code)
