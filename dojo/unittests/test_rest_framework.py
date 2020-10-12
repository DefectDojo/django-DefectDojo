from dojo.models import Product, Engagement, Test, Finding, \
    JIRA_Issue, Tool_Product_Settings, Tool_Configuration, Tool_Type, \
    User, ScanSettings, Scan, Stub_Finding, Endpoint, JIRA_PKey, JIRA_Conf, \
    Finding_Template, Note_Type, App_Analysis, Endpoint_Status, \
    Sonarqube_Issue, Sonarqube_Issue_Transition, Sonarqube_Product, Notes, \
    BurpRawRequestResponse
from dojo.api_v2.views import EndPointViewSet, EngagementViewSet, \
    FindingTemplatesViewSet, FindingViewSet, JiraConfigurationsViewSet, \
    JiraIssuesViewSet, JiraViewSet, ProductViewSet, ScanSettingsViewSet, \
    ScansViewSet, StubFindingsViewSet, TestsViewSet, \
    ToolConfigurationsViewSet, ToolProductSettingsViewSet, ToolTypesViewSet, \
    UsersViewSet, ImportScanView, NoteTypeViewSet, AppAnalysisViewSet, \
    EndpointStatusViewSet, SonarqubeIssueViewSet, SonarqubeIssueTransitionViewSet, \
    SonarqubeProductViewSet, NotesViewSet
from json import dumps
from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APITestCase, APIClient


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
            self.view_mixins = list(map(
                (lambda x: x.__name__), self.viewset.__bases__))

        def setUp(self):
            testuser = User.objects.get(username='admin')
            token = Token.objects.get(user=testuser)
            self.client = APIClient()
            self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)
            self.url = reverse(self.viewname + '-list')

        @skipIfNotSubclass('ListModelMixin')
        def test_list(self):
            if hasattr(self.endpoint_model, 'tags') and self.payload:
                # create a new instance first to make sure there's at least 1 instance with tags set by payload to trigger tag handling code
                response = self.client.post(self.url, self.payload)

            response = self.client.get(self.url, format='json')
            # print("RESPONSE[0]:", response.data['results'])
            # print("RESPONSE[0]:", response.data['results'][0])
            # print("RESPONSE[0]:", response.data['results'][0]['id'])
            # finding = Finding.objects.get(id=response.data['results'][0]['id'])
            # print("RESPONSE.age:", response.data['results'][0]['age'])
            # print("finding.age:", finding.age)

            # print("RESPONSE.sla_days_remaining:", response.data['results'][0]['sla_days_remaining'])
            # print("finding.sla_days_remaining:", finding.sla_days_remaining())
            self.assertEqual(200, response.status_code)

        @skipIfNotSubclass('CreateModelMixin')
        def test_create(self):
            length = self.endpoint_model.objects.count()
            response = self.client.post(self.url, self.payload)
            self.assertEqual(201, response.status_code, response.data)
            self.assertEqual(self.endpoint_model.objects.count(), length + 1)

        @skipIfNotSubclass('RetrieveModelMixin')
        def test_detail(self):
            current_objects = self.client.get(self.url, format='json').data
            relative_url = self.url + '%s/' % current_objects['results'][0]['id']
            response = self.client.get(relative_url)
            self.assertEqual(200, response.status_code)

        @skipIfNotSubclass('DestroyModelMixin')
        def test_delete(self):
            current_objects = self.client.get(self.url, format='json').data
            relative_url = self.url + '%s/' % current_objects['results'][0]['id']
            response = self.client.delete(relative_url)
            self.assertEqual(204, response.status_code)

        @skipIfNotSubclass('UpdateModelMixin')
        def test_update(self):
            current_objects = self.client.get(self.url, format='json').data
            relative_url = self.url + '%s/' % current_objects['results'][0]['id']
            response = self.client.patch(
                relative_url, self.update_fields)
            for key, value in self.update_fields.items():
                # some exception as push_to_jira has been implemented strangely in the update methods in the api
                if key != 'push_to_jira':
                    self.assertEqual(value, response.data[key])
            self.assertFalse('push_to_jira' in response.data)
            response = self.client.put(
                relative_url, self.payload)
            self.assertEqual(200, response.status_code)


class AppAnalysisTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = App_Analysis
        self.viewname = 'app_analysis'
        self.viewset = AppAnalysisViewSet
        self.payload = {
            'product': 1,
            'name': 'Tomcat',
            'user': 1,
            'confidence': 100,
            'version': '8.5.1',
            'icon': '',
            'website': '',
            'website_found': '',
            'created': '2018-08-16T16:58:23.908Z'
        }
        self.update_fields = {'version': '9.0'}
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class EndpointStatusTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Endpoint_Status
        self.viewname = 'endpoint_status'
        self.viewset = EndpointStatusViewSet
        self.payload = {
            'endpoint': 2,
            'finding': 2,
            'mitigated': False,
            'false_positive': False,
            'risk_accepted': False,
            'out_of_scope': False,
            "date": "2017-01-12T00:00",
        }
        self.update_fields = {'mitigated': True}
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


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
            'product': 1,
            "tags": ["mytag", "yourtag"]
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
            "product": "1",
            "tags": ["mytag"]
        }
        self.update_fields = {'version': 'latest'}
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class FindingRequestResponseTest(APITestCase):
    fixtures = ['dojo_testdata.json']

    def setUp(self):
        testuser = User.objects.get(username='admin')
        token = Token.objects.get(user=testuser)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)

    def test_request_response_post(self):
        length = BurpRawRequestResponse.objects.count()
        payload = {
            "req_resp": [{"request": "POST", "response": "200"}]
        }
        response = self.client.post('/api/v2/findings/7/request_response/', dumps(payload), content_type='application/json')
        self.assertEqual(200, response.status_code, response.data)
        self.assertEqual(BurpRawRequestResponse.objects.count(), length + 1)

    def test_request_response_get(self):
        response = self.client.get('/api/v2/findings/7/request_response/', format='json')
        self.assertEqual(200, response.status_code)


class FindingsTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Finding
        self.viewname = 'finding'
        self.viewset = FindingViewSet
        self.payload = {
            "review_requested_by": 2,
            "reviewers": [2, 3],
            "defect_review_requested_by": 2,
            "test": 3,
            "url": "http://www.example.com",
            "thread_id": 1,
            "found_by": [],
            "title": "DUMMY FINDING",
            "date": "2020-05-20",
            "cwe": 1,
            "severity": "HIGH",
            "description": "TEST finding",
            "mitigation": "MITIGATION",
            "impact": "HIGH",
            "references": "",
            "reporter": 3,
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
            "endpoints": [1, 2],
            "images": []}
        self.update_fields = {'active': True, "push_to_jira": "True"}
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
            "references": "",
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
            "url": "http://www.example.com",
            "username": "testuser",
            "password": "testuser",
            "default_issue_type": "Story",
            "epic_name_id": 1111,
            "open_status_key": 111,
            "close_status_key": 111,
            "info_mapping_severity": "LOW",
            "low_mapping_severity": "LOW",
            "medium_mapping_severity": "LOW",
            "high_mapping_severity": "LOW",
            "critical_mapping_severity": "LOW",
            "finding_text": "",
            "global_jira_sla_notification": False
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
            "finding": 2,
            "engagement": 2,
        }
        self.update_fields = {'finding': 2}
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
            "product": 1,
            "conf": 2,
        }
        self.update_fields = {'conf': 3}
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class SonarqubeIssueTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Sonarqube_Issue
        self.viewname = 'sonarqube_issue'
        self.viewset = SonarqubeIssueViewSet
        self.payload = {
            "key": "AREwS5n5TxsFUNm31CxP",
            "status": "OPEN",
            "type": "VULNERABILITY"
        }
        self.update_fields = {'key': 'AREwS5n5TxsFUNm31CxP'}
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class SonarqubeIssuesTransitionTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Sonarqube_Issue_Transition
        self.viewname = 'sonarqube_issue_transition'
        self.viewset = SonarqubeIssuesTransitionTest
        self.payload = {
            "sonarqube_issue": 1,
            "finding_status": "Active, Verified",
            "sonarqube_status": "OPEN",
            "transitions": "confirm"
        }
        self.update_fields = {'sonarqube_status': 'CLOSED'}
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class SonarqubeProductTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Sonarqube_Product
        self.viewname = 'sonarqube_product'
        self.viewset = JiraViewSet
        self.payload = {
            "product": 2,
            "sonarqube_project_key": "dojo_sonar_key",
            "sonarqube_tool_config": 3
        }
        self.update_fields = {'sonarqube_tool_config': 2}
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class ProductTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Product
        self.viewname = 'product'
        self.viewset = ProductViewSet
        self.payload = {
            "product_manager": 2,
            "technical_contact": 3,
            "team_manager": 2,
            "authorized_users": [2, 3],
            "prod_type": 1,
            "name": "Test Product",
            "description": "test product",
            "tags": ["mytag", "yourtag"]
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
            "product": 1,
            "user": 3,
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
            "reporter": 3,
            "test": 3,
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
            "engagement": 2,
            "estimated_time": "0:30:20",
            "actual_time": "0:20:30",
            "notes": [],
            "target_start": "2017-01-12T00:00",
            "target_end": "2017-01-12T00:00",
            "percent_complete": 0,
            "lead": 2,
            "tags": []
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
            "tool_type": 1,
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
            "tool_configuration": 3,
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


class NoteTypesTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Note_Type
        self.viewname = 'note_type'
        self.viewset = NoteTypeViewSet
        self.payload = {
            "name": "Test Note",
            "description": "not that much",
            "is_single": False,
            "is_active": True,
            "is_mandatory": False
        }
        self.update_fields = {'description': 'changed description'}
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class NotesTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Notes
        self.viewname = 'notes'
        self.viewset = NotesViewSet
        self.payload = {
            "id": 1,
            "entry": "updated_entry",
            "author": '{"username": "admin"}',
            "editor": '{"username": "user1"}'
        }
        self.update_fields = {'entry': 'changed entry'}
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class UsersTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = User
        self.viewname = 'user'
        self.viewset = UsersViewSet
        self.payload = {
            "username": "test_user",
            "first_name": "test",
            "last_name": "user",
            "email": "example@email.com",
            "is_active": True,
        }
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
            self.assertNotEqual(obj['id'], 3)

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
            self.assertNotEqual(obj['id'], 3)

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
            self.assertNotEqual(obj['id'], 3)

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
            "file": open('tests/zap_sample.xml'),
            "engagement": 1,
            "lead": 2,
            "tags": ["'ci/cd, api"],
            "version": "1.0.0",
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
                "file": open('tests/zap_sample.xml'),
                "test": 3,
                "version": "1.0.1",
            })
        self.assertEqual(length, Test.objects.all().count())
        self.assertEqual(201, response.status_code)
