from collections import OrderedDict
from drf_spectacular.drainage import GENERATOR_STATS
# from drf_spectacular.renderers import OpenApiJsonRenderer
from unittest.mock import MagicMock, call, patch, ANY
from dojo.models import Development_Environment, Product, Engagement, Test, Finding, \
    JIRA_Issue, Test_Type, Tool_Product_Settings, Tool_Configuration, Tool_Type, \
    User, Stub_Finding, Endpoint, JIRA_Project, JIRA_Instance, \
    Finding_Template, Note_Type, App_Analysis, Endpoint_Status, \
    Sonarqube_Issue, Sonarqube_Issue_Transition, Product_API_Scan_Configuration, Notes, \
    BurpRawRequestResponse, DojoMeta, FileUpload, Product_Type, Dojo_Group, \
    Role, Product_Type_Member, Product_Member, Product_Type_Group, Risk_Acceptance, \
    Product_Group, Global_Role, Dojo_Group_Member, Language_Type, Languages, \
    Notifications, UserContactInfo, Cred_Mapping, Cred_User, \
    TextQuestion, ChoiceQuestion, TextAnswer, ChoiceAnswer, Engagement_Survey, \
    Answered_Survey, General_Survey
from dojo.api_v2.views import DevelopmentEnvironmentViewSet, EndPointViewSet, EngagementViewSet, \
    FindingTemplatesViewSet, FindingViewSet, JiraInstanceViewSet, \
    JiraIssuesViewSet, JiraProjectViewSet, ProductViewSet, \
    StubFindingsViewSet, TestTypesViewSet, TestsViewSet, \
    ToolConfigurationsViewSet, ToolProductSettingsViewSet, ToolTypesViewSet, \
    UsersViewSet, ImportScanView, NoteTypeViewSet, AppAnalysisViewSet, \
    EndpointStatusViewSet, SonarqubeIssueViewSet, NotesViewSet, ProductTypeViewSet, \
    DojoGroupViewSet, RoleViewSet, ProductTypeMemberViewSet, ProductMemberViewSet, \
    ProductTypeGroupViewSet, ProductGroupViewSet, GlobalRoleViewSet, RiskAcceptanceViewSet, \
    DojoGroupMemberViewSet, LanguageTypeViewSet, LanguageViewSet, ImportLanguagesView, \
    NotificationsViewSet, UserContactInfoViewSet, ProductAPIScanConfigurationViewSet, \
    ConfigurationPermissionViewSet, CredentialsMappingViewSet, \
    CredentialsViewSet, QuestionnaireQuestionViewSet, QuestionnaireAnswerViewSet, \
    QuestionnaireGeneralSurveyViewSet, QuestionnaireEngagementSurveyViewSet, QuestionnaireAnsweredSurveyViewSet
from json import dumps
from enum import Enum
from django.urls import reverse
from django.contrib.auth.models import Permission
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient
from .dojo_test_case import DojoAPITestCase
from dojo.api_v2.prefetch.utils import _get_prefetchable_fields
from rest_framework.mixins import \
    ListModelMixin, RetrieveModelMixin, CreateModelMixin, \
    DestroyModelMixin, UpdateModelMixin
from dojo.api_v2.mixins import DeletePreviewModelMixin
from dojo.api_v2.prefetch import PrefetchListMixin, PrefetchRetrieveMixin
from drf_spectacular.settings import spectacular_settings
import logging
import pathlib
import json
from dojo.authorization.roles_permissions import Permissions


logger = logging.getLogger(__name__)

BASE_API_URL = "/api/v2"

TYPE_OBJECT = "object"  #:
TYPE_STRING = "string"  #:
TYPE_NUMBER = "number"  #:
TYPE_INTEGER = "integer"  #:
TYPE_BOOLEAN = "boolean"  #:
TYPE_ARRAY = "array"  #:
TYPE_FILE = "file"  #:

IMPORTER_MOCK_RETURN_VALUE = None, 0, 0, None
REIMPORTER_MOCK_RETURN_VALUE = None, 0, 0, 0, 0, 0, MagicMock()


def get_open_api3_json_schema():
    generator_class = spectacular_settings.DEFAULT_GENERATOR_CLASS
    generator = generator_class()
    schema = generator.get_schema(request=None, public=True)
    GENERATOR_STATS.emit_summary()

    from drf_spectacular.validation import validate_schema
    validate_schema(schema)

    return schema


# use ugly global to avoid generating the schema for every test/method (as it's slow)
global open_api3_json_schema
open_api3_json_schema = get_open_api3_json_schema()


def skipIfNotSubclass(baseclass):
    def decorate(f):
        def wrapper(self, *args, **kwargs):
            if not issubclass(self.viewset, baseclass):
                self.skipTest('This view does not inherit from %s' % baseclass)
            else:
                f(self, *args, **kwargs)
        return wrapper
    return decorate


# def testIsBroken(method):
#     return tag("broken")(method)


def check_response_valid(expected_code, response):
    def _data_to_str(response):
        if hasattr(response, "data"):
            return response.data
        return None

    assert response.status_code == expected_code, \
        f"Response invalid, returned with code {response.status_code}\nResponse Data:\n{_data_to_str(response)}"


def format_url(path):
    return f"{BASE_API_URL}{path}"


class SchemaChecker():
    def __init__(self, components):
        self._prefix = []
        self._has_failed = False
        self._components = components
        self._errors = []

    def _register_error(self, error):
        self._errors += [error]

    def _check_or_fail(self, condition, message):
        if not condition:
            self._has_failed = True
            self._register_error(message)
            # print(message)

    def _get_prefix(self):
        return '#'.join(self._prefix)

    def _push_prefix(self, prefix):
        self._prefix += [prefix]

    def _pop_prefix(self):
        self._prefix = self._prefix if len(self._prefix) == 0 else self._prefix[:-1]

    def _resolve_if_ref(self, schema):
        if '$ref' not in schema:
            return schema

        ref_name = schema["$ref"]
        ref_name = ref_name[ref_name.rfind("/") + 1:]
        return self._components['schemas'][ref_name]

    def _check_has_required_fields(self, required_fields, obj):
        # if not required_fields:
        #     print('no required fields')

        for required_field in required_fields:
            # passwords are writeOnly, but this is not supported by Swagger / OpenAPIv2
            # TODO check this for OpenAPI3
            if required_field != 'password':
                # print('checking field: ', required_field)
                field = f"{self._get_prefix()}#{required_field}"
                self._check_or_fail(obj is not None and required_field in obj, f"{field} is required but was not returned")

    def _check_type(self, schema, obj):
        if 'type' not in schema:
            # TODO implement OneOf / AllOff  (enums)
            # Engagement
            # "status": {
            #     "nullable": true,
            #     "oneOf": [
            #         {
            #             "$ref": "#/components/schemas/StatusEnum"
            #         },
            #         {
            #             "$ref": "#/components/schemas/NullEnum"
            #         }
            #     ]
            # },

            # "StatusEnum": {
            #     "enum": [
            #         "Not Started",
            #         "Blocked",
            #         "Cancelled",
            #         "Completed",
            #         "In Progress",
            #         "On Hold",
            #         "Waiting for Resource"
            #     ],
            #     "type": "string"
            # },
            return schema
        schema_type = schema["type"]
        is_nullable = schema.get("x-nullable", False) or schema.get("readOnly", False)

        def _check_helper(check):
            self._check_or_fail(check, f"{self._get_prefix()} should be of type {schema_type} but value was of type {type(obj)}")

        if obj is None:
            self._check_or_fail(is_nullable, f"{self._get_prefix()} is not nullable yet the value returned was null")
        elif schema_type == TYPE_BOOLEAN:
            _check_helper(isinstance(obj, bool))
        elif schema_type == TYPE_INTEGER:
            _check_helper(isinstance(obj, int))
        elif schema_type == TYPE_NUMBER:
            _check_helper(obj.isdecimal())
        elif schema_type == TYPE_ARRAY:
            _check_helper(isinstance(obj, list))
        elif schema_type == TYPE_OBJECT:
            _check_helper(isinstance(obj, OrderedDict) or isinstance(obj, dict))
        elif schema_type == TYPE_STRING:
            _check_helper(isinstance(obj, str))
        else:
            # Default case
            _check_helper(False)

        # print('_check_type ok for: %s: %s' % (schema, obj))

    def _with_prefix(self, prefix, callable, *args):
        self._push_prefix(prefix)
        callable(*args)
        self._pop_prefix()

    def check(self, schema, obj):
        def _check(schema, obj):
            # Convert sets to lists to streamline checks
            if 'type' in schema and schema["type"] is TYPE_ARRAY and isinstance(obj, set):
                obj = list(obj)

            schema = self._resolve_if_ref(schema)
            self._check_type(schema, obj)

            required_fields = schema.get("required", [])
            self._check_has_required_fields(required_fields, obj)

            if obj is None:
                return

            properties = schema.get("properties", None)

            if properties is not None:
                for name, prop in properties.items():
                    obj_child = obj.get(name, None)
                    if obj_child is not None:
                        # print('checking child: ', name, obj_child)
                        # self._with_prefix(name, _check, prop, obj_child)
                        _check(prop, obj_child)

                for child_name in obj.keys():
                    # TODO prefetch mixins not picked up by spectcular?
                    if child_name not in ['prefetch']:
                        if not properties or child_name not in properties.keys():
                            self._has_failed = True
                            self._register_error(f'unexpected property "{child_name}" found')

            additional_properties = schema.get("additionalProperties", None)
            if additional_properties is not None:
                for name, obj_child in obj.items():
                    self._with_prefix(f"additionalProp<{name}>", _check, additional_properties, obj_child)

            # TODO implement support for enum / OneOff / AllOff
            if 'type' in schema and schema["type"] is TYPE_ARRAY:
                items_schema = schema["items"]
                for index in range(len(obj)):
                    self._with_prefix(f"item{index}", _check, items_schema, obj[index])

        self._has_failed = False
        self._errors = []
        self._prefix = []
        _check(schema, obj)
        assert not self._has_failed, "\n" + '\n'.join(self._errors) + "\nFailed with " + str(len(self._errors)) + " errors"


class TestType(Enum):
    STANDARD = 1
    OBJECT_PERMISSIONS = 2
    CONFIGURATION_PERMISSIONS = 3


class BaseClass():
    class RESTEndpointTest(DojoAPITestCase):
        def __init__(self, *args, **kwargs):
            DojoAPITestCase.__init__(self, *args, **kwargs)

        def setUp(self):
            testuser = User.objects.get(username='admin')
            token = Token.objects.get(user=testuser)
            self.client = APIClient()
            self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)
            self.url = reverse(self.viewname + '-list')
            self.schema = open_api3_json_schema

        def check_schema(self, schema, obj):
            schema_checker = SchemaChecker(self.schema["components"])
            # print(vars(schema_checker))
            schema_checker.check(self.schema, obj)

        # def get_valid_object_id(self):
        #     response = self.client.get(format_url(f"/{self.viewname}/"))
        #     check_response_valid(status.HTTP_200_OK, response)
        #     if len(response.data["results"]) == 0:
        #         return None

        #     return response.data["results"][0].get('id', None)

        def get_endpoint_schema(self, path, method):
            paths = self.schema["paths"]
            methods = paths.get(path, None)
            assert methods is not None, f"{path} not found in {[path for path in paths.keys()]}"

            endpoint = methods.get(method, None)
            assert endpoint is not None, f"Method {method} not found in {[method for method in methods.keys()]}"

            return endpoint

        def check_schema_response(self, method, status_code, response, detail=False):
            detail_path = '{id}/' if detail else ''
            endpoints_schema = self.schema["paths"][format_url(f"/{self.endpoint_path}/{detail_path}")]
            schema = endpoints_schema[method]['responses'][status_code]['content']['application/json']['schema']
            obj = response.data
            self.check_schema(schema, obj)

        @skipIfNotSubclass(ListModelMixin)
        def test_list(self):
            # print(open_api3_json_schema)
            # validator = ResponseValidator(spec)

            check_for_tags = False
            if hasattr(self.endpoint_model, 'tags') and self.payload and self.payload.get('tags', None):
                # create a new instance first to make sure there's at least 1 instance with tags set by payload to trigger tag handling code
                logger.debug('creating model with endpoints: %s', self.payload)
                response = self.client.post(self.url, self.payload)
                self.assertEqual(201, response.status_code, response.content[:1000])

                # print('response:', response.content[:1000])
                check_for_id = response.data['id']
                # print('id: ', check_for_id)
                check_for_tags = self.payload.get('tags', None)

            response = self.client.get(self.url, format='json')
            # print('response')
            # print(vars(response))

            # print('response.data')
            # print(response.data)
            # tags must be present in last entry, the one we created
            if check_for_tags:
                tags_found = False
                for result in response.data['results']:
                    if result['id'] == check_for_id:
                        # logger.debug('result.tags: %s', result.get('tags', ''))
                        self.assertEqual(len(check_for_tags), len(result.get('tags', None)))
                        for tag in check_for_tags:
                            # logger.debug('looking for tag %s in tag list %s', tag, result['tags'])
                            self.assertTrue(tag in result['tags'])
                        tags_found = True
                self.assertTrue(tags_found)

            self.assertEqual(200, response.status_code, response.content[:1000])

            self.check_schema_response('get', '200', response)

        @skipIfNotSubclass(CreateModelMixin)
        def test_create(self):
            length = self.endpoint_model.objects.count()
            response = self.client.post(self.url, self.payload)
            logger.debug('test_create_response:')
            logger.debug(response)
            logger.debug(response.data)
            self.assertEqual(201, response.status_code, response.content[:1000])
            self.assertEqual(self.endpoint_model.objects.count(), length + 1)

            if hasattr(self.endpoint_model, 'tags') and self.payload and self.payload.get('tags', None):
                self.assertEqual(len(self.payload.get('tags')), len(response.data.get('tags', None)))
                for tag in self.payload.get('tags'):
                    # logger.debug('looking for tag %s in tag list %s', tag, response.data['tags'])
                    self.assertTrue(tag in response.data['tags'])

            self.check_schema_response('post', '201', response)

        @skipIfNotSubclass(RetrieveModelMixin)
        def test_detail(self):
            current_objects = self.client.get(self.url, format='json').data
            relative_url = self.url + '%s/' % current_objects['results'][0]['id']
            response = self.client.get(relative_url)
            self.assertEqual(200, response.status_code, response.content[:1000])
            # sensitive data must be set to write_only so those are not returned in the response
            # https://github.com/DefectDojo/django-DefectDojo/security/advisories/GHSA-8q8j-7wc4-vjg5
            self.assertFalse('password' in response.data)
            self.assertFalse('ssh' in response.data)
            self.assertFalse('api_key' in response.data)

            self.check_schema_response('get', '200', response, detail=True)

        @skipIfNotSubclass(DestroyModelMixin)
        def test_delete(self):
            current_objects = self.client.get(self.url, format='json').data
            relative_url = self.url + '%s/' % current_objects['results'][-1]['id']
            response = self.client.delete(relative_url)
            self.assertEqual(204, response.status_code, response.content[:1000])

        @skipIfNotSubclass(UpdateModelMixin)
        def test_update(self):
            current_objects = self.client.get(self.url, format='json').data
            relative_url = self.url + '%s/' % current_objects['results'][0]['id']
            response = self.client.patch(relative_url, self.update_fields)
            # print('patch response.data')
            # print(response.data)

            self.assertEqual(200, response.status_code, response.content[:1000])

            self.check_schema_response('patch', '200', response, detail=True)

            for key, value in self.update_fields.items():
                # some exception as push_to_jira has been implemented strangely in the update methods in the api
                if key not in ['push_to_jira', 'ssh', 'password', 'api_key']:
                    # Convert data to sets to avoid problems with lists
                    if isinstance(value, list):
                        value = set(value)
                    if isinstance(response.data[key], list):
                        response_data = set(response.data[key])
                    else:
                        response_data = response.data[key]
                    self.assertEqual(value, response_data)

            self.assertFalse('push_to_jira' in response.data)
            self.assertFalse('ssh' in response.data)
            self.assertFalse('password' in response.data)
            self.assertFalse('api_key' in response.data)

            if hasattr(self.endpoint_model, 'tags') and self.update_fields and self.update_fields.get('tags', None):
                self.assertEqual(len(self.update_fields.get('tags')), len(response.data.get('tags', None)))
                for tag in self.update_fields.get('tags'):
                    logger.debug('looking for tag %s in tag list %s', tag, response.data['tags'])
                    self.assertTrue(tag in response.data['tags'])

            response = self.client.put(
                relative_url, self.payload)
            self.assertEqual(200, response.status_code, response.content[:1000])
            # print('put response.data')
            # print(response.data)

            self.check_schema_response('put', '200', response, detail=True)

        @skipIfNotSubclass(DeletePreviewModelMixin)
        def test_delete_preview(self):
            current_objects = self.client.get(self.url, format='json').data
            relative_url = self.url + '%s/delete_preview/' % current_objects['results'][0]['id']
            response = self.client.get(relative_url)
            # print('delete_preview response.data')

            self.assertEqual(200, response.status_code, response.content[:1000])

            self.check_schema_response('get', '200', response, detail=True)

            self.assertFalse('push_to_jira' in response.data)
            self.assertFalse('password' in response.data)
            self.assertFalse('ssh' in response.data)
            self.assertFalse('api_key' in response.data)

            self.assertIsInstance(response.data['results'], list)
            self.assertTrue(len(response.data['results']) > 0, "Length: {}".format(len(response.data['results'])))

            for obj in response.data['results']:
                self.assertIsInstance(obj, dict)
                self.assertTrue(len(obj), 3)
                self.assertIsInstance(obj['model'], str)
                if obj['id']:  # It needs to be None or int
                    self.assertIsInstance(obj['id'], int)
                self.assertIsInstance(obj['name'], str)

            self.assertEqual(self.deleted_objects, len(response.data['results']), response.content[:1000])

        @skipIfNotSubclass(PrefetchRetrieveMixin)
        def test_detail_prefetch(self):
            # print("=======================================================")
            prefetchable_fields = [x[0] for x in _get_prefetchable_fields(self.viewset.serializer_class)]

            current_objects = self.client.get(self.url, format='json').data
            relative_url = self.url + '%s/' % current_objects['results'][0]['id']
            response = self.client.get(relative_url, data={
                "prefetch": ','.join(prefetchable_fields)
            })

            self.assertEqual(200, response.status_code)
            obj = response.data
            self.assertTrue("prefetch" in obj)

            for field in prefetchable_fields:
                field_value = obj.get(field, None)
                if field_value is None:
                    continue

                self.assertTrue(field in obj["prefetch"])
                values = field_value if type(field_value) is list else [field_value]

                for value in values:
                    self.assertTrue(value in obj["prefetch"][field])

            # TODO add schema check

        @skipIfNotSubclass(PrefetchListMixin)
        def test_list_prefetch(self):
            prefetchable_fields = [x[0] for x in _get_prefetchable_fields(self.viewset.serializer_class)]

            response = self.client.get(self.url, data={
                "prefetch": ','.join(prefetchable_fields)
            })

            self.assertEqual(200, response.status_code)
            objs = response.data
            self.assertTrue("results" in objs)
            self.assertTrue("prefetch" in objs)

            for obj in objs["results"]:
                for field in prefetchable_fields:
                    field_value = obj.get(field, None)
                    if field_value is None:
                        continue

                    self.assertTrue(field in objs["prefetch"])
                    values = field_value if type(field_value) is list else [field_value]

                    for value in values:
                        if type(value) is not int:
                            value = value['id']
                        self.assertTrue(value in objs["prefetch"][field])

            # TODO add schema check

        def setUp_not_authorized(self):
            testuser = User.objects.get(id=3)
            token = Token.objects.get(user=testuser)
            self.client = APIClient()
            self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)

        def setUp_global_reader(self):
            testuser = User.objects.get(id=5)
            token = Token.objects.get(user=testuser)
            self.client = APIClient()
            self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)

        def setUp_global_owner(self):
            testuser = User.objects.get(id=6)
            token = Token.objects.get(user=testuser)
            self.client = APIClient()
            self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)

        @skipIfNotSubclass(ListModelMixin)
        def test_list_object_not_authorized(self):
            if not self.test_type == TestType.OBJECT_PERMISSIONS:
                self.skipTest('Authorization is not object based')

            self.setUp_not_authorized()

            response = self.client.get(self.url, format='json')
            self.assertFalse(response.data['results'])
            self.assertEqual(200, response.status_code, response.content[:1000])

        @skipIfNotSubclass(RetrieveModelMixin)
        def test_detail_object_not_authorized(self):
            if not self.test_type == TestType.OBJECT_PERMISSIONS:
                self.skipTest('Authorization is not object based')

            self.setUp_not_authorized()

            current_objects = self.endpoint_model.objects.all()
            relative_url = self.url + '%s/' % current_objects[0].id
            response = self.client.get(relative_url)
            self.assertEqual(404, response.status_code, response.content[:1000])

        @skipIfNotSubclass(CreateModelMixin)
        @patch('dojo.api_v2.permissions.user_has_permission')
        def test_create_object_not_authorized(self, mock):
            if not self.test_type == TestType.OBJECT_PERMISSIONS:
                self.skipTest('Authorization is not object based')

            mock.return_value = False

            response = self.client.post(self.url, self.payload)
            self.assertEqual(403, response.status_code, response.content[:1000])
            mock.assert_called_with(User.objects.get(username='admin'),
                ANY,
                self.permission_create)

        @skipIfNotSubclass(DestroyModelMixin)
        @patch('dojo.api_v2.permissions.user_has_permission')
        def test_delete_object_not_authorized(self, mock):
            if not self.test_type == TestType.OBJECT_PERMISSIONS:
                self.skipTest('Authorization is not object based')

            mock.return_value = False

            current_objects = self.client.get(self.url, format='json').data
            relative_url = self.url + '%s/' % current_objects['results'][0]['id']
            response = self.client.delete(relative_url)

            if self.endpoint_model == Endpoint_Status:
                permission_object = Endpoint.objects.get(id=current_objects['results'][0]['endpoint'])
            elif self.endpoint_model == JIRA_Issue:
                permission_object = Finding.objects.get(id=current_objects['results'][0]['finding'])
            else:
                permission_object = self.permission_check_class.objects.get(id=current_objects['results'][0]['id'])

            mock.assert_called_with(User.objects.get(username='admin'),
                permission_object,
                self.permission_delete)

        @skipIfNotSubclass(UpdateModelMixin)
        @patch('dojo.api_v2.permissions.user_has_permission')
        def test_update_object_not_authorized(self, mock):
            if not self.test_type == TestType.OBJECT_PERMISSIONS:
                self.skipTest('Authorization is not object based')

            mock.return_value = False

            current_objects = self.client.get(self.url, format='json').data
            relative_url = self.url + '%s/' % current_objects['results'][0]['id']

            if self.endpoint_model == Endpoint_Status:
                permission_object = Endpoint.objects.get(id=current_objects['results'][0]['endpoint'])
            elif self.endpoint_model == JIRA_Issue:
                permission_object = Finding.objects.get(id=current_objects['results'][0]['finding'])
            else:
                permission_object = self.permission_check_class.objects.get(id=current_objects['results'][0]['id'])

            response = self.client.patch(relative_url, self.update_fields)
            self.assertEqual(403, response.status_code, response.content[:1000])
            mock.assert_called_with(User.objects.get(username='admin'),
                permission_object,
                self.permission_update)

            response = self.client.put(relative_url, self.payload)
            self.assertEqual(403, response.status_code, response.content[:1000])
            mock.assert_called_with(User.objects.get(username='admin'),
                permission_object,
                self.permission_update)

        @skipIfNotSubclass(ListModelMixin)
        def test_list_configuration_not_authorized(self):
            if not self.test_type == TestType.CONFIGURATION_PERMISSIONS:
                self.skipTest('Authorization is not configuration based')

            self.setUp_not_authorized()

            response = self.client.get(self.url, format='json')
            self.assertEqual(403, response.status_code, response.content[:1000])

        @skipIfNotSubclass(RetrieveModelMixin)
        def test_detail_configuration_not_authorized(self):
            if not self.test_type == TestType.CONFIGURATION_PERMISSIONS:
                self.skipTest('Authorization is not configuration based')

            self.setUp_not_authorized()

            current_objects = self.endpoint_model.objects.all()
            relative_url = self.url + '%s/' % current_objects[0].id
            response = self.client.get(relative_url)
            self.assertEqual(403, response.status_code, response.content[:1000])

        @skipIfNotSubclass(CreateModelMixin)
        def test_create_configuration_not_authorized(self):
            if not self.test_type == TestType.CONFIGURATION_PERMISSIONS:
                self.skipTest('Authorization is not configuration based')

            self.setUp_not_authorized()

            response = self.client.post(self.url, self.payload)
            self.assertEqual(403, response.status_code, response.content[:1000])

        @skipIfNotSubclass(DestroyModelMixin)
        def test_delete_configuration_not_authorized(self):
            if not self.test_type == TestType.CONFIGURATION_PERMISSIONS:
                self.skipTest('Authorization is not configuration based')

            self.setUp_not_authorized()

            current_objects = self.endpoint_model.objects.all()
            relative_url = self.url + '%s/' % current_objects[0].id
            response = self.client.delete(relative_url)
            self.assertEqual(403, response.status_code, response.content[:1000])

        @skipIfNotSubclass(UpdateModelMixin)
        def test_update_configuration_not_authorized(self):
            if not self.test_type == TestType.CONFIGURATION_PERMISSIONS:
                self.skipTest('Authorization is not configuration based')

            self.setUp_not_authorized()

            current_objects = self.endpoint_model.objects.all()
            relative_url = self.url + '%s/' % current_objects[0].id

            response = self.client.patch(relative_url, self.update_fields)
            self.assertEqual(403, response.status_code, response.content[:1000])

            response = self.client.put(relative_url, self.payload)
            self.assertEqual(403, response.status_code, response.content[:1000])

    class MemberEndpointTest(RESTEndpointTest):
        def __init__(self, *args, **kwargs):
            BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)

        def test_update(self):
            current_objects = self.client.get(self.url, format='json').data
            relative_url = self.url + '%s/' % current_objects['results'][0]['id']
            response = self.client.patch(relative_url, self.update_fields)
            self.assertEqual(405, response.status_code, response.content[:1000])

            response = self.client.put(
                relative_url, self.payload)
            self.assertEqual(200, response.status_code, response.content[:1000])
            self.check_schema_response('put', '200', response, detail=True)

        @skipIfNotSubclass(UpdateModelMixin)
        @patch('dojo.api_v2.permissions.user_has_permission')
        def test_update_object_not_authorized(self, mock):
            if not self.test_type == TestType.OBJECT_PERMISSIONS:
                self.skipTest('Authorization is not object based')

            mock.return_value = False

            current_objects = self.client.get(self.url, format='json').data
            relative_url = self.url + '%s/' % current_objects['results'][0]['id']

            response = self.client.put(relative_url, self.payload)
            self.assertEqual(403, response.status_code, response.content[:1000])
            mock.assert_called_with(User.objects.get(username='admin'),
                self.permission_check_class.objects.get(id=current_objects['results'][0]['id']),
                self.permission_update)

    class AuthenticatedViewTest(RESTEndpointTest):
        def __init__(self, *args, **kwargs):
            BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)

        @skipIfNotSubclass(ListModelMixin)
        def test_list_configuration_not_authorized(self):
            if not self.test_type == TestType.CONFIGURATION_PERMISSIONS:
                self.skipTest('Authorization is not configuration based')

            self.setUp_not_authorized()

            response = self.client.get(self.url, format='json')
            self.assertEqual(200, response.status_code, response.content[:1000])

        @skipIfNotSubclass(RetrieveModelMixin)
        def test_detail_configuration_not_authorized(self):
            if not self.test_type == TestType.CONFIGURATION_PERMISSIONS:
                self.skipTest('Authorization is not configuration based')

            self.setUp_not_authorized()

            current_objects = self.endpoint_model.objects.all()
            relative_url = self.url + '%s/' % current_objects[0].id
            response = self.client.get(relative_url)
            self.assertEqual(200, response.status_code, response.content[:1000])


class AppAnalysisTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = App_Analysis
        self.endpoint_path = 'technologies'
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
        self.test_type = TestType.OBJECT_PERMISSIONS
        self.permission_check_class = Product
        self.permission_create = Permissions.Technology_Add
        self.permission_update = Permissions.Technology_Edit
        self.permission_delete = Permissions.Technology_Delete
        self.deleted_objects = 1
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class EndpointStatusTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Endpoint_Status
        self.endpoint_path = 'endpoint_status'
        self.viewname = 'endpoint_status'
        self.viewset = EndpointStatusViewSet
        self.payload = {
            'endpoint': 2,
            'finding': 3,
            'mitigated': False,
            'false_positive': False,
            'risk_accepted': False,
            'out_of_scope': False,
            "date": "2017-01-12",
        }
        self.update_fields = {'mitigated': True}
        self.test_type = TestType.OBJECT_PERMISSIONS
        self.permission_check_class = Endpoint
        self.permission_create = Permissions.Endpoint_Edit
        self.permission_update = Permissions.Endpoint_Edit
        self.permission_delete = Permissions.Endpoint_Edit
        self.deleted_objects = 1
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)

    def test_create_unsuccessful(self):
        unsucessful_payload = self.payload.copy()
        unsucessful_payload['finding'] = 2
        response = self.client.post(self.url, unsucessful_payload)
        logger.debug('test_create_response:')
        logger.debug(response)
        logger.debug(response.data)
        self.assertEqual(400, response.status_code, response.content[:1000])
        self.assertIn('This endpoint-finding relation already exists', response.content.decode("utf-8"))

    def test_create_minimal(self):
        # This call should not fail even if there is not date defined
        minimal_payload = {
            'endpoint': 1,
            'finding': 3,
        }
        response = self.client.post(self.url, minimal_payload)
        logger.debug('test_create_response:')
        logger.debug(response)
        logger.debug(response.data)
        self.assertEqual(201, response.status_code, response.content[:1000])

    def test_update_patch_unsuccessful(self):
        anoher_finding_payload = self.payload.copy()
        anoher_finding_payload['finding'] = 3
        response = self.client.post(self.url, anoher_finding_payload)

        current_objects = self.client.get(self.url, format='json').data

        object1 = current_objects['results'][0]
        object2 = current_objects['results'][1]

        unsucessful_payload = {
            'endpoint': object2['endpoint'],
            'finding': object2['finding']
        }

        relative_url = self.url + '%s/' % object1['id']

        response = self.client.patch(relative_url, unsucessful_payload)
        self.assertEqual(400, response.status_code, response.content[:1000])
        self.assertIn('This endpoint-finding relation already exists', response.content.decode("utf-8"))

    def test_update_put_unsuccessful(self):
        anoher_finding_payload = self.payload.copy()
        anoher_finding_payload['finding'] = 3
        response = self.client.post(self.url, anoher_finding_payload)

        current_objects = self.client.get(self.url, format='json').data

        object1 = current_objects['results'][0]
        object2 = current_objects['results'][1]

        unsucessful_payload = {
            'endpoint': object2['endpoint'],
            'finding': object2['finding']
        }

        relative_url = self.url + '%s/' % object1['id']

        response = self.client.put(relative_url, unsucessful_payload)
        self.assertEqual(400, response.status_code, response.content[:1000])
        self.assertIn('This endpoint-finding relation already exists', response.content.decode("utf-8"))


class EndpointTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Endpoint
        self.endpoint_path = 'endpoints'
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
        self.update_fields = {'protocol': 'ftp', 'tags': ['one_new_tag']}
        self.test_type = TestType.OBJECT_PERMISSIONS
        self.permission_check_class = Endpoint
        self.permission_create = Permissions.Endpoint_Add
        self.permission_update = Permissions.Endpoint_Edit
        self.permission_delete = Permissions.Endpoint_Delete
        self.deleted_objects = 2
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class EngagementTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Engagement
        self.endpoint_path = 'engagements'
        self.viewname = 'engagement'
        self.viewset = EngagementViewSet
        self.payload = {
            "engagement_type": 'Interactive',
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
        self.test_type = TestType.OBJECT_PERMISSIONS
        self.permission_check_class = Engagement
        self.permission_create = Permissions.Engagement_Add
        self.permission_update = Permissions.Engagement_Edit
        self.permission_delete = Permissions.Engagement_Delete
        self.deleted_objects = 23
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class RiskAcceptanceTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Risk_Acceptance
        self.endpoint_path = 'risk_acceptance'
        self.viewname = 'risk_acceptance'
        self.viewset = RiskAcceptanceViewSet
        self.test_type = TestType.OBJECT_PERMISSIONS
        self.permission_check_class = Risk_Acceptance
        self.permission_delete = Permissions.Risk_Acceptance
        self.deleted_objects = 3
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class FindingRequestResponseTest(DojoAPITestCase):
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
        self.assertEqual(200, response.status_code, response.content[:1000])
        self.assertEqual(BurpRawRequestResponse.objects.count(), length + 1)

    def test_request_response_get(self):
        response = self.client.get('/api/v2/findings/7/request_response/', format='json')
        # print('response.data:')
        # print(response.data)
        self.assertEqual(200, response.status_code, response.content[:1000])


class FilesTest(DojoAPITestCase):
    fixtures = ['dojo_testdata.json']

    def setUp(self):
        testuser = User.objects.get(username='admin')
        token = Token.objects.get(user=testuser)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')
        self.path = pathlib.Path(__file__).parent.absolute()
        # model: file_id
        self.url_levels = {
            'findings/7': 0,
            'tests/3': 0,
            'engagements/1': 0
        }

    def test_request_response_post_and_download(self):
        # Test the creation
        for level in self.url_levels.keys():
            length = FileUpload.objects.count()
            payload = {
                "title": level,
                "file": open(f'{str(self.path)}/scans/acunetix/one_finding.xml', 'r')
            }
            response = self.client.post(f'/api/v2/{level}/files/', payload)
            self.assertEqual(201, response.status_code, response.data)
            self.assertEqual(FileUpload.objects.count(), length + 1)
            # Save the ID of the newly created file object
            self.url_levels[level] = response.data.get('id')
        #  Test the download
        with open(f'{str(self.path)}/scans/acunetix/one_finding.xml', 'r') as file:
            file_data = file.read()
        for level, file_id in self.url_levels.items():
            response = self.client.get(f'/api/v2/{level}/files/download/{file_id}/')
            self.assertEqual(200, response.status_code)
            downloaded_file = b''.join(response.streaming_content).decode().replace('\\n', '\n')
            self.assertEqual(file_data, downloaded_file)

    def test_request_response_get(self):
        for level in self.url_levels.keys():
            response = self.client.get(f'/api/v2/{level}/files/')
            self.assertEqual(200, response.status_code)


class FindingsTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Finding
        self.endpoint_path = 'findings'
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
            "title": "DUMMY FINDING123",
            "date": "2020-05-20",
            "cwe": 1,
            "severity": "HIGH",
            "description": "TEST finding",
            "mitigation": "MITIGATION",
            "impact": "HIGH",
            "references": "",
            "reporter": 3,
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
            "files": [],
            "tags": ['tag1', 'tag_2'],
        }
        self.update_fields = {'duplicate': False, 'active': True, "push_to_jira": "True", 'tags': ['finding_tag_new']}
        self.test_type = TestType.OBJECT_PERMISSIONS
        self.permission_check_class = Finding
        self.permission_create = Permissions.Finding_Add
        self.permission_update = Permissions.Finding_Edit
        self.permission_delete = Permissions.Finding_Delete
        self.deleted_objects = 2
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)

    def test_duplicate(self):
        # Reassign duplicate
        result = self.client.post(self.url + "2/original/3/")
        self.assertEqual(result.status_code, status.HTTP_204_NO_CONTENT, "Could not move duplicate")
        result = self.client.get(self.url + "2/")
        self.assertEqual(result.status_code, status.HTTP_200_OK, "Could not check new duplicate")
        result_json = result.json()
        assert result_json["duplicate"]
        assert result_json["duplicate_finding"] == 3

        # Check duplicate status
        result = self.client.get(self.url + "3/duplicate/")
        assert result.status_code == status.HTTP_200_OK, "Could not check duplicate status"
        result_json = result.json()
        # Should return all duplicates for id=3
        assert set(x["id"] for x in result_json) == {2, 4, 5, 6}

        # Reset duplicate
        result = self.client.post(self.url + "2/duplicate/reset/")
        self.assertEqual(result.status_code, status.HTTP_204_NO_CONTENT, "Could not reset duplicate")
        new_result = self.client.get(self.url + "2/")
        self.assertEqual(result.status_code, status.HTTP_204_NO_CONTENT, "Could not check reset duplicate status")
        result_json = new_result.json()
        assert not result_json["duplicate"]
        assert result_json["duplicate_finding"] is None

    def test_filter_steps_to_reproduce(self):
        # Confirm initial data
        result = self.client.get(self.url + '?steps_to_reproduce=lorem')
        self.assertEqual(result.status_code, status.HTTP_200_OK, "Could not filter on steps_to_reproduce")
        result_json = result.json()
        assert result_json["count"] == 0

        # Set steps to reproduce
        result = self.client.patch(self.url + "2/", data={"steps_to_reproduce": "Lorem ipsum dolor sit amet"})
        self.assertEqual(result.status_code, status.HTTP_200_OK, "Could not patch finding with steps to reproduce")
        assert result.json()["steps_to_reproduce"] == "Lorem ipsum dolor sit amet"
        result = self.client.patch(self.url + "3/", data={"steps_to_reproduce": "Ut enim ad minim veniam"})
        self.assertEqual(result.status_code, status.HTTP_200_OK, "Could not patch finding with steps to reproduce")
        assert result.json()["steps_to_reproduce"] == "Ut enim ad minim veniam"

        # Test
        result = self.client.get(self.url + "?steps_to_reproduce=lorem")
        self.assertEqual(result.status_code, status.HTTP_200_OK, "Could not filter on steps_to_reproduce")
        result_json = result.json()
        assert result_json["count"] == 1
        assert result_json["results"][0]["id"] == 2
        assert result_json["results"][0]["steps_to_reproduce"] == "Lorem ipsum dolor sit amet"

        # Set steps to reproduce
        result = self.client.patch(self.url + "2/", data={"steps_to_reproduce": ""})
        self.assertEqual(result.status_code, status.HTTP_200_OK, "Could not patch finding with steps to reproduce")
        assert result.json()["steps_to_reproduce"] == ""
        result = self.client.patch(self.url + "3/", data={"steps_to_reproduce": ""})
        self.assertEqual(result.status_code, status.HTTP_200_OK, "Could not patch finding with steps to reproduce")
        assert result.json()["steps_to_reproduce"] == ""


class FindingMetadataTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Finding
        self.endpoint_path = 'findings'
        self.viewname = 'finding'
        self.viewset = FindingViewSet
        self.payload = {}
        self.test_type = TestType.STANDARD
        self.deleted_objects = 3
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)

    def setUp(self):
        super().setUp()
        testuser = User.objects.get(username='admin')
        token = Token.objects.get(user=testuser)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)
        self.url = reverse(self.viewname + '-list')

        self.current_findings = self.client.get(self.url, format='json').data["results"]
        finding = Finding.objects.get(id=self.current_findings[0]['id'])

        self.base_url = f"{self.url}{self.current_findings[0]['id']}/metadata/"
        metadata = DojoMeta(finding=finding, name="test_meta", value="20")
        metadata.save()

    def test_create(self):
        response = self.client.post(self.base_url, data={"name": "test_meta2", "value": "40"})
        self.assertEqual(200, response.status_code, response.data)

        results = self.client.get(self.base_url).data
        for result in results:
            if result["name"] == "test_meta2" and result["value"] == "40":
                return

        assert False, "Metadata was not created correctly"

    def test_create_duplicate(self):
        result = self.client.post(self.base_url, data={"name": "test_meta", "value": "40"})
        assert result.status_code == status.HTTP_400_BAD_REQUEST, "Metadata creation did not failed on duplicate"

    def test_get(self):
        results = self.client.get(self.base_url, format="json").data
        for result in results:
            if result["name"] == "test_meta" and result["value"] == "20":
                return

        assert False, "Metadata was not created correctly"

    def test_update(self):
        self.client.put(self.base_url + "?name=test_meta", data={"name": "test_meta", "value": "40"})
        result = self.client.get(self.base_url).data[0]
        assert result["name"] == "test_meta" and result["value"] == "40", "Metadata not edited correctly"

    def test_delete(self):
        self.client.delete(self.base_url + "?name=test_meta")
        result = self.client.get(self.base_url).data
        assert len(result) == 0, "Metadata not deleted correctly"


class FindingTemplatesTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Finding_Template
        self.endpoint_path = 'finding_templates'
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
        self.test_type = TestType.CONFIGURATION_PERMISSIONS
        self.deleted_objects = 1
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class JiraInstancesTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = JIRA_Instance
        self.endpoint_path = 'jira_instances'
        self.viewname = 'jira_instance'
        self.viewset = JiraInstanceViewSet
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
        self.test_type = TestType.CONFIGURATION_PERMISSIONS
        self.deleted_objects = 1
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class JiraIssuesTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = JIRA_Issue
        self.endpoint_path = 'jira_finding_mappings'
        self.viewname = 'jira_issue'
        self.viewset = JiraIssuesViewSet
        self.payload = {
            "jira_id": "JIRA 1",
            "jira_key": "SOME KEY",
            "finding": 2,
        }
        self.update_fields = {'jira_change': '2022-01-02T13:47:38.021481Z'}
        self.test_type = TestType.OBJECT_PERMISSIONS
        self.permission_check_class = Finding
        self.permission_create = Permissions.Finding_Edit
        self.permission_update = Permissions.Finding_Edit
        self.permission_delete = Permissions.Finding_Edit
        self.deleted_objects = 1
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class JiraProjectTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = JIRA_Project
        self.endpoint_path = 'jira_projects'
        self.viewname = 'jira_project'
        self.viewset = JiraProjectViewSet
        self.payload = {
            "project_key": "TEST KEY",
            "component": "",
            "push_all_issues": False,
            "enable_engagement_epic_mapping": False,
            "push_notes": False,
            "product": 1,
            "jira_instance": 2,
        }
        self.update_fields = {'jira_instance': 3}
        self.test_type = TestType.OBJECT_PERMISSIONS
        self.permission_check_class = Product
        self.permission_create = Permissions.Product_Edit
        self.permission_update = Permissions.Product_Edit
        self.permission_delete = Permissions.Product_Edit
        self.deleted_objects = 1
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class SonarqubeIssueTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Sonarqube_Issue
        self.endpoint_path = 'sonarqube_issues'
        self.viewname = 'sonarqube_issue'
        self.viewset = SonarqubeIssueViewSet
        self.payload = {
            "key": "AREwS5n5TxsFUNm31CxP",
            "status": "OPEN",
            "type": "VULNERABILITY"
        }
        self.update_fields = {'key': 'AREwS5n5TxsFUNm31CxP'}
        self.test_type = TestType.STANDARD
        self.deleted_objects = 2
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class SonarqubeIssuesTransitionTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Sonarqube_Issue_Transition
        self.endpoint_path = 'sonarqube_transitions'
        self.viewname = 'sonarqube_issue_transition'
        self.viewset = SonarqubeIssuesTransitionTest
        self.payload = {
            "sonarqube_issue": 1,
            "finding_status": "Active, Verified",
            "sonarqube_status": "OPEN",
            "transitions": "confirm"
        }
        self.update_fields = {'sonarqube_status': 'CLOSED'}
        self.test_type = TestType.STANDARD
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class Product_API_Scan_ConfigurationTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Product_API_Scan_Configuration
        self.endpoint_path = 'product_api_scan_configurations'
        self.viewname = 'product_api_scan_configuration'
        self.viewset = ProductAPIScanConfigurationViewSet
        self.payload = {
            "product": 2,
            "service_key_1": "dojo_sonar_key",
            "tool_configuration": 3
        }
        self.update_fields = {'tool_configuration': 2}
        self.test_type = TestType.OBJECT_PERMISSIONS
        self.permission_check_class = Product_API_Scan_Configuration
        self.permission_create = Permissions.Product_API_Scan_Configuration_Add
        self.permission_update = Permissions.Product_API_Scan_Configuration_Edit
        self.permission_delete = Permissions.Product_API_Scan_Configuration_Delete
        self.deleted_objects = 1
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class ProductTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Product
        self.endpoint_path = 'products'
        self.viewname = 'product'
        self.viewset = ProductViewSet
        self.payload = {
            "product_manager": 2,
            "technical_contact": 3,
            "team_manager": 2,
            "prod_type": 1,
            "name": "Test Product",
            "description": "test product",
            "tags": ["mytag, yourtag"]
        }
        self.update_fields = {'prod_type': 2}
        self.test_type = TestType.OBJECT_PERMISSIONS
        self.permission_check_class = Product
        self.permission_create = Permissions.Product_Type_Add_Product
        self.permission_update = Permissions.Product_Edit
        self.permission_delete = Permissions.Product_Delete
        self.deleted_objects = 25
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class StubFindingsTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Stub_Finding
        self.endpoint_path = 'stub_findings'
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
        self.test_type = TestType.OBJECT_PERMISSIONS
        self.permission_check_class = Stub_Finding
        self.permission_create = Permissions.Finding_Add
        self.permission_update = Permissions.Finding_Edit
        self.permission_delete = Permissions.Finding_Delete
        self.deleted_objects = 1
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class TestsTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Test
        self.endpoint_path = 'tests'
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
            "tags": [],
            "version": "1.0",
            "branch_tag": "master",
            "commit_hash": "1234567890abcdefghijkl",
        }
        self.update_fields = {'percent_complete': 100}
        self.test_type = TestType.OBJECT_PERMISSIONS
        self.permission_check_class = Test
        self.permission_create = Permissions.Test_Add
        self.permission_update = Permissions.Test_Edit
        self.permission_delete = Permissions.Test_Delete
        self.deleted_objects = 18
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class ToolConfigurationsTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Tool_Configuration
        self.viewname = 'tool_configuration'
        self.endpoint_path = 'tool_configurations'
        self.viewset = ToolConfigurationsViewSet
        self.payload = {
            "url": "http://www.example.com",
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
        self.test_type = TestType.CONFIGURATION_PERMISSIONS
        self.deleted_objects = 2
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class ToolProductSettingsTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Tool_Product_Settings
        self.endpoint_path = 'tool_product_settings'
        self.viewname = 'tool_product_settings'
        self.viewset = ToolProductSettingsViewSet
        self.payload = {
            "setting_url": "http://www.example.com",
            "name": "Tool Product Setting",
            "description": "test tool product setting",
            "tool_project_id": "1",
            "tool_configuration": 3,
            "product": 2,
        }
        self.update_fields = {'tool_project_id': '2'}
        self.test_type = TestType.OBJECT_PERMISSIONS
        self.permission_check_class = Product
        self.permission_create = Permissions.Product_Edit
        self.permission_update = Permissions.Product_Edit
        self.permission_delete = Permissions.Product_Edit
        self.deleted_objects = 1
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class ToolTypesTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Tool_Type
        self.endpoint_path = 'tool_types'
        self.viewname = 'tool_type'
        self.viewset = ToolTypesViewSet
        self.payload = {
            "name": "Tool Type",
            "description": "test tool type"
        }
        self.update_fields = {'description': 'changed description'}
        self.test_type = TestType.CONFIGURATION_PERMISSIONS
        self.deleted_objects = 3
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class NoteTypesTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Note_Type
        self.endpoint_path = 'note_type'
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
        self.test_type = TestType.CONFIGURATION_PERMISSIONS
        self.deleted_objects = 1
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class NotesTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Notes
        self.endpoint_path = 'notes'
        self.viewname = 'notes'
        self.viewset = NotesViewSet
        self.payload = {
            "id": 1,
            "entry": "updated_entry",
            "author": '{"username": "admin"}',
            "editor": '{"username": "user1"}'
        }
        self.update_fields = {'entry': 'changed entry'}
        self.test_type = TestType.STANDARD
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class UsersTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = User
        self.endpoint_path = 'users'
        self.viewname = 'user'
        self.viewset = UsersViewSet
        self.payload = {
            "username": "test_user",
            "first_name": "test",
            "last_name": "user",
            "email": "example@email.com",
            "is_active": True,
            "configuration_permissions": [217, 218]
        }
        self.update_fields = {"first_name": "test changed", "configuration_permissions": [219, 220]}
        self.test_type = TestType.CONFIGURATION_PERMISSIONS
        self.deleted_objects = 18
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)

    def test_create_user_with_non_configuration_permissions(self):
        payload = self.payload.copy()
        payload['configuration_permissions'] = [25, 26]  # these permissions exist but user can not assign them becaause they are not "configuration_permissions"
        response = self.client.post(self.url, payload)
        self.assertEqual(response.status_code, 400)
        self.assertIn('object does not exist', response.data['message'])

    def test_update_user_with_non_configuration_permissions(self):
        payload = {}
        payload['configuration_permissions'] = [25, 26]  # these permissions exist but user can not assign them becaause they are not "configuration_permissions"
        response = self.client.patch(self.url + '3/', payload)
        self.assertEqual(response.status_code, 400)
        self.assertIn('object does not exist', response.data['message'])

    def test_update_user_other_permissions_will_not_leak_and_stay_untouched(self):
        payload = {}
        payload['configuration_permissions'] = [217, 218, 219]
        response = self.client.patch(self.url + '6/', payload)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['configuration_permissions'], payload['configuration_permissions'])
        user_permissions = User.objects.get(username='user5').user_permissions.all().values_list('id', flat=True)
        self.assertEqual(set(user_permissions), set(payload['configuration_permissions'] + [26, 28]))


class UserContactInfoTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = UserContactInfo
        self.endpoint_path = 'user_contact_infos'
        self.viewname = 'usercontactinfo'
        self.viewset = UserContactInfoViewSet
        self.payload = {
            "user": 4,
            "title": "Sir",
            "phone_number": "+999999999",
            "cell_number": "+999999999",
            "twitter_username": "defectdojo",
        }
        self.update_fields = {"title": "Lady"}
        self.test_type = TestType.STANDARD
        self.deleted_objects = 1
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class ProductPermissionTest(DojoAPITestCase):
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


class ImportScanTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Test
        self.endpoint_path = 'import-scan'
        self.viewname = 'importscan'
        self.viewset = ImportScanView
        self.payload = {
            "minimum_severity": 'Low',
            "active": False,
            "verified": True,
            "scan_type": 'ZAP Scan',
            "file": open('tests/zap_sample.xml'),
            "engagement": 1,
            "lead": 2,
            "tags": ["ci/cd", "api"],
            "version": "1.0.0",
        }
        self.test_type = TestType.OBJECT_PERMISSIONS
        self.permission_create = Permissions.Import_Scan_Result
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)

    @patch('dojo.importers.reimporter.reimporter.DojoDefaultReImporter.reimport_scan')
    @patch('dojo.importers.importer.importer.DojoDefaultImporter.import_scan')
    @patch('dojo.api_v2.permissions.user_has_permission')
    def test_create_not_authorized_product_name_engagement_name(self, mock, importer_mock, reimporter_mock):
        mock.return_value = False
        importer_mock.return_value = IMPORTER_MOCK_RETURN_VALUE
        reimporter_mock.return_value = REIMPORTER_MOCK_RETURN_VALUE

        payload = {
            "minimum_severity": 'Low',
            "active": False,
            "verified": True,
            "scan_type": 'ZAP Scan',
            "file": open('tests/zap_sample.xml'),
            "product_name": 'Python How-to',
            "engagement_name": 'April monthly engagement',
            "lead": 2,
            "tags": ["ci/cd", "api"],
            "version": "1.0.0",
        }

        response = self.client.post(self.url, payload)
        self.assertEqual(403, response.status_code, response.content[:1000])
        mock.assert_called_with(User.objects.get(username='admin'),
            Engagement.objects.get(id=2),  # engagement id found via product name and engagement name
            Permissions.Import_Scan_Result)
        importer_mock.assert_not_called()
        reimporter_mock.assert_not_called()

    @patch('dojo.importers.reimporter.reimporter.DojoDefaultReImporter.reimport_scan')
    @patch('dojo.importers.importer.importer.DojoDefaultImporter.import_scan')
    @patch('dojo.api_v2.permissions.user_has_permission')
    def test_create_not_authorized_product_name_engagement_name_auto_create_engagement(self, mock, importer_mock, reimporter_mock):
        mock.return_value = False
        importer_mock.return_value = IMPORTER_MOCK_RETURN_VALUE
        reimporter_mock.return_value = REIMPORTER_MOCK_RETURN_VALUE

        payload = {
            "minimum_severity": 'Low',
            "active": False,
            "verified": True,
            "scan_type": 'ZAP Scan',
            "file": open('tests/zap_sample.xml'),
            "product_name": 'Python How-to',
            "engagement_name": 'New engagement',
            "lead": 2,
            "tags": ["ci/cd", "api"],
            "version": "1.0.0",
            "auto_create_context": True
        }

        response = self.client.post(self.url, payload)
        self.assertEqual(403, response.status_code, response.content[:1000])
        mock.assert_called_with(User.objects.get(username='admin'),
            Product.objects.get(id=1),
            Permissions.Engagement_Add)
        importer_mock.assert_not_called()
        reimporter_mock.assert_not_called()

    @patch('dojo.importers.reimporter.reimporter.DojoDefaultReImporter.reimport_scan')
    @patch('dojo.importers.importer.importer.DojoDefaultImporter.import_scan')
    @patch('dojo.api_v2.permissions.user_has_permission')
    def test_create_not_authorized_product_name_engagement_name_auto_create_product(self, mock, importer_mock, reimporter_mock):
        mock.return_value = False
        importer_mock.return_value = IMPORTER_MOCK_RETURN_VALUE
        reimporter_mock.return_value = REIMPORTER_MOCK_RETURN_VALUE

        payload = {
            "minimum_severity": 'Low',
            "active": False,
            "verified": True,
            "scan_type": 'ZAP Scan',
            "file": open('tests/zap_sample.xml'),
            "product_type_name": "books",
            "product_name": 'New Product',
            "engagement_name": 'New engagement',
            "lead": 2,
            "tags": ["ci/cd", "api"],
            "version": "1.0.0",
            "auto_create_context": True
        }

        response = self.client.post(self.url, payload)
        self.assertEqual(403, response.status_code, response.content[:1000])
        mock.assert_called_with(User.objects.get(username='admin'),
            Product_Type.objects.get(id=1),
            Permissions.Product_Type_Add_Product)
        importer_mock.assert_not_called()
        reimporter_mock.assert_not_called()

    @patch('dojo.importers.reimporter.reimporter.DojoDefaultReImporter.reimport_scan')
    @patch('dojo.importers.importer.importer.DojoDefaultImporter.import_scan')
    @patch('dojo.api_v2.permissions.user_has_global_permission')
    def test_create_not_authorized_product_name_engagement_name_auto_create_product_type(self, mock, importer_mock, reimporter_mock):
        mock.return_value = False
        importer_mock.return_value = IMPORTER_MOCK_RETURN_VALUE
        reimporter_mock.return_value = REIMPORTER_MOCK_RETURN_VALUE

        payload = {
            "minimum_severity": 'Low',
            "active": False,
            "verified": True,
            "scan_type": 'ZAP Scan',
            "file": open('tests/zap_sample.xml'),
            "product_type_name": "more books",
            "product_name": 'New Product',
            "engagement_name": 'New engagement',
            "lead": 2,
            "tags": ["ci/cd", "api"],
            "version": "1.0.0",
            "auto_create_context": True
        }

        response = self.client.post(self.url, payload)
        self.assertEqual(403, response.status_code, response.content[:1000])
        mock.assert_called_with(User.objects.get(username='admin'),
            Permissions.Product_Type_Add)
        importer_mock.assert_not_called()
        reimporter_mock.assert_not_called()

    @patch('dojo.importers.reimporter.reimporter.DojoDefaultReImporter.reimport_scan')
    @patch('dojo.importers.importer.importer.DojoDefaultImporter.import_scan')
    @patch('dojo.api_v2.permissions.user_has_permission')
    def test_create_authorized_product_name_engagement_name_auto_create_engagement(self, mock, importer_mock, reimporter_mock):
        """
        Test creating a new engagement should also check for import scan permission in the product
        """
        mock.return_value = True
        importer_mock.return_value = IMPORTER_MOCK_RETURN_VALUE
        reimporter_mock.return_value = REIMPORTER_MOCK_RETURN_VALUE

        payload = {
            "minimum_severity": 'Low',
            "active": False,
            "verified": True,
            "scan_type": 'ZAP Scan',
            "file": open('tests/zap_sample.xml'),
            "product_name": 'Python How-to',
            "engagement_name": 'New engagement',
            "lead": 2,
            "tags": ["ci/cd", "api"],
            "version": "1.0.0",
            "auto_create_context": True
        }

        response = self.client.post(self.url, payload)
        self.assertEqual(201, response.status_code, response.content[:1000])
        mock.assert_has_calls([
            call(User.objects.get(username='admin'),
                Product.objects.get(id=1),
                Permissions.Engagement_Add),
            call(User.objects.get(username='admin'),
                Product.objects.get(id=1),
                Permissions.Import_Scan_Result)
        ])
        importer_mock.assert_called_once()
        reimporter_mock.assert_not_called()

    @patch('dojo.importers.reimporter.reimporter.DojoDefaultReImporter.reimport_scan')
    @patch('dojo.importers.importer.importer.DojoDefaultImporter.import_scan')
    @patch('dojo.api_v2.permissions.user_has_permission')
    def test_create_authorized_product_name_engagement_name_auto_create_product(self, mock, importer_mock, reimporter_mock):
        mock.return_value = True
        importer_mock.return_value = IMPORTER_MOCK_RETURN_VALUE
        reimporter_mock.return_value = REIMPORTER_MOCK_RETURN_VALUE

        payload = {
            "minimum_severity": 'Low',
            "active": False,
            "verified": True,
            "scan_type": 'ZAP Scan',
            "file": open('tests/zap_sample.xml'),
            "product_type_name": "books",
            "product_name": 'New Product',
            "engagement_name": 'New engagement',
            "lead": 2,
            "tags": ["ci/cd", "api"],
            "version": "1.0.0",
            "auto_create_context": True
        }

        response = self.client.post(self.url, payload)
        self.assertEqual(201, response.status_code, response.content[:1000])
        mock.assert_called_with(User.objects.get(username='admin'),
            Product_Type.objects.get(id=1),
            Permissions.Product_Type_Add_Product)
        importer_mock.assert_called_once()
        reimporter_mock.assert_not_called()

    @patch('dojo.importers.reimporter.reimporter.DojoDefaultReImporter.reimport_scan')
    @patch('dojo.importers.importer.importer.DojoDefaultImporter.import_scan')
    @patch('dojo.api_v2.permissions.user_has_global_permission')
    def test_create_authorized_product_name_engagement_name_auto_create_product_type(self, mock, importer_mock, reimporter_mock):
        mock.return_value = True
        importer_mock.return_value = IMPORTER_MOCK_RETURN_VALUE
        reimporter_mock.return_value = REIMPORTER_MOCK_RETURN_VALUE

        payload = {
            "minimum_severity": 'Low',
            "active": False,
            "verified": True,
            "scan_type": 'ZAP Scan',
            "file": open('tests/zap_sample.xml'),
            "product_type_name": "more books",
            "product_name": 'New Product',
            "engagement_name": 'New engagement',
            "lead": 2,
            "tags": ["ci/cd", "api"],
            "version": "1.0.0",
            "auto_create_context": True
        }

        response = self.client.post(self.url, payload)
        self.assertEqual(201, response.status_code, response.content[:1000])
        mock.assert_called_with(User.objects.get(username='admin'),
            Permissions.Product_Type_Add)
        importer_mock.assert_called_once()
        reimporter_mock.assert_not_called()


class ReimportScanTest(DojoAPITestCase):
    fixtures = ['dojo_testdata.json']

    def setUp(self):
        testuser = User.objects.get(username='admin')
        token = Token.objects.get(user=testuser)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)
        self.url = reverse('reimportscan' + '-list')

    # Specific tests for reimport

    @patch('dojo.importers.reimporter.reimporter.DojoDefaultReImporter.reimport_scan')
    @patch('dojo.importers.importer.importer.DojoDefaultImporter.import_scan')
    def test_reimport_zap_xml(self, importer_mock, reimporter_mock):
        importer_mock.return_value = IMPORTER_MOCK_RETURN_VALUE
        reimporter_mock.return_value = REIMPORTER_MOCK_RETURN_VALUE

        length = Test.objects.all().count()
        response = self.client.post(
            reverse('reimportscan-list'), {
                "minimum_severity": 'Low',
                "active": True,
                "verified": True,
                "scan_type": 'ZAP Scan',
                "file": open('tests/zap_sample.xml'),
                "test": 3,
                "version": "1.0.1",
            })
        self.assertEqual(length, Test.objects.all().count())
        self.assertEqual(201, response.status_code, response.content[:1000])
        # TODO add schema check
        importer_mock.assert_not_called()
        reimporter_mock.assert_called_once()

    @patch('dojo.importers.reimporter.reimporter.DojoDefaultReImporter.reimport_scan')
    @patch('dojo.importers.importer.importer.DojoDefaultImporter.import_scan')
    @patch('dojo.api_v2.permissions.user_has_permission')
    def test_create_not_authorized_product_name_engagement_name(self, mock, importer_mock, reimporter_mock):
        mock.return_value = False
        importer_mock.return_value = IMPORTER_MOCK_RETURN_VALUE
        reimporter_mock.return_value = REIMPORTER_MOCK_RETURN_VALUE

        payload = {
            "minimum_severity": 'Low',
            "active": False,
            "verified": True,
            "scan_type": 'ZAP Scan',
            "file": open('tests/zap_sample.xml'),
            "product_name": 'Security How-to',
            "engagement_name": 'April monthly engagement',
            "lead": 2,
            "tags": ["ci/cd", "api"],
            "version": "1.0.0",
        }

        response = self.client.post(self.url, payload)
        self.assertEqual(403, response.status_code, response.content[:1000])
        mock.assert_called_with(User.objects.get(username='admin'),
            Test.objects.get(id=4),  # test id found via product name and engagement name and scan_type
            Permissions.Import_Scan_Result)
        importer_mock.assert_not_called()
        reimporter_mock.assert_not_called()

    @patch('dojo.importers.reimporter.reimporter.DojoDefaultReImporter.reimport_scan')
    @patch('dojo.importers.importer.importer.DojoDefaultImporter.import_scan')
    @patch('dojo.api_v2.permissions.user_has_permission')
    def test_create_authorized_product_name_engagement_name_scan_type_title_auto_create(self, mock, importer_mock, reimporter_mock):
        mock.return_value = True
        importer_mock.return_value = IMPORTER_MOCK_RETURN_VALUE
        reimporter_mock.return_value = REIMPORTER_MOCK_RETURN_VALUE

        payload = {
            "minimum_severity": 'Low',
            "active": False,
            "verified": True,
            "scan_type": 'ZAP Scan',
            "file": open('tests/zap_sample.xml'),
            "product_name": 'Security How-to',
            "engagement_name": 'April monthly engagement',
            "test_title": 'My ZAP Scan NEW',
            "version": "1.0.0",
            "auto_create_context": True,
        }

        response = self.client.post(self.url, payload)
        self.assertEqual(201, response.status_code, response.content[:1000])
        mock.assert_called_with(User.objects.get(username='admin'),
            Engagement.objects.get(id=4),
            Permissions.Import_Scan_Result)
        importer_mock.assert_called_once()
        reimporter_mock.assert_not_called()

    @patch('dojo.importers.reimporter.reimporter.DojoDefaultReImporter.reimport_scan')
    @patch('dojo.importers.importer.importer.DojoDefaultImporter.import_scan')
    @patch('dojo.api_v2.permissions.user_has_permission')
    def test_create_authorized_product_name_engagement_name_auto_create_engagement(self, mock, importer_mock, reimporter_mock):
        """
        Test creating a new engagement should also check for import scan permission in the product
        """
        mock.return_value = True
        importer_mock.return_value = IMPORTER_MOCK_RETURN_VALUE
        reimporter_mock.return_value = REIMPORTER_MOCK_RETURN_VALUE

        payload = {
            "minimum_severity": 'Low',
            "active": False,
            "verified": True,
            "scan_type": 'ZAP Scan',
            "file": open('tests/zap_sample.xml'),
            "product_name": 'Python How-to',
            "engagement_name": 'New engagement',
            "lead": 2,
            "tags": ["ci/cd", "api"],
            "version": "1.0.0",
            "auto_create_context": True
        }

        response = self.client.post(self.url, payload)
        self.assertEqual(201, response.status_code, response.content[:1000])
        mock.assert_has_calls([
            call(User.objects.get(username='admin'),
                Product.objects.get(id=1),
                Permissions.Engagement_Add),
            call(User.objects.get(username='admin'),
                Product.objects.get(id=1),
                Permissions.Import_Scan_Result)
        ])
        importer_mock.assert_called_once()
        reimporter_mock.assert_not_called()

    @patch('dojo.importers.reimporter.reimporter.DojoDefaultReImporter.reimport_scan')
    @patch('dojo.importers.importer.importer.DojoDefaultImporter.import_scan')
    @patch('dojo.api_v2.permissions.user_has_permission')
    def test_create_authorized_product_name_engagement_name_auto_create_product(self, mock, importer_mock, reimporter_mock):
        mock.return_value = True
        importer_mock.return_value = IMPORTER_MOCK_RETURN_VALUE
        reimporter_mock.return_value = REIMPORTER_MOCK_RETURN_VALUE

        payload = {
            "minimum_severity": 'Low',
            "active": False,
            "verified": True,
            "scan_type": 'ZAP Scan',
            "file": open('tests/zap_sample.xml'),
            "product_type_name": "books",
            "product_name": 'New Product',
            "engagement_name": 'New engagement',
            "lead": 2,
            "tags": ["ci/cd", "api"],
            "version": "1.0.0",
            "auto_create_context": True
        }

        response = self.client.post(self.url, payload)
        self.assertEqual(201, response.status_code, response.content[:1000])
        mock.assert_called_with(User.objects.get(username='admin'),
            Product_Type.objects.get(id=1),
            Permissions.Product_Type_Add_Product)
        importer_mock.assert_called_once()
        reimporter_mock.assert_not_called()

    @patch('dojo.importers.reimporter.reimporter.DojoDefaultReImporter.reimport_scan')
    @patch('dojo.importers.importer.importer.DojoDefaultImporter.import_scan')
    @patch('dojo.api_v2.permissions.user_has_global_permission')
    def test_create_authorized_product_name_engagement_name_auto_create_product_type(self, mock, importer_mock, reimporter_mock):
        mock.return_value = True
        importer_mock.return_value = IMPORTER_MOCK_RETURN_VALUE
        reimporter_mock.return_value = REIMPORTER_MOCK_RETURN_VALUE

        payload = {
            "minimum_severity": 'Low',
            "active": False,
            "verified": True,
            "scan_type": 'ZAP Scan',
            "file": open('tests/zap_sample.xml'),
            "product_type_name": "more books",
            "product_name": 'New Product',
            "engagement_name": 'New engagement',
            "lead": 2,
            "tags": ["ci/cd", "api"],
            "version": "1.0.0",
            "auto_create_context": True
        }

        response = self.client.post(self.url, payload)
        self.assertEqual(201, response.status_code, response.content[:1000])
        mock.assert_called_with(User.objects.get(username='admin'),
            Permissions.Product_Type_Add)
        importer_mock.assert_called_once()
        reimporter_mock.assert_not_called()

    @patch('dojo.importers.reimporter.reimporter.DojoDefaultReImporter.reimport_scan')
    @patch('dojo.importers.importer.importer.DojoDefaultImporter.import_scan')
    @patch('dojo.api_v2.permissions.user_has_permission')
    def test_create_not_authorized_test_id(self, mock, importer_mock, reimporter_mock):
        mock.return_value = False
        importer_mock.return_value = IMPORTER_MOCK_RETURN_VALUE
        reimporter_mock.return_value = REIMPORTER_MOCK_RETURN_VALUE

        payload = {
                "minimum_severity": 'Low',
                "active": True,
                "verified": True,
                "scan_type": 'ZAP Scan',
                "file": open('tests/zap_sample.xml'),
                "test": 3,
                "version": "1.0.1"
        }
        response = self.client.post(self.url, payload)
        self.assertEqual(403, response.status_code, response.content[:1000])
        mock.assert_called_with(User.objects.get(username='admin'),
            Test.objects.get(id=3),
            Permissions.Import_Scan_Result)
        importer_mock.assert_not_called()
        reimporter_mock.assert_not_called()

    # copied tests from import, unsure how to use inheritance/mixins with test_ methods

    @patch('dojo.importers.reimporter.reimporter.DojoDefaultReImporter.reimport_scan')
    @patch('dojo.importers.importer.importer.DojoDefaultImporter.import_scan')
    @patch('dojo.api_v2.permissions.user_has_permission')
    def test_create_not_authorized_product_name_engagement_name_auto_create_engagement(self, mock, importer_mock, reimporter_mock):
        mock.return_value = False
        importer_mock.return_value = IMPORTER_MOCK_RETURN_VALUE
        reimporter_mock.return_value = REIMPORTER_MOCK_RETURN_VALUE

        payload = {
            "minimum_severity": 'Low',
            "active": False,
            "verified": True,
            "scan_type": 'ZAP Scan',
            "file": open('tests/zap_sample.xml'),
            "product_name": 'Python How-to',
            "engagement_name": 'New engagement',
            "lead": 2,
            "tags": ["ci/cd", "api"],
            "version": "1.0.0",
            "auto_create_context": True
        }

        response = self.client.post(self.url, payload)
        self.assertEqual(403, response.status_code, response.content[:1000])
        mock.assert_called_with(User.objects.get(username='admin'),
            Product.objects.get(id=1),
            Permissions.Engagement_Add)
        importer_mock.assert_not_called()
        reimporter_mock.assert_not_called()

    @patch('dojo.importers.reimporter.reimporter.DojoDefaultReImporter.reimport_scan')
    @patch('dojo.importers.importer.importer.DojoDefaultImporter.import_scan')
    @patch('dojo.api_v2.permissions.user_has_permission')
    def test_create_not_authorized_product_name_engagement_name_auto_create_product(self, mock, importer_mock, reimporter_mock):
        mock.return_value = False
        importer_mock.return_value = IMPORTER_MOCK_RETURN_VALUE
        reimporter_mock.return_value = REIMPORTER_MOCK_RETURN_VALUE

        payload = {
            "minimum_severity": 'Low',
            "active": False,
            "verified": True,
            "scan_type": 'ZAP Scan',
            "file": open('tests/zap_sample.xml'),
            "product_type_name": "books",
            "product_name": 'New Product',
            "engagement_name": 'New engagement',
            "lead": 2,
            "tags": ["ci/cd", "api"],
            "version": "1.0.0",
            "auto_create_context": True
        }

        response = self.client.post(self.url, payload)
        self.assertEqual(403, response.status_code, response.content[:1000])
        mock.assert_called_with(User.objects.get(username='admin'),
            Product_Type.objects.get(id=1),
            Permissions.Product_Type_Add_Product)
        importer_mock.assert_not_called()
        reimporter_mock.assert_not_called()

    @patch('dojo.importers.reimporter.reimporter.DojoDefaultReImporter.reimport_scan')
    @patch('dojo.importers.importer.importer.DojoDefaultImporter.import_scan')
    @patch('dojo.api_v2.permissions.user_has_global_permission')
    def test_create_not_authorized_product_name_engagement_name_auto_create_product_type(self, mock, importer_mock, reimporter_mock):
        mock.return_value = False
        importer_mock.return_value = IMPORTER_MOCK_RETURN_VALUE
        reimporter_mock.return_value = REIMPORTER_MOCK_RETURN_VALUE

        payload = {
            "minimum_severity": 'Low',
            "active": False,
            "verified": True,
            "scan_type": 'ZAP Scan',
            "file": open('tests/zap_sample.xml'),
            "product_type_name": "more books",
            "product_name": 'New Product',
            "engagement_name": 'New engagement',
            "lead": 2,
            "tags": ["ci/cd", "api"],
            "version": "1.0.0",
            "auto_create_context": True
        }

        response = self.client.post(self.url, payload)
        self.assertEqual(403, response.status_code, response.content[:1000])
        mock.assert_called_with(User.objects.get(username='admin'),
            Permissions.Product_Type_Add)
        importer_mock.assert_not_called()
        reimporter_mock.assert_not_called()

    @patch('dojo.importers.reimporter.reimporter.DojoDefaultReImporter.reimport_scan')
    @patch('dojo.importers.importer.importer.DojoDefaultImporter.import_scan')
    @patch('dojo.api_v2.permissions.user_has_permission')
    def test_create_not_authorized_product_name_engagement_name_scan_type(self, mock, importer_mock, reimporter_mock):
        mock.return_value = False
        importer_mock.return_value = IMPORTER_MOCK_RETURN_VALUE
        reimporter_mock.return_value = REIMPORTER_MOCK_RETURN_VALUE

        payload = {
            "minimum_severity": 'Low',
            "active": False,
            "verified": True,
            "scan_type": 'ZAP Scan',
            "file": open('tests/zap_sample.xml'),
            "product_name": 'Security How-to',
            "engagement_name": 'April monthly engagement',
            "version": "1.0.0",
        }

        response = self.client.post(self.url, payload)
        self.assertEqual(403, response.status_code, response.content[:1000])
        mock.assert_called_with(User.objects.get(username='admin'),
            Test.objects.get(id=4),  # engagement id found via product name and engagement name
            Permissions.Import_Scan_Result)
        importer_mock.assert_not_called()
        reimporter_mock.assert_not_called()

    @patch('dojo.importers.reimporter.reimporter.DojoDefaultReImporter.reimport_scan')
    @patch('dojo.importers.importer.importer.DojoDefaultImporter.import_scan')
    @patch('dojo.api_v2.permissions.user_has_permission')
    def test_create_not_authorized_product_name_engagement_name_scan_type_title(self, mock, importer_mock, reimporter_mock):
        mock.return_value = False
        importer_mock.return_value = IMPORTER_MOCK_RETURN_VALUE
        reimporter_mock.return_value = REIMPORTER_MOCK_RETURN_VALUE

        payload = {
            "minimum_severity": 'Low',
            "active": False,
            "verified": True,
            "scan_type": 'ZAP Scan',
            "file": open('tests/zap_sample.xml'),
            "product_name": 'Security How-to',
            "engagement_name": 'April monthly engagement',
            "test_title": 'My ZAP Scan',
            "version": "1.0.0",
        }

        response = self.client.post(self.url, payload)
        self.assertEqual(403, response.status_code, response.content[:1000])
        mock.assert_called_with(User.objects.get(username='admin'),
            Test.objects.get(id=4),  # test id found via product name and engagement name and scan_type and test_title
            Permissions.Import_Scan_Result)
        importer_mock.assert_not_called()
        reimporter_mock.assert_not_called()


class ProductTypeTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Product_Type
        self.endpoint_path = 'product_types'
        self.viewname = 'product_type'
        self.viewset = ProductTypeViewSet
        self.payload = {
            "name": "Test Product Type",
            "description": "Test",
            "key_product": True,
            "critical_product": False
        }
        self.update_fields = {'description': "changed"}
        self.test_type = TestType.OBJECT_PERMISSIONS
        self.permission_check_class = Product_Type
        self.permission_update = Permissions.Product_Type_Edit
        self.permission_delete = Permissions.Product_Type_Delete
        self.deleted_objects = 25
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)

    def test_create_object_not_authorized(self):
        self.setUp_not_authorized()

        response = self.client.post(self.url, self.payload)
        self.assertEqual(403, response.status_code, response.content[:1000])

    def test_create_not_authorized_reader(self):
        self.setUp_global_reader()

        response = self.client.post(self.url, self.payload)
        self.assertEqual(403, response.status_code, response.content[:1000])

    def test_create_authorized_owner(self):
        self.setUp_global_owner()

        response = self.client.post(self.url, self.payload)
        self.assertEqual(201, response.status_code, response.content[:1000])


class DojoGroupsTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Dojo_Group
        self.endpoint_path = 'dojo_groups'
        self.viewname = 'dojo_group'
        self.viewset = DojoGroupViewSet
        self.payload = {
            "name": "Test Group",
            "description": "Test",
            "configuration_permissions": [217, 218],
        }
        self.update_fields = {'description': "changed", "configuration_permissions": [219, 220]}
        self.test_type = TestType.OBJECT_PERMISSIONS
        self.permission_check_class = Dojo_Group
        self.permission_update = Permissions.Group_Edit
        self.permission_delete = Permissions.Group_Delete
        self.deleted_objects = 4
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)

    def test_list_object_not_authorized(self):
        self.setUp_not_authorized()

        response = self.client.get(self.url, format='json')
        self.assertEqual(403, response.status_code, response.content[:1000])

    def test_detail_object_not_authorized(self):
        self.setUp_not_authorized()

        current_objects = self.endpoint_model.objects.all()
        relative_url = self.url + '%s/' % current_objects[0].id
        response = self.client.get(relative_url)
        self.assertEqual(403, response.status_code, response.content[:1000])

    def test_create_object_not_authorized(self):
        self.setUp_not_authorized()

        response = self.client.post(self.url, self.payload)
        self.assertEqual(403, response.status_code, response.content[:1000])

    def test_create_group_with_non_configuration_permissions(self):
        payload = self.payload.copy()
        payload['configuration_permissions'] = [25, 26]  # these permissions exist but user can not assign them becaause they are not "configuration_permissions"
        response = self.client.post(self.url, payload)
        self.assertEqual(response.status_code, 400)
        self.assertIn('object does not exist', response.data['message'])

    def test_update_group_with_non_configuration_permissions(self):
        payload = {}
        payload['configuration_permissions'] = [25, 26]  # these permissions exist but user can not assign them becaause they are not "configuration_permissions"
        response = self.client.patch(self.url + '2/', payload)
        self.assertEqual(response.status_code, 400)
        self.assertIn('object does not exist', response.data['message'])

    def test_update_group_other_permissions_will_not_leak_and_stay_untouched(self):
        Dojo_Group.objects.get(name='Group 1 Testdata').auth_group.permissions.set([218, 220, 26, 28])  # I was trying to set this in 'dojo_testdata.json' but it hasn't sucessful
        payload = {}
        payload['configuration_permissions'] = [217, 218, 219]
        response = self.client.patch(self.url + '1/', payload)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['configuration_permissions'], payload['configuration_permissions'])
        permissions = Dojo_Group.objects.get(name='Group 1 Testdata').auth_group.permissions.all().values_list('id', flat=True)
        self.assertEqual(set(permissions), set(payload['configuration_permissions'] + [26, 28]))
        Dojo_Group.objects.get(name='Group 1 Testdata').auth_group.permissions.clear()


class DojoGroupsUsersTest(BaseClass.MemberEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Dojo_Group_Member
        self.endpoint_path = 'dojo_group_members'
        self.viewname = 'dojo_group_member'
        self.viewset = DojoGroupMemberViewSet
        self.payload = {
            "group": 1,
            "user": 3,
            "role": 4
        }
        self.update_fields = {'role': 3}
        self.test_type = TestType.OBJECT_PERMISSIONS
        self.permission_check_class = Dojo_Group_Member
        self.permission_create = Permissions.Group_Manage_Members
        self.permission_update = Permissions.Group_Manage_Members
        self.permission_delete = Permissions.Group_Member_Delete
        self.deleted_objects = 1
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class RolesTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Role
        self.endpoint_path = 'roles'
        self.viewname = 'role'
        self.viewset = RoleViewSet
        self.test_type = TestType.STANDARD
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class GlobalRolesTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Global_Role
        self.endpoint_path = 'global_roles'
        self.viewname = 'global_role'
        self.viewset = GlobalRoleViewSet
        self.payload = {
            "user": 2,
            "role": 2
        }
        self.update_fields = {'role': 3}
        self.test_type = TestType.STANDARD
        self.deleted_objects = 1
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class ProductTypeMemberTest(BaseClass.MemberEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Product_Type_Member
        self.endpoint_path = 'product_type_members'
        self.viewname = 'product_type_member'
        self.viewset = ProductTypeMemberViewSet
        self.payload = {
            "product_type": 1,
            "user": 3,
            "role": 2
        }
        self.update_fields = {'role': 3}
        self.test_type = TestType.OBJECT_PERMISSIONS
        self.permission_check_class = Product_Type_Member
        self.permission_create = Permissions.Product_Type_Manage_Members
        self.permission_update = Permissions.Product_Type_Manage_Members
        self.permission_delete = Permissions.Product_Type_Member_Delete
        self.deleted_objects = 1
        BaseClass.MemberEndpointTest.__init__(self, *args, **kwargs)


class ProductMemberTest(BaseClass.MemberEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Product_Member
        self.endpoint_path = 'product_members'
        self.viewname = 'product_member'
        self.viewset = ProductMemberViewSet
        self.payload = {
            "product": 3,
            "user": 2,
            "role": 2
        }
        self.update_fields = {'role': 3}
        self.test_type = TestType.OBJECT_PERMISSIONS
        self.permission_check_class = Product_Member
        self.permission_create = Permissions.Product_Manage_Members
        self.permission_update = Permissions.Product_Manage_Members
        self.permission_delete = Permissions.Product_Member_Delete
        self.deleted_objects = 1
        BaseClass.MemberEndpointTest.__init__(self, *args, **kwargs)


class ProductTypeGroupTest(BaseClass.MemberEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Product_Type_Group
        self.endpoint_path = 'product_type_groups'
        self.viewname = 'product_type_group'
        self.viewset = ProductTypeGroupViewSet
        self.payload = {
            "product_type": 1,
            "group": 2,
            "role": 2
        }
        self.update_fields = {'role': 3}
        self.test_type = TestType.OBJECT_PERMISSIONS
        self.permission_check_class = Product_Type_Group
        self.permission_create = Permissions.Product_Type_Group_Add
        self.permission_update = Permissions.Product_Type_Group_Edit
        self.permission_delete = Permissions.Product_Type_Group_Delete
        self.deleted_objects = 1
        BaseClass.MemberEndpointTest.__init__(self, *args, **kwargs)


class ProductGroupTest(BaseClass.MemberEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Product_Group
        self.endpoint_path = 'product_groups'
        self.viewname = 'product_group'
        self.viewset = ProductGroupViewSet
        self.payload = {
            "product": 1,
            "group": 2,
            "role": 2
        }
        self.update_fields = {'role': 3}
        self.test_type = TestType.OBJECT_PERMISSIONS
        self.permission_check_class = Product_Group
        self.permission_create = Permissions.Product_Group_Add
        self.permission_update = Permissions.Product_Group_Edit
        self.permission_delete = Permissions.Product_Group_Delete
        self.deleted_objects = 1
        BaseClass.MemberEndpointTest.__init__(self, *args, **kwargs)


class LanguageTypeTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Language_Type
        self.endpoint_path = 'language_types'
        self.viewname = 'language_type'
        self.viewset = LanguageTypeViewSet
        self.payload = {
            'language': 'Test',
            'color': 'red',
            'created': '2018-08-16T16:58:23.908Z'
        }
        self.update_fields = {'color': 'blue'}
        self.test_type = TestType.CONFIGURATION_PERMISSIONS
        self.deleted_objects = 2
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class LanguageTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Languages
        self.endpoint_path = 'languages'
        self.viewname = 'languages'
        self.viewset = LanguageViewSet
        self.payload = {
            'product': 1,
            'language': 2,
            'user': 1,
            'files': 2,
            'blank': 3,
            'comment': 4,
            'code': 5,
            'created': '2018-08-16T16:58:23.908Z'
        }
        self.update_fields = {'code': 10}
        self.test_type = TestType.OBJECT_PERMISSIONS
        self.permission_check_class = Languages
        self.permission_create = Permissions.Language_Add
        self.permission_update = Permissions.Language_Edit
        self.permission_delete = Permissions.Language_Delete
        self.deleted_objects = 1
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class ImportLanguagesTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Languages
        self.endpoint_path = 'import-languages'
        self.viewname = 'importlanguages'
        self.viewset = ImportLanguagesView
        self.payload = {
            'product': 1,
            'file': open("unittests/files/defectdojo_cloc.json")
        }
        self.test_type = TestType.OBJECT_PERMISSIONS
        self.permission_check_class = Languages
        self.permission_create = Permissions.Language_Add
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)

    def test_create(self):
        BaseClass.RESTEndpointTest.test_create(self)

        languages = Languages.objects.filter(product=1).order_by('language')

        self.assertEqual(2, len(languages))

        self.assertEqual(languages[0].product, Product.objects.get(id=1))
        self.assertEqual(languages[0].language, Language_Type.objects.get(id=1))
        self.assertEqual(languages[0].files, 21)
        self.assertEqual(languages[0].blank, 7)
        self.assertEqual(languages[0].comment, 0)
        self.assertEqual(languages[0].code, 63996)

        self.assertEqual(languages[1].product, Product.objects.get(id=1))
        self.assertEqual(languages[1].language, Language_Type.objects.get(id=2))
        self.assertEqual(languages[1].files, 432)
        self.assertEqual(languages[1].blank, 10813)
        self.assertEqual(languages[1].comment, 5054)
        self.assertEqual(languages[1].code, 51056)


class NotificationsTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Notifications
        self.endpoint_path = 'notifications'
        self.viewname = 'notifications'
        self.viewset = NotificationsViewSet
        self.payload = {
            'product': 1,
            'user': 3,
            'product_type_added': ["alert", "msteams"]
        }
        self.update_fields = {'product_added': ["alert", "msteams"]}
        self.test_type = TestType.STANDARD
        self.deleted_objects = 1
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class UserProfileTest(DojoAPITestCase):
    fixtures = ['dojo_testdata.json']

    def setUp(self):
        testuser = User.objects.get(username='admin')
        token = Token.objects.get(user=testuser)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)
        self.url = reverse('user_profile')

    def test_profile(self):
        response = self.client.get(reverse('user_profile'))
        data = json.loads(response.content)

        self.assertEqual(1, data['user']['id'])
        self.assertEqual('admin', data['user']['username'])
        self.assertTrue(data['user']['is_superuser'])
        self.assertEqual(1, data['user_contact_info']['user'])
        self.assertEqual('#admin', data['user_contact_info']['twitter_username'])
        self.assertEqual(1, data['global_role']['user'])
        self.assertEqual(4, data['global_role']['role'])
        self.assertEqual(1, data['dojo_group_member'][0]['user'])
        self.assertEqual(1, data['dojo_group_member'][0]['group'])
        self.assertEqual(1, data['product_type_member'][0]['user'])
        self.assertEqual(1, data['product_type_member'][0]['product_type'])
        self.assertEqual(1, data['product_member'][1]['user'])
        self.assertEqual(3, data['product_member'][1]['product'])


class DevelopmentEnvironmentTest(BaseClass.AuthenticatedViewTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Development_Environment
        self.endpoint_path = 'development_environments'
        self.viewname = 'development_environment'
        self.viewset = DevelopmentEnvironmentViewSet
        self.payload = {
            'name': 'Test_1'
        }
        self.update_fields = {'name': 'Test_2'}
        self.test_type = TestType.CONFIGURATION_PERMISSIONS
        self.deleted_objects = 1
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)

    def test_delete(self):
        current_objects = self.client.get(self.url, format='json').data
        relative_url = self.url + '%s/' % current_objects['results'][-1]['id']
        response = self.client.delete(relative_url)
        self.assertEqual(409, response.status_code, response.content[:1000])


class TestTypeTest(BaseClass.AuthenticatedViewTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Test_Type
        self.endpoint_path = 'test_types'
        self.viewname = 'test_type'
        self.viewset = TestTypesViewSet
        self.payload = {
            'name': 'Test_1'
        }
        self.update_fields = {'name': 'Test_2'}
        self.test_type = TestType.CONFIGURATION_PERMISSIONS
        self.deleted_objects = 1
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class ConfigurationPermissionTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Permission
        self.endpoint_path = 'configuration_permissions'
        self.viewname = 'permission'
        self.viewset = ConfigurationPermissionViewSet
        self.test_type = TestType.STANDARD
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class CredentialMappingTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Cred_Mapping
        self.endpoint_path = 'credential_mappings'
        self.viewname = 'cred_mapping'
        self.viewset = CredentialsMappingViewSet
        self.payload = {
            'cred_id': 1,
            'product': 1,
            'url': 'https://google.com'
        }
        self.update_fields = {'url': 'https://bing.com'}
        self.test_type = TestType.OBJECT_PERMISSIONS
        self.permission_check_class = Product
        self.permission_create = Permissions.Credential_Add
        self.permission_update = Permissions.Credential_Edit
        self.permission_delete = Permissions.Credential_Delete
        self.deleted_objects = 1
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class CredentialTest(BaseClass.RESTEndpointTest):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Cred_User
        self.endpoint_path = 'credentials'
        self.viewname = 'cred_user'
        self.viewset = CredentialsViewSet
        self.payload = {
            'name': 'name',
            'username': 'usernmae',
            'password': 'password',
            'role': 'role',
            'url': 'https://some-url.com',
            'environment': 1,
        }
        self.update_fields = {'name': 'newname'}
        self.test_type = TestType.STANDARD
        self.deleted_objects = 2
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class TextQuestionTest(BaseClass.RESTEndpointTest):
    fixtures = ['questionnaire_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = TextQuestion
        self.endpoint_path = 'questionnaire_questions'
        self.viewname = 'question'
        self.viewset = QuestionnaireQuestionViewSet
        self.test_type = TestType.STANDARD
        self.deleted_objects = 5
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class ChoiceQuestionTest(BaseClass.RESTEndpointTest):
    fixtures = ['questionnaire_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = ChoiceQuestion
        self.endpoint_path = 'questionnaire_questions'
        self.viewname = 'question'
        self.viewset = QuestionnaireQuestionViewSet
        self.test_type = TestType.STANDARD
        self.deleted_objects = 5
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class TextAnswerTest(BaseClass.RESTEndpointTest):
    fixtures = ['questionnaire_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = TextAnswer
        self.endpoint_path = 'questionnaire_answers'
        self.viewname = 'answer'
        self.viewset = QuestionnaireAnswerViewSet
        self.test_type = TestType.STANDARD
        self.deleted_objects = 5
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class ChoiceAnswerTest(BaseClass.RESTEndpointTest):
    fixtures = ['questionnaire_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = ChoiceAnswer
        self.endpoint_path = 'questionnaire_answers'
        self.viewname = 'answer'
        self.viewset = QuestionnaireAnswerViewSet
        self.test_type = TestType.STANDARD
        self.deleted_objects = 5
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class GeneralSurveyTest(BaseClass.RESTEndpointTest):
    fixtures = ['questionnaire_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = General_Survey
        self.endpoint_path = 'questionnaire_general_questionnaires'
        self.viewname = 'general_survey'
        self.viewset = QuestionnaireGeneralSurveyViewSet
        self.test_type = TestType.STANDARD
        self.deleted_objects = 5
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class EngagementSurveyTest(BaseClass.RESTEndpointTest):
    fixtures = ['questionnaire_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Engagement_Survey
        self.endpoint_path = 'questionnaire_engagement_questionnaires'
        self.viewname = 'engagement_survey'
        self.viewset = QuestionnaireEngagementSurveyViewSet
        self.test_type = TestType.STANDARD
        self.deleted_objects = 5
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)


class AnsweredSurveyTest(BaseClass.RESTEndpointTest):
    fixtures = ['questionnaire_testdata.json']

    def __init__(self, *args, **kwargs):
        self.endpoint_model = Answered_Survey
        self.endpoint_path = 'questionnaire_answered_questionnaires'
        self.viewname = 'answered_survey'
        self.viewset = QuestionnaireAnsweredSurveyViewSet
        self.test_type = TestType.STANDARD
        self.deleted_objects = 5
        BaseClass.RESTEndpointTest.__init__(self, *args, **kwargs)
