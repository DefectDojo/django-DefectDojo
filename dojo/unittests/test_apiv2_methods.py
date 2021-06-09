from rest_framework.test import APIRequestFactory
from rest_framework.views import APIView
from rest_framework.test import APITestCase, force_authenticate
from drf_yasg.generators import OpenAPISchemaGenerator
from drf_yasg.openapi import Info
from dojo.models import Dojo_User
from dojo.urls import v2_api

SWAGGER_SCHEMA_GENERATOR = OpenAPISchemaGenerator(Info("defectdojo", "v2"))


class ApiEndpointMethods(APITestCase):
    fixtures = ['dojo_testdata.json']

    def setUp(self):
        super().setUp()
        testuser = Dojo_User.objects.get(username='admin')

        factory = APIRequestFactory()
        request = factory.get('/')
        force_authenticate(request, user=testuser)
        request = APIView().initialize_request(request)

        self.schema = SWAGGER_SCHEMA_GENERATOR.get_schema(request, public=True)

        self.registry = v2_api.registry

    def test_is_defined(self):

        for reg, _, _ in sorted(self.registry):
            if reg in ['import-scan', 'reimport-scan', 'system_settings', 'users']:
                continue

            for method in ['get', 'post']:
                self.assertIsNotNone(self.schema["paths"]['/' + reg + '/'].get(method),
                                     "Endpoint: {}, Method: {}".format(reg, method))

            for method in ['get', 'put', 'patch', 'delete']:
                self.assertIsNotNone(self.schema["paths"]['/' + reg + '/{id}/'].get(method),
                                     "Endpoint: {}, Method: {}".format(reg, method))
