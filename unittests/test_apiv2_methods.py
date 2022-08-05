from dojo.urls import v2_api
from .dojo_test_case import DojoTestCase
from .test_rest_framework import get_open_api3_json_schema, BASE_API_URL


class ApiEndpointMethods(DojoTestCase):
    fixtures = ['dojo_testdata.json']

    def setUp(self):
        super().setUp()

        self.schema = get_open_api3_json_schema()

        self.registry = v2_api.registry

    def test_is_defined(self):

        for reg, _, _ in sorted(self.registry):
            if reg in ['import-scan', 'reimport-scan', 'notes', 'system_settings', 'roles', 'import-languages', 'endpoint_meta_import', 'test_types', 'sla_configurations', 'configuration_permissions']:
                continue

            for method in ['get', 'post']:
                self.assertIsNotNone(self.schema["paths"][BASE_API_URL + '/' + reg + '/'].get(method),
                                     "Endpoint: {}, Method: {}".format(reg, method))

            for method in ['get', 'put', 'patch', 'delete']:
                self.assertIsNotNone(self.schema["paths"][BASE_API_URL + '/' + reg + '/{id}/'].get(method),
                                     "Endpoint: {}, Method: {}".format(reg, method))

            self.assertIsNotNone(self.schema["paths"].get(BASE_API_URL + '/' + reg + '/{id}/delete_preview/', {}).get('get'),
                             "Endpoint: {}, Method: get - delete_preview".format(reg))
