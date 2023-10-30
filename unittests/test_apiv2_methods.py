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
        exempt_list = [
            'import-scan', 'reimport-scan', 'notes', 'system_settings', 'roles',
            'import-languages', 'endpoint_meta_import', 'test_types',
            'configuration_permissions', 'risk_acceptance', 'questionnaire_questions',
            'questionnaire_answers', 'questionnaire_answered_questionnaires',
            'questionnaire_engagement_questionnaires', 'questionnaire_general_questionnaires',
        ]
        for reg, _, _ in sorted(self.registry):
            if reg in exempt_list:
                continue
            for method in ['get', 'post']:
                self.assertIsNotNone(
                    self.schema["paths"][f'{BASE_API_URL}/{reg}/'].get(method),
                    f"Endpoint: {reg}, Method: {method}",
                )

            for method in ['get', 'put', 'patch', 'delete']:
                self.assertIsNotNone(
                    self.schema["paths"][f'{BASE_API_URL}/{reg}' + '/{id}/'].get(method),
                    f"Endpoint: {reg}, Method: {method}",
                )

            self.assertIsNotNone(
                self.schema["paths"]
                .get(f'{BASE_API_URL}/{reg}' + '/{id}/delete_preview/', {})
                .get('get'),
                f"Endpoint: {reg}, Method: get - delete_preview",
            )
