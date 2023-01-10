from .dojo_test_case import DojoTestCase
from dojo.tools.factory import get_api_scan_configuration_hints
from dojo.models import Tool_Configuration, Tool_Type


class TestApiScanConfigEmpty(DojoTestCase):

    def setUp(self):
        tool_type, _ = Tool_Type.objects.get_or_create(name='SonarQube')
        Tool_Configuration.objects.get_or_create(name='SonarQube', tool_type=tool_type, authentication_type="API")

    def test_base(self):
        acsh = get_api_scan_configuration_hints()
        self.assertEqual(len(acsh), 5, acsh)

        i = 0
        with self.subTest('Bugcrowd'):
            self.assertEqual(acsh[i]['name'], 'Bugcrowd API Import')
            self.assertEqual(acsh[i]['tool_type_name'], 'Bugcrowd API')
            self.assertEqual(acsh[i]['hint'], 'the field <b>Service key 1</b> has to be set with the Bugcrowd program code. <b>Service key 2</b> can be set with the target in the Bugcrowd program (will be url encoded for the api call), if not supplied, will fetch all submissions in the program')

        i += 1
        with self.subTest('Cobalt.io'):
            self.assertEqual(acsh[i]['name'], 'Cobalt.io API Import')
            self.assertEqual(acsh[i]['tool_type_name'], 'Cobalt.io')
            self.assertEqual(acsh[i]['hint'], 'the field <b>Service key 1</b> has to be set with the Cobalt.io asset id. <b>Service key 2</b> will be populated with the asset name while saving the configuration.')

        i += 1
        with self.subTest('Edgescan'):
            self.assertEqual(acsh[i]['name'], 'Edgescan Scan')
            self.assertEqual(acsh[i]['tool_type_name'], 'Edgescan')
            self.assertEqual(acsh[i]['hint'], 'the field <b>Service key 1</b> has to be set with the Edgescan asset id.')

        i += 1
        with self.subTest('SonarQube'):
            self.assertEqual(acsh[i]['name'], 'SonarQube API Import')
            self.assertEqual(acsh[i]['tool_type_name'], 'SonarQube')
            self.assertEqual(acsh[i]['hint'], 'the field <b>Service key 1</b> has to be set with the SonarQube project key. <b>Service key 2</b> can be used for the Organization ID if using SonarCloud.')

        i += 1
        with self.subTest('Vulners'):
            self.assertEqual(acsh[i]['name'], 'Vulners')
            self.assertEqual(acsh[i]['tool_type_name'], 'Vulners')
            self.assertEqual(acsh[i]['hint'], 'the field <b>Service key 1</b> has to be set with the Vulners API key.')

    def test_counts(self):
        acsh = get_api_scan_configuration_hints()
        self.assertEqual(acsh[0]['tool_types'].count(), 0)
        self.assertEqual(acsh[0]['tool_configurations'].count(), 0)
        self.assertEqual(acsh[3]['tool_types'].count(), 1)
        self.assertEqual(acsh[3]['tool_configurations'].count(), 1)

# TODO test missing test