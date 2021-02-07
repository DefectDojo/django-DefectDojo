from .dojo_test_case import DojoVCRTestCase
from .dojo_test_case import DojoTestCase
import logging
from vcr import VCR
from django.urls import reverse


logger = logging.getLogger(__name__)


class GoogleSheetsConfigTestApi(DojoVCRTestCase):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        DojoTestCase.__init__(self, *args, **kwargs)

    def assert_cassette_played(self):
        if True:  # set to True when committing. set to False when recording new test cassettes
            self.assertTrue(self.cassette.all_played)

    def _get_vcr(self, **kwargs):
        my_vcr = super(GoogleSheetsConfigTestApi, self)._get_vcr(**kwargs)
        my_vcr.record_mode = 'once'
        my_vcr.path_transformer = VCR.ensure_suffix('.yaml')
        my_vcr.cassette_library_dir = 'dojo/unittests/vcr/google_sheets/'
        return my_vcr

    def setUp(self):
        super().setUp()
        self.client.force_login(self.get_test_admin())

    def test_config_google_sheets(self):
        # To regenerate the cassette, use an actual credentials json file
        # with open('tests/defectdojo-sheets-localdev.json', 'rb') as f:
        with open('tests/test-dojo-sheets-ab2fe11c32b5.json', 'rb') as f:
            data = {}
            # fail on purpose to get all the fields dynamically
            response = self.client.post(reverse('configure_google_sheets'), data, follow=True)
            form = response.context['form']
            self.assertEqual(form.is_valid(), False)

            for field in form:
                # do not consider the "protect" checkbox, leave them as is
                if 'Protect' in field.html_name:
                    continue
                # Select Hide (0) by default
                data.update({field.html_name: 0})

            data.update({
                # To regenerate the cassette, use actual credentials
                # If regenerating, make sure all credentials used are deleted prior to pushing,
                # due to the bearer token having to remain in the vcr yaml
                'email_address': 'defectdojo-fake-user@fake-project-name.iam.gserviceaccount.com',
                # needs to match ID in the cassette
                'drive_folder_ID': 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
                'enable_service': 'on',
                'cred_file': f
            })
            # force use of specific submit button
            data.update({
                'update': 'Submit'
            })

            response = self.client.post(reverse('configure_google_sheets'), data, follow=True)
            self.assertContains(response, "successfully")
            self.assert_cassette_played()
