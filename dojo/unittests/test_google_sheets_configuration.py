# from dojo.models import User
# from rest_framework.authtoken.models import Token
# from rest_framework.test import APITestCase, APIClient
from .dojo_test_case import DojoVCRTestCase
from .dojo_test_case import DojoTestCase
import logging
from vcr import VCR
from django.urls import reverse


logger = logging.getLogger(__name__)


# filters headers doesn't seem to work for cookies, so use callbacks to filter cookies from being recorded
# https://github.com/kevin1024/vcrpy/issues/569
def before_record_request(request):
    if 'Cookie' in request.headers:
        del request.headers['Cookie']
    if 'cookie' in request.headers:
        del request.headers['cookie']
    return request


def before_record_response(response):
    if 'Set-Cookie' in response['headers']:
        del response['headers']['Set-Cookie']
    if 'set-cookie' in response['headers']:
        del response['headers']['set-cookie']
    return response


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
        # filters headers doesn't seem to work for cookies, so use callbacks to filter cookies from being recorded
        # my_vcr.before_record_request = before_record_request
        # my_vcr.before_record_response = before_record_response
        return my_vcr

    def setUp(self):
        super().setUp()
        self.client.force_login(self.get_test_admin())

    def test_config_google_sheets(self):
        with open('tests/defectdojo-sheets-localdev.json', 'rb') as f:
            data = {
                'email_address': 'fred.blaise@gmail.com',
                'drive_folder_ID': 'xxxxx',
                'enable_service': 'true',
                'cred_file': f
            }

            response = self.client.post(reverse('configure_google_sheets'), data)
            logger.debug(response)
            # self.assert_cassette_played()
