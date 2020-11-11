from django.urls import reverse
from django.test import TestCase
from dojo.models import System_Settings
# import json
# from unittest import skip
import logging

logger = logging.getLogger(__name__)


class JIRAWebhookTest(TestCase):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        TestCase.__init__(self, *args, **kwargs)
        self.correct_secret = '12345'
        self.incorrect_secret = '1234567890'

    # def setUp(self):
        # self.url = reverse(self.viewname + '-list')

    def system_settings(self, enable_jira=False, enable_jira_web_hook=False, disable_jira_webhook_secret=False, jira_webhook_secret=None):
        ss = System_Settings.objects.get()
        ss.enable_jira = enable_jira
        ss.enable_jira_web_hook = enable_jira_web_hook
        ss.disable_jira_webhook_secret = disable_jira_webhook_secret
        ss.jira_webhook_secret = jira_webhook_secret
        ss.save()

    def test_webhook_get(self):
        response = self.client.get(reverse('jira_web_hook'))
        self.assertEqual(405, response.status_code)

    def test_webhook_jira_disabled(self):
        self.system_settings(enable_jira=False)
        response = self.client.post(reverse('jira_web_hook'))
        self.assertEqual(404, response.status_code)

    def test_webhook_disabled(self):
        self.system_settings(enable_jira=False, enable_jira_web_hook=False)
        response = self.client.post(reverse('jira_web_hook'))
        self.assertEqual(404, response.status_code)

    def test_webhook_invalid_content_type(self):
        self.system_settings(enable_jira=True, enable_jira_web_hook=True, disable_jira_webhook_secret=True)
        response = self.client.post(reverse('jira_web_hook'))
        # 400 due to incorrect content_type
        self.assertEqual(400, response.status_code)

    def test_webhook_secret_disabled_no_secret(self):
        self.system_settings(enable_jira=True, enable_jira_web_hook=True, disable_jira_webhook_secret=True)
        response = self.client.post(reverse('jira_web_hook'))
        # 400 due to incorrect content_type
        self.assertEqual(400, response.status_code)

    def test_webhook_secret_disabled_secret(self):
        self.system_settings(enable_jira=True, enable_jira_web_hook=True, disable_jira_webhook_secret=True)
        response = self.client.post(reverse('jira_web_hook_secret', args=(self.incorrect_secret, )))
        # 400 due to incorrect content_type
        self.assertEqual(400, response.status_code)

    def test_webhook_secret_enabled_no_secret(self):
        self.system_settings(enable_jira=True, enable_jira_web_hook=True, disable_jira_webhook_secret=False, jira_webhook_secret=self.correct_secret)
        response = self.client.post(reverse('jira_web_hook'))
        self.assertEqual(403, response.status_code)

    def test_webhook_secret_enabled_incorrect_secret(self):
        self.system_settings(enable_jira=True, enable_jira_web_hook=True, disable_jira_webhook_secret=False, jira_webhook_secret=self.correct_secret)
        response = self.client.post(reverse('jira_web_hook_secret', args=(self.incorrect_secret, )))
        self.assertEqual(403, response.status_code)

    def test_webhook_secret_enabled_correct_secret(self):
        self.system_settings(enable_jira=True, enable_jira_web_hook=True, disable_jira_webhook_secret=False, jira_webhook_secret=self.correct_secret)
        response = self.client.post(reverse('jira_web_hook_secret', args=(self.correct_secret, )))
        # 400 due to incorrect content_type
        self.assertEqual(400, response.status_code)


# example for future tests including body
# python_dict = {
#     "1": {
#         "guid": "8a40135230f21bdb0130f21c255c0007",
#         "portalId": 999,
#         "email": "fake@email"
#     }
# }
# response = self.client.post('/pipeline-endpoint/',
#                             json.dumps(python_dict),
#                             content_type="application/json")
