from unittest.mock import patch

from django.urls import reverse
from django.utils.http import urlencode
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.models import JIRA_Instance, Tool_Configuration, Tool_Type
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures

URL = "https://jira.example.com"
OTHER_URL = "https://jira-new.example.com"
PASSWORD = "stored-jira-password"
NEW_PASSWORD = "new-jira-password"


@versioned_fixtures
class JIRAInstanceEditTest(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.system_settings(enable_jira=True)
        self.admin = self.get_test_admin()
        self.client.force_login(self.admin)
        self.jira_instance = JIRA_Instance.objects.create(
            configuration_name="edit test",
            url=URL,
            username="service-account",
            password=PASSWORD,
            default_issue_type="Bug",
            epic_name_id=1,
            open_status_key=1,
            close_status_key=1,
            info_mapping_severity="Info",
            low_mapping_severity="Low",
            medium_mapping_severity="Medium",
            high_mapping_severity="High",
            critical_mapping_severity="Critical",
        )
        self.stored_password = JIRA_Instance.objects.get(pk=self.jira_instance.pk).password

    def _form_data(self, **overrides):
        data = {
            "configuration_name": "edit test",
            "url": URL,
            "username": "service-account",
            "password": "",
            "default_issue_type": "Bug",
            "epic_name_id": 1,
            "open_status_key": 1,
            "close_status_key": 1,
            "info_mapping_severity": "Info",
            "low_mapping_severity": "Low",
            "medium_mapping_severity": "Medium",
            "high_mapping_severity": "High",
            "critical_mapping_severity": "Critical",
            "accepted_mapping_resolution": "Fixed",
            "false_positive_mapping_resolution": "False Positive",
        }
        data.update(overrides)
        return data

    @patch("dojo.jira.views.jira_helper.get_jira_connection_raw")
    def _edit(self, data, jira_mock):
        response = self.client.post(
            reverse("edit_jira", args=(self.jira_instance.id,)),
            urlencode(data),
            content_type="application/x-www-form-urlencoded",
        )
        self.jira_instance.refresh_from_db()
        return response, jira_mock

    def test_blank_password_keeps_stored_password_for_same_url(self):
        response, jira_mock = self._edit(self._form_data(configuration_name="renamed"))
        self.assertRedirects(response, "/jira")
        self.assertEqual("renamed", self.jira_instance.configuration_name)
        self.assertEqual(self.stored_password, self.jira_instance.password)
        for call_args in jira_mock.call_args_list:
            self.assertEqual(URL, call_args.args[0])

    def test_trailing_slash_counts_as_same_url(self):
        response, _jira_mock = self._edit(self._form_data(url=URL + "/"))
        self.assertRedirects(response, "/jira")
        self.assertEqual(self.stored_password, self.jira_instance.password)

    def test_changing_url_requires_password(self):
        response, jira_mock = self._edit(self._form_data(url=OTHER_URL))
        self.assertEqual(200, response.status_code)
        self.assertIn("password", response.context["jform"].errors)
        jira_mock.assert_not_called()
        self.assertEqual(URL, self.jira_instance.url)

    def test_changing_url_with_password(self):
        response, jira_mock = self._edit(self._form_data(url=OTHER_URL, password=NEW_PASSWORD))
        self.assertRedirects(response, "/jira")
        self.assertEqual(OTHER_URL, self.jira_instance.url)
        jira_mock.assert_called_with(OTHER_URL, "service-account", NEW_PASSWORD)

    def _api_client(self):
        client = APIClient()
        token, _ = Token.objects.get_or_create(user=self.admin)
        client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        return client

    def test_api_changing_url_requires_password(self):
        path = reverse("jira_instance-detail", args=(self.jira_instance.id,))
        response = self._api_client().patch(path, {"url": OTHER_URL}, format="json")
        self.assertEqual(400, response.status_code, response.content[:500])
        self.assertIn("password", response.json())
        self.jira_instance.refresh_from_db()
        self.assertEqual(URL, self.jira_instance.url)

        response = self._api_client().patch(path, {"url": OTHER_URL, "password": NEW_PASSWORD}, format="json")
        self.assertEqual(200, response.status_code, response.content[:500])

    def test_api_other_fields_keep_password(self):
        path = reverse("jira_instance-detail", args=(self.jira_instance.id,))
        response = self._api_client().patch(path, {"configuration_name": "renamed", "url": URL}, format="json")
        self.assertEqual(200, response.status_code, response.content[:500])
        self.jira_instance.refresh_from_db()
        self.assertEqual(self.stored_password, self.jira_instance.password)

    def test_api_tool_configuration_url_change(self):
        tool_type, _ = Tool_Type.objects.get_or_create(name="Edit Test Tool")
        tool_config = Tool_Configuration.objects.create(
            name="edit test", tool_type=tool_type, url=URL,
            authentication_type="API", password=PASSWORD, ssh="key", api_key="api-key",
        )
        path = reverse("tool_configuration-detail", args=(tool_config.id,))

        response = self._api_client().patch(path, {"name": "renamed"}, format="json")
        self.assertEqual(200, response.status_code, response.content[:500])
        tool_config.refresh_from_db()
        self.assertEqual("api-key", tool_config.api_key)

        response = self._api_client().patch(path, {"url": OTHER_URL, "api_key": "new-key"}, format="json")
        self.assertEqual(200, response.status_code, response.content[:500])
        tool_config.refresh_from_db()
        self.assertEqual("new-key", tool_config.api_key)
        self.assertFalse(tool_config.password)
        self.assertFalse(tool_config.ssh)
