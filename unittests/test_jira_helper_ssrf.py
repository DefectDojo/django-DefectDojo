from unittest.mock import patch

from dojo.jira.forms import BaseJiraForm
from dojo.jira.helper import connect_to_jira
from unittests.dojo_test_case import DojoTestCase


class TestConnectToJiraUrlValidation(DojoTestCase):

    def test_rfc1918_url_raises_value_error_before_calling_jira(self):
        with patch("dojo.jira.helper.JIRA") as mock_jira:
            with self.assertRaisesRegex(ValueError, "JIRA URL is not allowed"):
                connect_to_jira("http://172.18.0.3:5432", "user", "password")
            mock_jira.assert_not_called()

    def test_loopback_url_raises_value_error_before_calling_jira(self):
        with patch("dojo.jira.helper.JIRA") as mock_jira:
            with self.assertRaisesRegex(ValueError, "JIRA URL is not allowed"):
                connect_to_jira("http://127.0.0.1/", "user", "password")
            mock_jira.assert_not_called()

    def test_link_local_metadata_url_raises_value_error_before_calling_jira(self):
        with patch("dojo.jira.helper.JIRA") as mock_jira:
            with self.assertRaisesRegex(ValueError, "JIRA URL is not allowed"):
                connect_to_jira("http://169.254.169.254/", "user", "password")
            mock_jira.assert_not_called()

    def test_unsupported_scheme_raises_value_error_before_calling_jira(self):
        with patch("dojo.jira.helper.JIRA") as mock_jira:
            with self.assertRaisesRegex(ValueError, "JIRA URL is not allowed"):
                connect_to_jira("file:///etc/passwd", "user", "password")
            mock_jira.assert_not_called()

    def test_public_url_proceeds_to_jira_client(self):
        # 8.8.8.8 is globally routable; getaddrinfo on a numeric IP literal
        # does not hit DNS, so this is reliable in CI.
        with patch("dojo.jira.helper.JIRA") as mock_jira:
            connect_to_jira("http://8.8.8.8/", "user", "password")
            mock_jira.assert_called_once()
            _, kwargs = mock_jira.call_args
            self.assertEqual(kwargs["server"], "http://8.8.8.8/")
            self.assertEqual(kwargs["basic_auth"], ("user", "password"))


class TestBaseJiraFormSurfacesValidationError(DojoTestCase):

    def test_form_clean_surfaces_blocked_url_as_form_error_not_500(self):
        form = BaseJiraForm.__new__(BaseJiraForm)
        form._errors = {}
        form.cleaned_data = {
            "url": "http://127.0.0.1/",
            "username": "user",
            "password": "password",
        }

        added_errors: dict[str, list[str]] = {}

        def fake_add_error(field, message):
            added_errors.setdefault(field, []).append(str(message))

        form.add_error = fake_add_error  # type: ignore[assignment]

        # Should not raise — exception is caught and surfaced as form errors.
        form.test_jira_connection()

        self.assertIn("username", added_errors)
        self.assertIn("password", added_errors)
        for messages in added_errors.values():
            self.assertTrue(
                any("JIRA URL is not allowed" in m for m in messages),
                f"Expected blocked-URL detail in form error, got: {messages}",
            )
