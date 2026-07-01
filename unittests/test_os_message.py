import hashlib
from types import SimpleNamespace
from unittest.mock import patch

import requests
from django.core.cache import cache
from django.template import Context, Template
from django.test import RequestFactory, SimpleTestCase, override_settings
from django.urls import reverse

from dojo import context_processors
from dojo.announcement import os_message
from dojo.models import User, UserContactInfo
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures


class _Resp:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class TestParseOsMessage(SimpleTestCase):

    def setUp(self):
        cache.clear()

    def test_valid_doc_with_expanded(self):
        text = (
            "# DefectDojo v3.0 is available\n"
            "\n"
            "## Expanded Message\n"
            "\n"
            "- Major feature A\n"
            "- Major feature B\n"
        )
        result = os_message.parse_os_message(text)
        self.assertEqual(result["message"], "DefectDojo v3.0 is available")
        self.assertIn("<li>Major feature A</li>", result["expanded_html"])
        self.assertIn("<li>Major feature B</li>", result["expanded_html"])

    def test_missing_headline_returns_none(self):
        text = "No headline here\n## Expanded Message\nbody\n"
        self.assertIsNone(os_message.parse_os_message(text))

    def test_headline_inline_markdown(self):
        text = "# Read the **release notes** at [link](https://example.com)\n"
        result = os_message.parse_os_message(text)
        self.assertIn("<strong>release notes</strong>", result["message"])
        self.assertIn('<a href="https://example.com">link</a>', result["message"])
        self.assertIsNone(result["expanded_html"])

    def test_headline_strips_disallowed_html(self):
        text = "# Headline <script>alert(1)</script> tail\n"
        result = os_message.parse_os_message(text)
        self.assertNotIn("<script", result["message"])
        self.assertNotIn("</script>", result["message"])
        self.assertIn("Headline", result["message"])

    def test_missing_expanded_section(self):
        text = "# Just a headline\n"
        result = os_message.parse_os_message(text)
        self.assertEqual(result["message"], "Just a headline")
        self.assertIsNone(result["expanded_html"])

    def test_expanded_with_fenced_code(self):
        text = (
            "# Headline\n"
            "## Expanded Message\n"
            "```python\n"
            "print('hi')\n"
            "```\n"
        )
        result = os_message.parse_os_message(text)
        self.assertIn("<pre>", result["expanded_html"])
        self.assertIn("<code>", result["expanded_html"])
        self.assertIn("print('hi')", result["expanded_html"])

    def test_expanded_strips_script_tag(self):
        text = (
            "# Headline\n"
            "## Expanded Message\n"
            "<script>alert(1)</script>\n"
            "Body paragraph\n"
        )
        result = os_message.parse_os_message(text)
        self.assertNotIn("<script", result["expanded_html"])
        self.assertNotIn("</script>", result["expanded_html"])
        self.assertIn("Body paragraph", result["expanded_html"])

    def test_headline_outer_p_is_stripped(self):
        text = "# Plain headline\n"
        result = os_message.parse_os_message(text)
        self.assertFalse(result["message"].startswith("<p>"))
        self.assertFalse(result["message"].endswith("</p>"))

    def test_headline_truncated_to_100_chars(self):
        long_headline = "x" * 200
        text = f"# {long_headline}\n"
        result = os_message.parse_os_message(text)
        self.assertLessEqual(len(result["message"]), 100)


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class TestFetchOsMessage(SimpleTestCase):

    def setUp(self):
        cache.clear()

    def test_200_with_body_caches_body(self):
        body = "# headline\n"
        with patch("dojo.announcement.os_message.requests.get", return_value=_Resp(200, body)) as mock_get:
            result = os_message.fetch_os_message()
        self.assertEqual(result, body)
        self.assertEqual(cache.get(os_message.CACHE_KEY), body)
        mock_get.assert_called_once()

    def test_404_caches_none(self):
        with patch("dojo.announcement.os_message.requests.get", return_value=_Resp(404, "not found")):
            result = os_message.fetch_os_message()
        self.assertIsNone(result)
        self.assertIsNone(cache.get(os_message.CACHE_KEY, default="sentinel"))

    def test_timeout_caches_none(self):
        with patch("dojo.announcement.os_message.requests.get", side_effect=requests.exceptions.Timeout):
            result = os_message.fetch_os_message()
        self.assertIsNone(result)
        self.assertIsNone(cache.get(os_message.CACHE_KEY, default="sentinel"))

    def test_connection_error_caches_none(self):
        with patch("dojo.announcement.os_message.requests.get", side_effect=requests.exceptions.ConnectionError):
            result = os_message.fetch_os_message()
        self.assertIsNone(result)
        self.assertIsNone(cache.get(os_message.CACHE_KEY, default="sentinel"))

    def test_empty_body_caches_none(self):
        with patch("dojo.announcement.os_message.requests.get", return_value=_Resp(200, "   \n\n")):
            result = os_message.fetch_os_message()
        self.assertIsNone(result)
        self.assertIsNone(cache.get(os_message.CACHE_KEY, default="sentinel"))

    def test_second_call_hits_cache(self):
        with patch("dojo.announcement.os_message.requests.get", return_value=_Resp(200, "# h\n")) as mock_get:
            os_message.fetch_os_message()
            os_message.fetch_os_message()
        self.assertEqual(mock_get.call_count, 1)

    def test_second_call_after_failure_also_hits_cache(self):
        with patch("dojo.announcement.os_message.requests.get", side_effect=requests.exceptions.Timeout) as mock_get:
            os_message.fetch_os_message()
            os_message.fetch_os_message()
        self.assertEqual(mock_get.call_count, 1)


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class TestGetOsBanner(SimpleTestCase):

    def setUp(self):
        cache.clear()

    def test_returns_none_when_fetch_returns_none(self):
        with patch("dojo.announcement.os_message.fetch_os_message", return_value=None):
            self.assertIsNone(os_message.get_os_banner())

    def test_swallows_parse_exception(self):
        with patch("dojo.announcement.os_message.fetch_os_message", return_value="# ok\n"), \
             patch("dojo.announcement.os_message.parse_os_message", side_effect=RuntimeError("boom")):
            self.assertIsNone(os_message.get_os_banner())

    @override_settings(OS_MESSAGE_ENABLED=False)
    def test_disabled_returns_none_without_fetching(self):
        with patch("dojo.announcement.os_message.fetch_os_message") as mock_fetch, \
             patch("dojo.announcement.os_message.requests.get") as mock_get:
            self.assertIsNone(os_message.get_os_banner())
        mock_fetch.assert_not_called()
        mock_get.assert_not_called()

    @override_settings(OS_MESSAGE_ENABLED=True)
    def test_enabled_returns_parsed_banner(self):
        with patch("dojo.announcement.os_message.fetch_os_message", return_value="# Headline\n") as mock_fetch:
            result = os_message.get_os_banner()
        mock_fetch.assert_called_once()
        self.assertEqual(result["message"], "Headline")
        self.assertIsNone(result["expanded_html"])

    @override_settings(OS_MESSAGE_ENABLED=True)
    def test_enabled_includes_dismiss_token(self):
        text = "# Headline\n"
        with patch("dojo.announcement.os_message.fetch_os_message", return_value=text):
            result = os_message.get_os_banner()
        expected = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
        self.assertEqual(result["dismiss_token"], expected)


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class TestGlobalizeVarsOsBanner(SimpleTestCase):

    def setUp(self):
        cache.clear()
        self.request = RequestFactory().get("/")

    def test_additional_banners_populated_when_banner_present(self):
        banner = {"message": "<strong>Hi</strong>", "expanded_html": "<p>body</p>"}
        with patch.object(context_processors, "get_os_banner", return_value=banner):
            result = context_processors.globalize_vars(self.request)
        self.assertIn("additional_banners", result)
        entry = result["additional_banners"][0]
        self.assertEqual(entry["source"], "os")
        self.assertEqual(entry["message"], "<strong>Hi</strong>")
        self.assertEqual(entry["expanded_html"], "<p>body</p>")
        self.assertEqual(entry["style"], "info")
        self.assertEqual(entry["url"], "")
        self.assertEqual(entry["link_text"], "")

    def test_additional_banners_absent_when_no_banner(self):
        with patch.object(context_processors, "get_os_banner", return_value=None):
            result = context_processors.globalize_vars(self.request)
        self.assertNotIn("additional_banners", result)

    def test_show_plg_link_is_true_by_default(self):
        with patch.object(context_processors, "get_os_banner", return_value=None):
            result = context_processors.globalize_vars(self.request)
        self.assertTrue(result["SHOW_PLG_LINK"])

    def test_create_cloud_banner_not_in_context(self):
        with patch.object(context_processors, "get_os_banner", return_value=None):
            result = context_processors.globalize_vars(self.request)
        self.assertNotIn("CREATE_CLOUD_BANNER", result)

    def test_template_renders_bleached_message(self):
        banner = {"message": "<strong>Hi</strong>", "expanded_html": None}
        with patch.object(context_processors, "get_os_banner", return_value=banner):
            ctx = context_processors.globalize_vars(self.request)
        rendered = Template(
            "{% for b in additional_banners %}{{ b.message|safe }}{% endfor %}",
        ).render(Context(ctx))
        self.assertIn("<strong>Hi</strong>", rendered)

    def test_session_product_banners_merged_into_additional_banners(self):
        session_banner = {
            "source": "product_announcement",
            "message": "Pro has async imports!",
            "style": "info",
            "url": "",
            "link_text": "",
            "expanded_html": None,
        }
        self.request.session = {"_product_banners": [session_banner]}
        with patch.object(context_processors, "get_os_banner", return_value=None):
            result = context_processors.globalize_vars(self.request)
        self.assertIn("additional_banners", result)
        self.assertEqual(len(result["additional_banners"]), 1)
        self.assertEqual(result["additional_banners"][0]["source"], "product_announcement")
        self.assertEqual(self.request.session.get("_product_banners"), None)

    def test_os_and_session_banners_combined(self):
        os_banner = {"message": "<strong>OS msg</strong>", "expanded_html": None}
        session_banner = {
            "source": "product_announcement",
            "message": "Pro msg",
            "style": "info",
            "url": "",
            "link_text": "",
            "expanded_html": None,
        }
        self.request.session = {"_product_banners": [session_banner]}
        with patch.object(context_processors, "get_os_banner", return_value=os_banner):
            result = context_processors.globalize_vars(self.request)
        self.assertEqual(len(result["additional_banners"]), 2)
        self.assertEqual(result["additional_banners"][0]["source"], "os")
        self.assertEqual(result["additional_banners"][1]["source"], "product_announcement")

    def _authed_request(self, *, dismissed_hash="", ui_use_tailwind=True):
        request = RequestFactory().get("/")
        request.user = SimpleNamespace(
            is_authenticated=True,
            usercontactinfo=SimpleNamespace(
                user_state_details={os_message.OS_MESSAGE_DISMISSED_KEY: dismissed_hash},
                ui_use_tailwind=ui_use_tailwind,
            ),
        )
        return request

    @staticmethod
    def _os_entries(result):
        return [b for b in result.get("additional_banners", []) if b["source"] == "os"]

    def test_os_banner_dismissible_for_authenticated_user(self):
        banner = {"message": "Hi", "expanded_html": None, "dismiss_token": "deadbeef"}
        request = self._authed_request(dismissed_hash="")
        with patch.object(context_processors, "get_os_banner", return_value=banner):
            entries = self._os_entries(context_processors.globalize_vars(request))
        self.assertEqual(len(entries), 1)
        self.assertTrue(entries[0]["dismissible"])
        self.assertEqual(entries[0]["dismiss_token"], "deadbeef")

    def test_os_banner_hidden_when_dismissed_hash_matches(self):
        banner = {"message": "Hi", "expanded_html": None, "dismiss_token": "deadbeef"}
        request = self._authed_request(dismissed_hash="deadbeef")
        with patch.object(context_processors, "get_os_banner", return_value=banner):
            entries = self._os_entries(context_processors.globalize_vars(request))
        self.assertEqual(entries, [])

    def test_os_banner_shown_when_dismissed_hash_differs(self):
        banner = {"message": "Hi", "expanded_html": None, "dismiss_token": "newhash"}
        request = self._authed_request(dismissed_hash="oldhash")
        with patch.object(context_processors, "get_os_banner", return_value=banner):
            entries = self._os_entries(context_processors.globalize_vars(request))
        self.assertEqual(len(entries), 1)
        self.assertTrue(entries[0]["dismissible"])

    def test_os_banner_not_dismissible_for_anonymous(self):
        banner = {"message": "Hi", "expanded_html": None, "dismiss_token": "deadbeef"}
        with patch.object(context_processors, "get_os_banner", return_value=banner):
            entries = self._os_entries(context_processors.globalize_vars(self.request))
        self.assertEqual(len(entries), 1)
        self.assertFalse(entries[0]["dismissible"])


@versioned_fixtures
class TestDismissOsMessageView(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.user = User.objects.get(username="admin")
        self.client.force_login(self.user)
        self.url = reverse("dismiss_os_message")

    def test_post_persists_hash_on_usercontactinfo(self):
        response = self.client.post(self.url, {"token": "abc123def456"}, HTTP_X_REQUESTED_WITH="XMLHttpRequest")
        self.assertEqual(response.status_code, 204)
        contact = UserContactInfo.objects.get(user=self.user)
        self.assertEqual(contact.user_state_details.get(os_message.OS_MESSAGE_DISMISSED_KEY), "abc123def456")

    def test_dismiss_preserves_other_state_keys(self):
        """Dismissing must not clobber unrelated keys in the shared user_state_details blob."""
        contact = UserContactInfo.objects.get_or_create(user=self.user)[0]
        contact.user_state_details = {"other_flag": 1}
        contact.save(update_fields=["user_state_details"])
        response = self.client.post(self.url, {"token": "abc123def456"}, HTTP_X_REQUESTED_WITH="XMLHttpRequest")
        self.assertEqual(response.status_code, 204)
        contact.refresh_from_db()
        self.assertEqual(contact.user_state_details.get("other_flag"), 1)
        self.assertEqual(contact.user_state_details.get(os_message.OS_MESSAGE_DISMISSED_KEY), "abc123def456")

    def test_get_not_allowed(self):
        self.assertEqual(self.client.get(self.url).status_code, 405)

    def test_invalid_token_is_ignored(self):
        response = self.client.post(self.url, {"token": "NOT-HEX!"}, HTTP_X_REQUESTED_WITH="XMLHttpRequest")
        self.assertEqual(response.status_code, 204)
        contact = UserContactInfo.objects.filter(user=self.user).first()
        state = getattr(contact, "user_state_details", {}) or {}
        self.assertNotIn(os_message.OS_MESSAGE_DISMISSED_KEY, state)

    def test_requires_authentication(self):
        self.client.logout()
        response = self.client.post(self.url, {"token": "abc123"})
        self.assertIn(response.status_code, (302, 403))
