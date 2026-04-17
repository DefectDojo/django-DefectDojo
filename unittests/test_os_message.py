from unittest.mock import patch

import requests
from django.core.cache import cache
from django.template import Context, Template
from django.test import RequestFactory, SimpleTestCase, override_settings

from dojo import context_processors
from dojo.announcements import os_message


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
        with patch("dojo.announcements.os_message.requests.get", return_value=_Resp(200, body)) as mock_get:
            result = os_message.fetch_os_message()
        self.assertEqual(result, body)
        self.assertEqual(cache.get(os_message.CACHE_KEY), body)
        mock_get.assert_called_once()

    def test_404_caches_none(self):
        with patch("dojo.announcements.os_message.requests.get", return_value=_Resp(404, "not found")):
            result = os_message.fetch_os_message()
        self.assertIsNone(result)
        self.assertIsNone(cache.get(os_message.CACHE_KEY, default="sentinel"))

    def test_timeout_caches_none(self):
        with patch("dojo.announcements.os_message.requests.get", side_effect=requests.exceptions.Timeout):
            result = os_message.fetch_os_message()
        self.assertIsNone(result)
        self.assertIsNone(cache.get(os_message.CACHE_KEY, default="sentinel"))

    def test_connection_error_caches_none(self):
        with patch("dojo.announcements.os_message.requests.get", side_effect=requests.exceptions.ConnectionError):
            result = os_message.fetch_os_message()
        self.assertIsNone(result)
        self.assertIsNone(cache.get(os_message.CACHE_KEY, default="sentinel"))

    def test_empty_body_caches_none(self):
        with patch("dojo.announcements.os_message.requests.get", return_value=_Resp(200, "   \n\n")):
            result = os_message.fetch_os_message()
        self.assertIsNone(result)
        self.assertIsNone(cache.get(os_message.CACHE_KEY, default="sentinel"))

    def test_second_call_hits_cache(self):
        with patch("dojo.announcements.os_message.requests.get", return_value=_Resp(200, "# h\n")) as mock_get:
            os_message.fetch_os_message()
            os_message.fetch_os_message()
        self.assertEqual(mock_get.call_count, 1)

    def test_second_call_after_failure_also_hits_cache(self):
        with patch("dojo.announcements.os_message.requests.get", side_effect=requests.exceptions.Timeout) as mock_get:
            os_message.fetch_os_message()
            os_message.fetch_os_message()
        self.assertEqual(mock_get.call_count, 1)


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class TestGetOsBanner(SimpleTestCase):

    def setUp(self):
        cache.clear()

    def test_returns_none_when_fetch_returns_none(self):
        with patch("dojo.announcements.os_message.fetch_os_message", return_value=None):
            self.assertIsNone(os_message.get_os_banner())

    def test_swallows_parse_exception(self):
        with patch("dojo.announcements.os_message.fetch_os_message", return_value="# ok\n"), \
             patch("dojo.announcements.os_message.parse_os_message", side_effect=RuntimeError("boom")):
            self.assertIsNone(os_message.get_os_banner())


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
        self.assertEqual(entry["message"], "<strong>Hi</strong>")
        self.assertEqual(entry["expanded_html"], "<p>body</p>")
        self.assertEqual(entry["style"], "info")
        self.assertEqual(entry["url"], "")
        self.assertEqual(entry["link_text"], "")

    def test_additional_banners_absent_when_no_banner(self):
        with patch.object(context_processors, "get_os_banner", return_value=None):
            result = context_processors.globalize_vars(self.request)
        self.assertNotIn("additional_banners", result)

    def test_template_renders_bleached_message(self):
        banner = {"message": "<strong>Hi</strong>", "expanded_html": None}
        with patch.object(context_processors, "get_os_banner", return_value=banner):
            ctx = context_processors.globalize_vars(self.request)
        rendered = Template(
            "{% for b in additional_banners %}{{ b.message|safe }}{% endfor %}",
        ).render(Context(ctx))
        self.assertIn("<strong>Hi</strong>", rendered)
