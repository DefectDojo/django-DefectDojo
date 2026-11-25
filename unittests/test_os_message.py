import base64
import hashlib
import json
import re
from types import SimpleNamespace
from unittest.mock import patch

import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
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


_TEST_KEY = Ed25519PrivateKey.generate()
_TEST_PUBLIC_KEY = base64.b64encode(
    _TEST_KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
).decode()


def _signed(message, key=_TEST_KEY, prefix=b"defectdojo-os-message-v1\n"):
    """The body of the signed banner object, as the publisher writes it."""
    signature = key.sign(prefix + message.encode("utf-8"))
    return json.dumps({
        "version": 1,
        "message": message,
        "signature": base64.b64encode(signature).decode(),
    })


def _signed_resp(message, **kwargs):
    return _Resp(200, _signed(message, **kwargs))


# Every test in this module verifies against the throwaway key above, not the shipped one.
_with_test_key = patch("dojo.announcement.os_message.PUBLIC_KEYS", (_TEST_PUBLIC_KEY,))


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
        text = "# Read the **release notes** at [link](https://docs.defectdojo.com/)\n"
        result = os_message.parse_os_message(text)
        self.assertIn("<strong>release notes</strong>", result["message"])
        self.assertIn('<a href="https://docs.defectdojo.com/">link</a>', result["message"])
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


@_with_test_key
@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class TestFetchOsMessage(SimpleTestCase):

    def setUp(self):
        cache.clear()

    def test_200_with_body_caches_body(self):
        body = "# headline\n"
        with patch("dojo.announcement.os_message.requests.get", return_value=_signed_resp(body)) as mock_get:
            result = os_message.fetch_os_message()
        self.assertEqual(result, body)
        self.assertEqual(cache.get(os_message.CACHE_KEY), body)
        mock_get.assert_called_once_with(os_message.SIGNED_URL, timeout=os_message.HTTP_TIMEOUT_SECONDS)

    def test_body_decoded_as_utf8_without_charset_header(self):
        body = "# Headline\n\n## Expanded Message\n\n[Compare plans →](https://defectdojo.com/pricing)\n"
        response = requests.Response()
        response.status_code = 200
        response._content = _signed(body).encode("utf-8")
        response.headers["Content-Type"] = "application/json"
        # Mirror what the requests adapter does for a text/* type with no charset.
        response.encoding = requests.utils.get_encoding_from_headers(response.headers)
        with patch("dojo.announcement.os_message.requests.get", return_value=response):
            result = os_message.fetch_os_message()
        self.assertEqual(result, body)
        self.assertIn("Compare plans →", os_message.parse_os_message(result)["expanded_html"])

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
        with patch("dojo.announcement.os_message.requests.get", return_value=_signed_resp("# h\n")) as mock_get:
            os_message.fetch_os_message()
            os_message.fetch_os_message()
        self.assertEqual(mock_get.call_count, 1)

    def test_second_call_after_failure_also_hits_cache(self):
        with patch("dojo.announcement.os_message.requests.get", side_effect=requests.exceptions.Timeout) as mock_get:
            os_message.fetch_os_message()
            os_message.fetch_os_message()
        self.assertEqual(mock_get.call_count, 1)


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class TestFetchOsMessageSignature(SimpleTestCase):

    """An install shows only a banner signed with a key it ships; anything else is cached as no banner."""

    def setUp(self):
        cache.clear()

    def _fetch(self, response):
        with _with_test_key, patch("dojo.announcement.os_message.requests.get", return_value=response):
            return os_message.fetch_os_message()

    def assert_rejected(self, response):
        self.assertIsNone(self._fetch(response))
        self.assertIsNone(cache.get(os_message.CACHE_KEY, default="sentinel"))

    def test_valid_signature_is_accepted(self):
        self.assertEqual(self._fetch(_signed_resp("# Hello\n")), "# Hello\n")

    def test_unsigned_markdown_is_rejected(self):
        self.assert_rejected(_Resp(200, "# Visit [us](https://evil.example)\n"))

    def test_altered_message_is_rejected(self):
        envelope = json.loads(_signed("# Hello\n"))
        envelope["message"] = "# Hello [there](https://evil.example)\n"
        self.assert_rejected(_Resp(200, json.dumps(envelope)))

    def test_signature_from_another_key_is_rejected(self):
        self.assert_rejected(_signed_resp("# Hello\n", key=Ed25519PrivateKey.generate()))

    def test_signature_without_domain_prefix_is_rejected(self):
        self.assert_rejected(_signed_resp("# Hello\n", prefix=b""))

    def test_missing_or_malformed_signature_is_rejected(self):
        for signature in (None, "", "not base64!", base64.b64encode(b"short").decode(), 42):
            with self.subTest(signature=signature):
                cache.clear()
                envelope = json.loads(_signed("# Hello\n"))
                envelope["signature"] = signature
                self.assert_rejected(_Resp(200, json.dumps(envelope)))

    def test_malformed_envelopes_are_rejected(self):
        for body in ("{", "[]", "null", json.dumps({"version": 2, "message": "# h\n", "signature": ""}),
                     json.dumps({"version": 1, "message": 7, "signature": ""})):
            with self.subTest(body=body):
                cache.clear()
                self.assert_rejected(_Resp(200, body))

    def test_unsupported_version_is_rejected_even_when_signed(self):
        envelope = json.loads(_signed("# Hello\n"))
        envelope["version"] = 2
        self.assert_rejected(_Resp(200, json.dumps(envelope)))

    def test_unencodable_message_is_rejected_and_cached(self):
        # A lone surrogate is valid JSON but cannot be encoded to UTF-8 for verification. It must
        # count as no banner and be cached like any other rejection, not raise on every request.
        body = json.dumps({"version": 1, "message": "# Hello \ud800\n", "signature": base64.b64encode(b"x" * 64).decode()})
        with _with_test_key, patch("dojo.announcement.os_message.requests.get", return_value=_Resp(200, body)) as mock_get:
            self.assertIsNone(os_message.fetch_os_message())
            self.assertIsNone(os_message.fetch_os_message())
        self.assertEqual(mock_get.call_count, 1)
        self.assertIsNone(cache.get(os_message.CACHE_KEY, default="sentinel"))

    def test_signed_empty_message_is_no_banner(self):
        self.assert_rejected(_signed_resp(""))

    def test_no_shipped_key_shows_nothing(self):
        with patch("dojo.announcement.os_message.PUBLIC_KEYS", ()), \
             patch("dojo.announcement.os_message.requests.get", return_value=_signed_resp("# Hello\n")):
            self.assertIsNone(os_message.fetch_os_message())

    def test_any_shipped_key_verifies(self):
        other = base64.b64encode(
            Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
        ).decode()
        with patch("dojo.announcement.os_message.PUBLIC_KEYS", (other, _TEST_PUBLIC_KEY)), \
             patch("dojo.announcement.os_message.requests.get", return_value=_signed_resp("# Hello\n")):
            self.assertEqual(os_message.fetch_os_message(), "# Hello\n")

    def test_shipped_keys_are_valid_ed25519_keys(self):
        for key in os_message.PUBLIC_KEYS:
            with self.subTest(key=key):
                self.assertEqual(len(base64.b64decode(key, validate=True)), 32)


class TestOsMessageLinkHosts(SimpleTestCase):

    """A signed banner can still only link to company hosts; any other link keeps its text and loses its href."""

    ALLOWED = (
        "https://defectdojo.com",
        "https://defectdojo.com/pricing",
        "https://www.defectdojo.com/a?b=c#d",
        "https://docs.defectdojo.com/en/latest/",
        "https://DefectDojo.ORG/",
        "https://documentation.defectdojo.org/x",
        "https://github.com/DefectDojo",
        "https://github.com/DefectDojo/django-DefectDojo/releases",
        "https://github.com/defectdojo/django-DefectDojo",
        "https://github.com/DefectDojo-Inc/",
    )
    DENIED = (
        "http://defectdojo.com/",
        "https://evil.example/",
        "https://defectdojo.com.evil.example/",
        "https://evildefectdojo.com/",
        "https://defectdojo.com@evil.example/",
        "https://evil.example\\@defectdojo.com/",
        "https://defectdojo.com:8443/",
        "https://github.com/",
        "https://github.com/DefectDojoEvil/x",
        "https://github.com/someone/DefectDojo",
        "https://gist.github.com/DefectDojo/x",
        "https://github.com/DefectDojo/../evil-org/x",
        "https://github.com/DefectDojo/%2e%2e/evil-org",
        "https://github.com/DefectDojo/%2E%2e/evil-org",
        "https://github.com/DefectDojo/x%2f..%2f..%2fevil-org",
        "https://github.com/DefectDojo/x%5c..%5cevil-org",
        "https://github.com/DefectDojo/./x",
        "https://defectdojo.com/a/../b",
        "https://github.com/DefectDojo/&#46;&#46;/evil-org/repo",
        "https://github.com/DefectDojo/x/..&#x5c;evil-org",
        "https://github.com/DefectDojo/&period;&period;/evil-org",
        "javascript:alert(1)",
        "data:text/html,hi",
        "mailto:hello@defectdojo.com",
        "//evil.example/",
        "/relative",
        "",
    )

    def test_allowed_link_hosts(self):
        for url in self.ALLOWED:
            with self.subTest(url=url):
                self.assertTrue(os_message.is_allowed_link(url))

    def test_denied_link_hosts(self):
        for url in self.DENIED:
            with self.subTest(url=url):
                self.assertFalse(os_message.is_allowed_link(url))

    def test_headline_drops_foreign_href_keeps_text(self):
        result = os_message.parse_os_message("# Read [this](https://evil.example/x) and [docs](https://docs.defectdojo.com/)\n")
        self.assertNotIn("evil.example", result["message"])
        self.assertIn("this", result["message"])
        self.assertIn('href="https://docs.defectdojo.com/"', result["message"])

    def test_character_references_are_decoded_before_the_check(self):
        # Browsers decode character references in an href before following it, so the rule
        # judges the decoded URL: encoded dot segments are refused, an encoded query separator
        # in an allowed link is fine.
        md = "# h\n\n## Expanded Message\n\n[a](https://github.com/DefectDojo/&#46;&#46;/evil-org/repo) [b](https://defectdojo.com/p?x=1&amp;y=2)\n"
        html = os_message.parse_os_message(md)["expanded_html"]
        hrefs = re.findall(r'href="([^"]*)"', html)
        self.assertEqual(hrefs, ["https://defectdojo.com/p?x=1&amp;y=2"])

    def test_expanded_drops_foreign_hrefs_including_autolinks(self):
        text = (
            "# h\n\n## Expanded Message\n\n"
            "[a](https://evil.example/a) <https://evil.example/b> "
            '<a href="https://evil.example/c">c</a> [ok](https://github.com/DefectDojo/django-DefectDojo)\n'
        )
        html = os_message.parse_os_message(text)["expanded_html"]
        self.assertNotIn('href="https://evil.example', html)
        self.assertEqual(html.count("href="), 1)
        self.assertIn('href="https://github.com/DefectDojo/django-DefectDojo"', html)


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class TestGetOsBanner(SimpleTestCase):

    def setUp(self):
        cache.clear()
        os_message._parsed_banner = None

    def test_same_text_is_parsed_once(self):
        with patch("dojo.announcement.os_message.fetch_os_message", return_value="# Headline\n"), \
             patch("dojo.announcement.os_message.parse_os_message", wraps=os_message.parse_os_message) as mock_parse:
            first = os_message.get_os_banner()
            second = os_message.get_os_banner()
            # Each caller gets its own dict, so one request cannot change what the next one sees.
            first["message"] = "changed"
            third = os_message.get_os_banner()
        self.assertEqual(mock_parse.call_count, 1)
        self.assertEqual(second["message"], "Headline")
        self.assertEqual(third["message"], "Headline")

    def test_new_text_is_parsed_again(self):
        with patch("dojo.announcement.os_message.fetch_os_message", side_effect=["# One\n", "# Two\n"]):
            self.assertEqual(os_message.get_os_banner()["message"], "One")
            self.assertEqual(os_message.get_os_banner()["message"], "Two")

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

    @override_settings(OS_MESSAGE_ENABLED=False)
    def test_show_plg_link_is_false_when_os_message_disabled(self):
        with patch.object(context_processors, "get_os_banner", return_value=None):
            result = context_processors.globalize_vars(self.request)
        self.assertFalse(result["SHOW_PLG_LINK"])

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

    def _authed_request(self, *, dismissed_hash=""):
        request = RequestFactory().get("/")
        request.user = SimpleNamespace(
            is_authenticated=True,
            usercontactinfo=SimpleNamespace(
                user_state_details={os_message.OS_MESSAGE_DISMISSED_KEY: dismissed_hash},
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


@versioned_fixtures
class TestProDemoLinks(DojoTestCase):

    """The "Book a demo" links next to the existing Pro links: where they point and when they show."""

    fixtures = ["dojo_testdata.json"]

    DEMO_URL = (
        "https://defectdojo.com/book-a-demo/open-source?utm_source=oss-app&amp;utm_medium=in-app"
        "&amp;utm_campaign=oss-demo-prompt&amp;utm_content="
    )
    SUPPORT_DEMO_URL = DEMO_URL + "support-page"
    MENU_DEMO_URL = DEMO_URL + "user-menu"
    PAYG_URL = "https://cloud.defectdojo.com/onboarding?payg=1"

    def setUp(self):
        self.client.force_login(User.objects.get(username="admin"))
        # Keep the page render off the network: the banner itself is covered above.
        patcher = patch.object(context_processors, "get_os_banner", return_value=None)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _support_page(self):
        response = self.client.get(reverse("support"))
        self.assertEqual(response.status_code, 200)
        return response.content.decode()

    def test_support_page_links_to_demo_form(self):
        html = self._support_page()
        # One button in the Pro section's hero and one in its footer.
        self.assertEqual(html.count(self.SUPPORT_DEMO_URL), 2)

    def test_demo_is_the_main_action_on_the_support_page(self):
        html = self._support_page()
        self.assertEqual(html.count(f'class="sp-btn sp-btn-primary" href="{self.SUPPORT_DEMO_URL}"'), 2)
        self.assertEqual(html.count(f'class="sp-btn sp-btn-ghost" href="{self.PAYG_URL}"'), 2)

    def test_user_menu_links_to_demo_form(self):
        html = self._support_page()
        self.assertEqual(html.count(self.MENU_DEMO_URL), 1)
        # The demo link is the menu's only Pro item. Pay-as-you-go stays on the Support page.
        self.assertEqual(html.count(self.PAYG_URL), 2)

    def test_pro_links_open_new_tab_without_referrer(self):
        html = self._support_page()
        anchors = re.findall(r"<a\b[^>]*>", html)
        pro_links = [a for a in anchors if "book-a-demo" in a or self.PAYG_URL in a]
        self.assertEqual(len(pro_links), 5)
        for anchor in pro_links:
            with self.subTest(anchor=anchor):
                self.assertIn('target="_blank"', anchor)
                self.assertIn('rel="noopener noreferrer"', anchor)

    def test_demo_links_carry_nothing_about_the_instance(self):
        html = self._support_page()
        for url in re.findall(r'href="(https://defectdojo\.com/book-a-demo[^"]*)"', html):
            with self.subTest(url=url):
                self.assertIn(url, {self.SUPPORT_DEMO_URL, self.MENU_DEMO_URL})

    @override_settings(OS_MESSAGE_ENABLED=False)
    def test_user_menu_pro_link_hidden_when_os_message_disabled(self):
        html = self._support_page()
        self.assertNotIn(self.MENU_DEMO_URL, html)
        # Only the Support page's own links are left.
        self.assertEqual(html.count(self.PAYG_URL), 2)
        self.assertEqual(html.count(self.SUPPORT_DEMO_URL), 2)
