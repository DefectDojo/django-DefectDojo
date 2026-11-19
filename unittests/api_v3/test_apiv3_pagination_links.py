"""
API v3 ``next`` links follow the registered request-URL resolver.

Regression: ``_page_url()`` and ``_cursor_url()`` built ``next`` / ``previous`` from
``request.build_absolute_uri()``, so a plugin that serves the instance under another address (a
reverse proxy forwards ``Host`` without the public port) could not correct them, and a client
following ``next`` lost the scheme and the port. Both now start from
``dojo.site_url.request_absolute_url()``. With no resolver registered that is
``request.build_absolute_uri()``, so the links are byte for byte what they were.

DB-less: the link builders read only the request.
"""

from django.test import RequestFactory, SimpleTestCase, override_settings

from dojo import site_url as site_url_module
from dojo.api_v3 import pagination
from dojo.site_url import register_request_url_resolver, site_url

PATH = "/api/v3/findings/"
PUBLIC_BASE = "https://team-a.example.test:8443"


def _public_address(_request, path):
    # What a plugin serving the instance under another address does: its own base, the request's path.
    return f"{site_url()}{path}"


class PaginationLinksTest(SimpleTestCase):
    def setUp(self):
        # No resolver leaks into or out of a test.
        for registry in (site_url_module._RESOLVER, site_url_module._REQUEST_RESOLVER):
            saved = registry["fn"]
            registry["fn"] = None
            self.addCleanup(registry.__setitem__, "fn", saved)

    def _request(self, query, host="team-a.example.test", *, secure=False):
        return RequestFactory().get(f"{PATH}{query}", HTTP_HOST=host, secure=secure)

    @override_settings(SITE_URL=PUBLIC_BASE)
    def test_offset_link_uses_the_registered_resolver(self):
        register_request_url_resolver(_public_address, override=True)
        request = self._request("?active=true&limit=2&offset=4")
        self.assertEqual(f"{PUBLIC_BASE}{PATH}?active=true&limit=2&offset=6", pagination._page_url(request, 2, 6))
        self.assertEqual(f"{PUBLIC_BASE}{PATH}?active=true&limit=2&offset=2", pagination._page_url(request, 2, 2))

    @override_settings(SITE_URL=PUBLIC_BASE)
    def test_cursor_link_uses_the_registered_resolver(self):
        register_request_url_resolver(_public_address, override=True)
        request = self._request("?pagination=cursor&limit=2&cursor=old&offset=3")
        self.assertEqual(
            f"{PUBLIC_BASE}{PATH}?pagination=cursor&limit=2&cursor=next",
            pagination._cursor_url(request, "next"),
        )

    @override_settings(SITE_URL=PUBLIC_BASE)
    def test_no_resolver_keeps_the_request_s_own_address(self):
        # Byte for byte what build_absolute_uri() gave: scheme, host and port from the request.
        cases = [
            ("dojo.example.test:8080", False, "http://dojo.example.test:8080"),
            ("192.0.2.10:8443", True, "https://192.0.2.10:8443"),
        ]
        for host, secure, base in cases:
            with self.subTest(host=host):
                request = self._request("?title=caf%C3%A9&limit=2&offset=4", host=host, secure=secure)
                self.assertEqual(f"{base}{PATH}?title=caf%C3%A9&limit=2&offset=6", pagination._page_url(request, 2, 6))
                self.assertEqual(f"{base}{PATH}?title=caf%C3%A9&limit=2&cursor=c", pagination._cursor_url(request, "c"))
