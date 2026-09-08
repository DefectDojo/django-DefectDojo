"""Auth contract tests for API v3 (D8 / §4.2): token AND session+CSRF, both on the same endpoint."""
from __future__ import annotations

from .base import ApiV3TestCase


class TestApiV3Auth(ApiV3TestCase):

    def test_token_auth_get(self):
        """A v2 token authenticates a v3 GET (same token store)."""
        response = self.token_client().get(self.v3_url("findings"))
        self.assertEqual(200, response.status_code, response.content[:500])
        self.assertEqual("alpha", response["X-API-Status"])

    def test_session_auth_get(self):
        """Django session authenticates a v3 GET (safe method needs no CSRF)."""
        response = self.session_client().get(self.v3_url("findings"))
        self.assertEqual(200, response.status_code, response.content[:500])

    def test_anonymous_is_401_problem_json(self):
        """No credentials -> 401 problem+json (not 403, not a redirect)."""
        response = self.anonymous_client().get(self.v3_url("findings"))
        self.assertEqual(401, response.status_code, response.content[:500])
        self.assertEqual("application/problem+json", response["Content-Type"])
        body = response.json()
        self.assertEqual(401, body["status"])
        self.assertIn("type", body)
        self.assertIn("title", body)

    def test_both_auth_modes_on_same_endpoint(self):
        """The same endpoint accepts both token and session auth."""
        self.assertEqual(200, self.token_client().get(self.v3_url("findings")).status_code)
        self.assertEqual(200, self.session_client().get(self.v3_url("findings")).status_code)

    def test_token_bypasses_csrf_on_unsafe_method(self):
        """Header (token) auth needs no CSRF: an unsafe POST reaches the handler (400, not 401/403)."""
        response = self.token_client().post(
            self.v3_url("import"), {"scan_type": "ZAP Scan", "mode": "import"}, format="multipart",
        )
        self.assertNotIn(response.status_code, (401, 403), response.content[:500])
        self.assertEqual(400, response.status_code, response.content[:500])

    def test_session_csrf_enforced_on_unsafe_method(self):
        """Cookie (session) auth on an unsafe method without a CSRF token -> 403."""
        client = self.session_client(enforce_csrf=True)
        response = client.post(
            self.v3_url("import"), {"scan_type": "ZAP Scan", "mode": "import"}, format="multipart",
        )
        self.assertEqual(403, response.status_code, response.content[:500])
