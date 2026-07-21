"""
Base test case for API v3 (§6 preamble).

All v3 tests use the standard in-process Django test client (via ``DojoAPITestCase``) so the full
URLconf/middleware/auth/CSRF stack runs, server-side exceptions propagate as real tracebacks,
``assertNumQueries`` works and the test transaction is shared. ``ninja.testing.TestClient`` is
reserved for kernel-internal unit tests only.
"""
from __future__ import annotations

import json
from unittest import skipUnless

from django.conf import settings
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.models import User
from dojo.utils import get_system_setting
from unittests.dojo_test_case import DojoAPITestCase


@skipUnless(
    settings.V3_FEATURE_LOCATIONS,
    "API v3 is mounted only when V3_FEATURE_LOCATIONS is enabled (D5); with the flag off the "
    "endpoints do not exist, so these contract tests are not applicable. The CI unit-test matrix "
    "runs a flag-off leg, hence the guard. Flag-independent kernel unit tests (OpenAPI render, "
    "static authz tripwire, expand cycle guard) use SimpleTestCase directly and still run.",
)
class ApiV3TestCase(DojoAPITestCase):

    """Shared helpers: v3 URL prefix, token + session/CSRF clients, JSON assertions."""

    # v3 requires V3_FEATURE_LOCATIONS=True, under which the legacy Endpoint model raises on load;
    # use the locations-aware fixture (same products/engagements/tests/findings, no Endpoint rows).
    fixtures = ["dojo_testdata_locations.json"]

    def setUp(self):
        super().setUp()
        self.admin = User.objects.get(username="admin")
        self.token, _ = Token.objects.get_or_create(user=self.admin)
        # Default client authenticates with a token (mirrors login_as_admin()).
        self.client = self.token_client()

    # --- URL helper -------------------------------------------------------------------------
    def v3_url(self, path: str = "") -> str:
        prefix = get_system_setting("url_prefix")
        return f"/{prefix}{settings.API_V3_URL_PREFIX}/{path.lstrip('/')}"

    # --- client helpers ---------------------------------------------------------------------
    def token_client(self, *, user: User | None = None) -> APIClient:
        token = self.token if user is None else Token.objects.get_or_create(user=user)[0]
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        return client

    def session_client(self, *, user: User | None = None, enforce_csrf: bool = False) -> APIClient:
        client = APIClient(enforce_csrf_checks=enforce_csrf)
        client.force_login(user or self.admin)
        return client

    def anonymous_client(self) -> APIClient:
        return APIClient()

    # --- assertion helpers ------------------------------------------------------------------
    def get_json(self, path: str, *, client: APIClient | None = None, data: dict | None = None, expected: int = 200):
        client = client or self.client
        response = client.get(self.v3_url(path), data or {})
        self.assertEqual(expected, response.status_code, response.content[:1000])
        return json.loads(response.content) if response.content else None
