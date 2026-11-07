from urllib.parse import urlencode

from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient, APITestCase

from unittests.dojo_test_case import versioned_fixtures


@versioned_fixtures
class OA3SchemaContentDispositionTest(APITestCase):
    # Regression: GET /api/v2/oa3/schema/?version=<CR/LF> returned 500 with
    # django.http.response.BadHeaderError, because drf-spectacular interpolated the
    # attacker-controlled ?version= query parameter into the Content-Disposition filename
    # unsanitized. The header injection never succeeds (Django rejects CR/LF in header
    # values), but the unhandled exception became a 500 plus a diagnostics error report on
    # every scanner probe. DojoSpectacularAPIView now strips CR/LF (and the quote delimiter)
    # from the filename.
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        token = Token.objects.get(user__username="admin")
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)

    def test_crlf_in_version_is_not_a_500_and_injects_no_header(self):
        query = urlencode({"format": "json", "version": "test\r\nX-Injected: 1"})
        response = self.client.get(reverse("schema_oa3") + "?" + query)

        self.assertEqual(
            response.status_code, 200,
            msg=f"expected 200, got {response.status_code} (CR/LF in ?version= must not crash the response)",
        )
        disposition = response.headers.get("Content-Disposition", "")
        self.assertNotIn("\r", disposition, msg=f"Content-Disposition carried a CR: {disposition!r}")
        self.assertNotIn("\n", disposition, msg=f"Content-Disposition carried a LF: {disposition!r}")
        self.assertNotIn("X-Injected", response.headers, msg="the crafted header must not be injected")

    def test_a_normal_version_is_still_served(self):
        query = urlencode({"format": "json", "version": "v2"})
        response = self.client.get(reverse("schema_oa3") + "?" + query)

        self.assertEqual(response.status_code, 200, msg=f"expected 200, got {response.status_code}")
        self.assertIn("v2", response.headers.get("Content-Disposition", ""))
