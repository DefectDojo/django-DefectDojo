from urllib.parse import urlencode

from django.urls import reverse
from rest_framework.test import APIClient, APITestCase


class OA3SchemaContentDispositionTest(APITestCase):
    # Regression: GET /api/v2/oa3/schema/?version=<CR/LF> returned 500 with
    # django.http.response.BadHeaderError, because drf-spectacular interpolated the
    # attacker-controlled ?version= query parameter into the Content-Disposition filename
    # unsanitized. The header injection never succeeds (Django rejects CR/LF in header
    # values), but the unhandled exception became a 500 plus an error report on every
    # scanner probe. Other characters got through Django and broke the header further on:
    # a NUL, or a U+2028/U+0085 that Django MIME-folds onto a new line, made nginx answer
    # 502 ("upstream sent invalid header"). DojoSpectacularAPIView now keeps only the
    # characters a version string uses. The endpoint is public, so the requests are anonymous.

    def get_schema(self, version):
        query = urlencode({"format": "json", "version": version})
        return APIClient().get(reverse("schema_oa3") + "?" + query)

    def test_hostile_version_is_served_with_a_plain_ascii_filename(self):
        cases = {
            "CR/LF header injection": ("test\r\nX-Injected: 1", "testX-Injected1"),
            "NUL": ("a\x00b", "ab"),
            "U+2028 and U+0085 line separators": ("a\u2028b\x85c", "abc"),
            "quote and backslash": ('a"; filename=evil\\', "afilenameevil"),
            "path separators": ("../../etc/passwd", "....etcpasswd"),
        }
        for name, (version, expected) in cases.items():
            with self.subTest(name):
                response = self.get_schema(version)

                self.assertEqual(
                    response.status_code, 200,
                    msg=f"expected 200, got {response.status_code} (a hostile ?version= must not break the response)",
                )
                self.assertEqual(
                    response.headers.get("Content-Disposition"),
                    f'inline; filename="DefectDojo API v2 ({expected}).json"',
                    msg="the filename must keep only [A-Za-z0-9._+-] from ?version=",
                )
                self.assertNotIn("X-Injected", response.headers, msg="the crafted header must not be injected")

    def test_a_version_with_nothing_safe_left_is_dropped_from_the_filename(self):
        response = self.get_schema("\r\n\x00")

        self.assertEqual(response.status_code, 200, msg=f"expected 200, got {response.status_code}")
        self.assertEqual(response.headers.get("Content-Disposition"), 'inline; filename="DefectDojo API v2.json"')

    def test_a_normal_version_is_still_served(self):
        response = self.get_schema("v2")

        self.assertEqual(response.status_code, 200, msg=f"expected 200, got {response.status_code}")
        self.assertEqual(response.headers.get("Content-Disposition"), 'inline; filename="DefectDojo API v2 (v2).json"')
