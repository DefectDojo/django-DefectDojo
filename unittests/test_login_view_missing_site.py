from django.contrib.sites.models import Site
from django.test import TestCase, override_settings


# Regression: GET /login returned HTTP 500 (Site.DoesNotExist) on instances
# whose django_site row referenced by SITE_ID was absent. Django's LoginView
# resolves the current Site while building the login page context, and raises
# when that row is missing; the login page must render regardless.
@override_settings(SECURE_SSL_REDIRECT=False)
class TestLoginViewMissingSite(TestCase):

    def test_login_page_renders_when_site_present(self):
        # Control case: the default Site row exists, login renders normally.
        self.assertTrue(Site.objects.exists())
        response = self.client.get("/login")
        self.assertEqual(
            response.status_code, 200,
            msg=f"login GET returned {response.status_code} with a Site row present",
        )

    def test_login_page_renders_when_site_row_missing(self):
        # Reproduce the reported condition: no django_site row matches SITE_ID.
        Site.objects.all().delete()
        self.assertFalse(Site.objects.exists())
        response = self.client.get("/login")
        self.assertEqual(
            response.status_code, 200,
            msg=(
                f"login GET returned {response.status_code} when the Site row is "
                "missing (expected 200, not a Site.DoesNotExist 500)"
            ),
        )
