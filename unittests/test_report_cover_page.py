from django.test import Client
from django.urls import reverse

from unittests.dojo_test_case import DojoTestCase, versioned_fixtures


@versioned_fixtures
class ReportCoverPageTest(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def test_requires_login(self):
        response = Client().get(reverse("report_cover_page"), {"title": "Quarterly report"})
        self.assertEqual(302, response.status_code)
        self.assertIn(reverse("login"), response["Location"])

    def test_renders_for_a_logged_in_user(self):
        client = Client()
        client.force_login(self.get_test_admin())
        response = client.get(reverse("report_cover_page"), {"title": "Quarterly <report>", "info": "info text"})
        self.assertEqual(200, response.status_code)
        self.assertContains(response, "Quarterly &lt;report&gt;")
        self.assertContains(response, "info text")
