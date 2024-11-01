from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from unittests.dojo_test_case import DojoAPITestCase


class NotificationsTest(DojoAPITestCase):

    """Test the metadata APIv2 endpoint."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        token = Token.objects.get(user__username="admin")
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)

        r = self.create(
            template=True,
            scan_added=["alert", "slack"],
        )
        self.creation_id = r.json()["id"]
        self.assertEqual(r.status_code, 201, r.data)

    def tearDown(self):
        self.client.delete(f"{reverse('notifications-list')}/{self.creation_id}")

    def create(self, **kwargs):
        return self.client.post(reverse("notifications-list"), kwargs, format="json")

    def create_test_user(self):
        password = "testTEST1234!@#$"
        r = self.client.post(reverse("user-list"), {
            "username": "api-user-notification",
            "email": "admin@dojo.com",
            "password": password,
        }, format="json")
        return r.json()["id"]

    def test_notification_get(self):
        r = self.client.get(reverse("notifications-list"), format="json")
        self.assertEqual(r.status_code, 200)
        item = self.get_results_by_id(r.json()["results"], 1)
        self.assertEqual(item["template"], False)

    def test_notification_template(self):
        q = {"template": True}
        r = self.client.get(reverse("notifications-list"), q, format="json")
        self.assertEqual(r.status_code, 200)
        item = self.get_results_by_id(r.json()["results"], self.creation_id)
        self.assertEqual(item["template"], True)

    def test_notification_template_multiple(self):
        q = {"template": True, "scan_added": ["alert", "slack"]}
        r = self.client.post(reverse("notifications-list"), q, format="json")
        self.assertEqual("Notification template already exists", r.json()["non_field_errors"][0])

    def test_user_notifications(self):
        """Creates user and checks if template is assigned"""
        user = {"user": self.create_test_user()}
        r = self.client.get(reverse("notifications-list"), user, format="json")
        self.assertEqual(r.status_code, 200)
        item = r.json()["results"][-1]
        self.assertEqual(item["template"], False)
        self.assertIn("alert", item["scan_added"])
        self.assertIn("slack", item["scan_added"])
