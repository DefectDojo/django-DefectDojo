from django.test import TestCase
from django.urls import reverse


class EmptyPermissionsPolicyTests(TestCase):
    def test_empty_policy_still_sets_header(self):
        response = self.client.get(reverse("login"))
        self.assertIn("Permissions-Policy", response.headers)
        # Header may be empty or minimal, but must exist
        self.assertIsNotNone(response["Permissions-Policy"])
        self.assertGreaterEqual(len(response["Permissions-Policy"]), 2)
