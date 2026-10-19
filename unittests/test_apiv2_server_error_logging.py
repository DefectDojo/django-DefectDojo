"""
custom_exception_handler answers unexpected API errors itself, so Django's django.request
record (and the mail_admins email) must still carry the exception's traceback.
"""

from unittest.mock import patch

from django.core import mail
from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.exceptions import APIException
from rest_framework.test import APIClient, APITestCase

from dojo.api_v2.exception_handler import custom_exception_handler
from dojo.product.api.views import ProductViewSet
from unittests.dojo_test_case import versioned_fixtures


class ServiceUnavailableError(APIException):
    status_code = 503
    default_detail = "backend unavailable"


@versioned_fixtures
class ApiServerErrorLoggingTest(APITestCase):

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        token = Token.objects.get(user__username="admin")
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)

    def _get_products_raising(self, exc):
        with patch.object(ProductViewSet, "list", side_effect=exc), \
                self.assertLogs("django.request", level="ERROR") as logs:
            response = self.client.get(reverse("product-list"))
        return response, logs.records

    def test_unexpected_exception_is_logged_with_its_traceback(self):
        exc = RuntimeError("unexpected failure in the view")
        response, records = self._get_products_raising(exc)

        self.assertEqual(response.status_code, 500)
        self.assertEqual(len(records), 1)
        self.assertIsNotNone(records[0].exc_info)
        self.assertIs(records[0].exc_info[1], exc)
        self.assertEqual(records[0].status_code, 500)

    def test_admin_error_email_contains_the_traceback(self):
        mail.outbox = []
        # Not through assertLogs, which swaps out the mail_admins handler.
        with patch.object(ProductViewSet, "list", side_effect=RuntimeError("unexpected failure in the view")):
            self.client.get(reverse("product-list"))

        self.assertEqual(len(mail.outbox), 1)
        body = mail.outbox[0].body
        self.assertIn("RuntimeError", body)
        self.assertIn("unexpected failure in the view", body)
        self.assertNotIn("Traceback (most recent call last):\n  None", body)

    def test_server_side_api_exception_is_logged_with_its_traceback(self):
        exc = ServiceUnavailableError()
        response, records = self._get_products_raising(exc)

        self.assertEqual(response.status_code, 503)
        self.assertEqual(len(records), 1)
        self.assertIsNotNone(records[0].exc_info)
        self.assertIs(records[0].exc_info[1], exc)

    def test_response_body_does_not_change(self):
        response, _ = self._get_products_raising(RuntimeError("secret internal detail"))

        self.assertEqual(response.status_code, 500)
        self.assertNotIn("secret internal detail", response.content.decode())

    def test_handler_without_a_request_still_answers_500(self):
        with self.assertLogs("dojo.api_v2.exception_handler", level="ERROR"):
            response = custom_exception_handler(RuntimeError("no request in context"), {})

        self.assertEqual(response.status_code, 500)
