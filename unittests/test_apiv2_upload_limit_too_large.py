"""
Regression tests: an API request whose body exceeds the server's upload limits
must produce a client-actionable ``413 Request Entity Too Large``, not a bare
``500``.

Django's request parser raises a ``SuspiciousOperation`` subclass
(``RequestDataTooBig`` when the body is larger than
``DATA_UPLOAD_MAX_MEMORY_SIZE``, ``TooManyFieldsSent`` when a multipart form
carries more fields than ``DATA_UPLOAD_MAX_NUMBER_FIELDS``) the first time
``request.data`` is evaluated. For the import/reimport endpoints that happens in
the permission check, which already converts it to a clear error. Every other
write path parses ``request.data`` only inside the handler, so the exception
escaped ``drf``'s default handler (which returns ``None`` for it), fell through
to the generic branch of ``custom_exception_handler``, and the caller received
``500 Internal server error`` plus an entry in error reporting that reads like an
outage.

Reported from a production ``PATCH /api/v2/findings/<id>/`` whose body exceeded
``DATA_UPLOAD_MAX_MEMORY_SIZE``: the single-finding update is not an import, so it
never reached the import permission guard.

Only the two upload-limit ``SuspiciousOperation`` subclasses translate to 413.
Any other ``SuspiciousOperation`` points at a server-side or security concern and
must keep returning 500 so it stays visible.
"""

from django.core.exceptions import (
    DisallowedHost,
    RequestDataTooBig,
    SuspiciousOperation,
    TooManyFieldsSent,
)
from django.test import override_settings
from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient, APITestCase

from dojo.api_v2.exception_handler import custom_exception_handler
from dojo.models import Finding


class UploadLimitExceptionHandlerTest(APITestCase):

    """Coverage of the handler's upload-limit branch, called directly."""

    fixtures = ["dojo_testdata.json"]

    def test_request_data_too_big_returns_413(self):
        response = custom_exception_handler(
            RequestDataTooBig("Request body exceeded settings.DATA_UPLOAD_MAX_MEMORY_SIZE."), {},
        )

        self.assertIsNotNone(response)
        self.assertEqual(
            response.status_code, 413,
            msg=f"expected 413 for RequestDataTooBig, got {response.status_code}",
        )

    def test_too_many_fields_sent_returns_413(self):
        response = custom_exception_handler(
            TooManyFieldsSent("The number of GET/POST parameters exceeded settings.DATA_UPLOAD_MAX_NUMBER_FIELDS."), {},
        )

        self.assertEqual(
            response.status_code, 413,
            msg=f"expected 413 for TooManyFieldsSent, got {response.status_code}",
        )

    def test_message_names_the_limits_and_echoes_no_payload(self):
        response = custom_exception_handler(
            RequestDataTooBig("Request body exceeded settings.DATA_UPLOAD_MAX_MEMORY_SIZE."), {},
        )

        message = response.data["message"]
        self.assertIn("DD_DATA_UPLOAD_MAX_MEMORY_SIZE", message)
        self.assertIn("DD_DATA_UPLOAD_MAX_NUMBER_FIELDS", message)
        # The oversized body itself must never be reflected back in the response.
        self.assertNotIn("settings.DATA_UPLOAD_MAX_MEMORY_SIZE", message)

    def test_other_suspicious_operation_still_returns_500(self):
        """A non-size SuspiciousOperation must keep surfacing as 500, not 413."""
        for exc in (DisallowedHost("Invalid HTTP_HOST header"), SuspiciousOperation("something else")):
            with self.subTest(exc=type(exc).__name__):
                response = custom_exception_handler(exc, {})
                self.assertEqual(
                    response.status_code, 500,
                    msg=f"expected 500 for {type(exc).__name__}, got {response.status_code}",
                )


class UploadLimitApiTest(APITestCase):

    """Coverage through a real finding PATCH and the configured handler."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        token = Token.objects.get(user__username="admin")
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        self.finding = Finding.objects.first()
        self.url = reverse("finding-detail", args=[self.finding.id])

    @override_settings(DATA_UPLOAD_MAX_MEMORY_SIZE=50)
    def test_oversized_patch_returns_413_not_500(self):
        """
        The reproduction of the production report.

        With the body-size limit lowered below the request size, parsing
        ``request.data`` inside ``partial_update`` raises ``RequestDataTooBig``.
        Before the fix that escaped as a 500; now it is a clean 413.
        """
        response = self.client.patch(
            self.url,
            {"severity": "High", "_pad": "x" * 500},
            format="json",
        )

        self.assertEqual(
            response.status_code, 413,
            msg=f"expected 413 for an oversized PATCH, got {response.status_code}",
        )
        self.assertIn("upload limits", response.data["message"].lower())

    def test_small_patch_still_succeeds(self):
        """Guard against the handler swallowing legitimate, under-limit writes."""
        response = self.client.patch(
            self.url,
            {"severity": "High"},
            format="json",
        )

        self.assertEqual(
            response.status_code, 200,
            msg=f"expected 200 for an under-limit PATCH, got {response.status_code}",
        )
