"""
Regression tests: the ``message`` beside a 400's field map reads as sentences, not a Python repr.

``custom_exception_handler`` adds ``message = str(exc)`` to every 4xx body whose text differs from its
``detail``. For a serializer ``ValidationError`` that text was the repr of the error dict, for example
``{'ordering': [ErrorDetail(string='Not a valid choice.', code='invalid')]}``, which API callers that read
``message`` then had to parse. The key stays; its value is now the field messages as plain text, and the
rest of the body (the field map and the ``pro`` announcement) is what it was.
"""

from django.core.exceptions import ValidationError as DjangoValidationError
from django.test import SimpleTestCase, override_settings
from django.urls import reverse
from rest_framework import serializers
from rest_framework.authtoken.models import Token
from rest_framework.exceptions import NotFound
from rest_framework.test import APIClient, APITestCase

from dojo.api_v2.exception_handler import custom_exception_handler
from unittests.dojo_test_case import versioned_fixtures


class ValidationErrorMessageTest(SimpleTestCase):
    def _body(self, detail):
        response = custom_exception_handler(serializers.ValidationError(detail), {})
        self.assertEqual(400, response.status_code)
        self.assertNotIn("ErrorDetail", str(response.data.get("message", "")), response.data)
        return response.data

    def _message(self, detail):
        return self._body(detail)["message"]

    def test_the_whole_body_is_the_field_map_the_message_and_the_announcement(self):
        body = self._body({"name": ["This field is required."], "severity": ["Not a valid choice."]})
        self.assertEqual(
            {
                "name": ["This field is required."],
                "severity": ["Not a valid choice."],
                "message": "name: This field is required. severity: Not a valid choice.",
                "pro": body["pro"],
            },
            body,
        )
        self.assertEqual(1, len(body["pro"]))
        self.assertTrue(body["pro"][0].startswith("Pro comes with support."), body["pro"])

    def test_a_nested_field_names_its_path(self):
        message = self._message({"tabular_configuration": {"ordering": ["This block cannot be sorted by x."]}})
        self.assertEqual("tabular_configuration.ordering: This block cannot be sorted by x.", message)

    def test_a_list_of_nested_errors_names_each_position(self):
        message = self._message({"items": [{}, {"name": ["This field is required."]}]})
        self.assertEqual("items.name: This field is required.", message)

    def test_non_field_errors_read_without_a_field_name(self):
        message = self._message({"non_field_errors": ["The dates are in the wrong order."]})
        self.assertEqual("The dates are in the wrong order.", message)

    @override_settings(REST_FRAMEWORK={"NON_FIELD_ERRORS_KEY": "errors"})
    def test_the_configured_non_field_key_reads_without_a_field_name(self):
        message = self._message({"errors": ["The dates are in the wrong order."]})
        self.assertEqual("The dates are in the wrong order.", message)

    def test_a_detail_key_reads_without_a_field_name(self):
        self.assertEqual("Not allowed here.", self._message({"detail": "Not allowed here."}))

    def test_a_message_without_a_full_stop_gets_one(self):
        message = self._message({"a": ["Not allowed"], "b": ["Bad!"]})
        self.assertEqual("a: Not allowed. b: Bad!", message)

    def test_an_error_map_with_its_own_message_key_keeps_it(self):
        body = self._body({"message": "custom", "code": "x"})
        self.assertEqual("custom", body["message"])
        self.assertEqual("x", body["code"])

    def test_an_empty_error_map_gets_no_message(self):
        self.assertNotIn("message", self._body({}))

    def test_a_list_body_stays_a_list(self):
        # A list body has nowhere to put a message; it already is the messages.
        response = custom_exception_handler(serializers.ValidationError(["First problem.", "Second problem."]), {})
        self.assertEqual(["First problem.", "Second problem."], response.data)

    def test_another_client_error_keeps_its_body(self):
        response = custom_exception_handler(NotFound("No such thing."), {})
        self.assertEqual(404, response.status_code)
        self.assertEqual({"detail": "No such thing."}, response.data)


class DjangoValidationErrorMessageTest(SimpleTestCase):

    """A model or form ``ValidationError`` raised in a v2 view: ``str()`` of it was a list or dict repr."""

    def _body(self, exc):
        response = custom_exception_handler(exc, {})
        self.assertEqual(400, response.status_code)
        self.assertNotIn("['", response.data["message"], response.data)
        self.assertNotIn("{'", response.data["message"], response.data)
        return response.data

    def test_a_message_reads_as_itself(self):
        body = self._body(DjangoValidationError("Schema of Trivy json report is not supported"))
        self.assertEqual("Schema of Trivy json report is not supported.", body["message"])
        self.assertIn("pro", body)

    def test_several_messages_read_in_order(self):
        body = self._body(DjangoValidationError(["The file is empty.", "Pick a scan type."]))
        self.assertEqual("The file is empty. Pick a scan type.", body["message"])

    def test_a_field_error_names_its_field(self):
        body = self._body(DjangoValidationError({"scan_date": ["Enter a valid date."], "__all__": ["The test is closed."]}))
        self.assertEqual("scan_date: Enter a valid date. The test is closed.", body["message"])

    def test_a_message_with_params_is_formatted(self):
        body = self._body(DjangoValidationError("%(value)s is not allowed", params={"value": "x"}))
        self.assertEqual("x is not allowed.", body["message"])


@versioned_fixtures
class ValidationErrorMessageOverTheApiTest(APITestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        token = Token.objects.get(user__username="admin")
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)

    @override_settings(SECURE_SSL_REDIRECT=False)
    def test_a_v2_create_missing_a_field_answers_a_readable_message(self):
        response = self.client.post(reverse("tool_type-list"), {}, format="json")
        self.assertEqual(400, response.status_code, response.data)
        self.assertEqual(["This field is required."], response.data["name"])
        self.assertEqual("name: This field is required.", response.data["message"])
        self.assertIn("pro", response.data)
