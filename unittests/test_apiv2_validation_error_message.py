"""
Regression tests: the ``message`` beside a 400's field map reads as sentences, not a Python repr.

``custom_exception_handler`` adds ``message = str(exc)`` to every 4xx body whose text differs from its
``detail``. For a serializer ``ValidationError`` that text was the repr of the error dict, for example
``{'ordering': [ErrorDetail(string='Not a valid choice.', code='invalid')]}``, which API callers that read
``message`` then had to parse. The key stays; its value is now the field messages as plain text.
"""

from django.test import SimpleTestCase
from rest_framework import serializers
from rest_framework.exceptions import NotFound

from dojo.api_v2.exception_handler import custom_exception_handler


class ValidationErrorMessageTest(SimpleTestCase):
    def _message(self, exc):
        response = custom_exception_handler(exc, {})
        self.assertEqual(400, response.status_code)
        message = response.data["message"]
        self.assertNotIn("ErrorDetail", message, message)
        return message

    def test_a_field_map_reads_as_field_and_message(self):
        message = self._message(serializers.ValidationError({"name": ["This field is required."], "severity": ["Not a valid choice."]}))
        self.assertEqual("name: This field is required. severity: Not a valid choice.", message)

    def test_a_nested_field_names_its_path(self):
        message = self._message(serializers.ValidationError({"tabular_configuration": {"ordering": ["This block cannot be sorted by x."]}}))
        self.assertEqual("tabular_configuration.ordering: This block cannot be sorted by x.", message)

    def test_non_field_errors_read_without_a_field_name(self):
        message = self._message(serializers.ValidationError({"non_field_errors": ["The dates are in the wrong order."]}))
        self.assertEqual("The dates are in the wrong order.", message)

    def test_a_list_body_stays_a_list(self):
        # A list body has nowhere to put a message; it already is the messages.
        response = custom_exception_handler(serializers.ValidationError(["First problem.", "Second problem."]), {})
        self.assertEqual(["First problem.", "Second problem."], response.data)

    def test_the_field_map_itself_is_unchanged(self):
        response = custom_exception_handler(serializers.ValidationError({"name": ["This field is required."]}), {})
        self.assertEqual(["This field is required."], response.data["name"])

    def test_another_client_error_keeps_its_body(self):
        response = custom_exception_handler(NotFound("No such thing."), {})
        self.assertEqual(404, response.status_code)
        self.assertEqual({"detail": "No such thing."}, response.data)
