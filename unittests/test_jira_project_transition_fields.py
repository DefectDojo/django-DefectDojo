from unittest.mock import Mock

from django.core.exceptions import ValidationError
from django.test import SimpleTestCase
from rest_framework import serializers

from dojo.jira.api.serializers import JIRAProjectSerializer
from dojo.models import JIRA_Instance, JIRA_Project


class JIRAProjectTransitionFieldsValidationTest(SimpleTestCase):

    """
    The close/reopen transition fields are sent as the `fields` object of a
    JIRA transition call. A bare transition ID saved in one of these JSON
    fields produced the invalid payload {"transition": {...}, "fields": 141}.
    """

    FIELD_NAMES = ("close_transition_fields", "reopen_transition_fields")

    def _project(self, **fields):
        return JIRA_Project(jira_instance=JIRA_Instance(), **fields)

    def _serializer(self):
        return JIRAProjectSerializer(context={"request": Mock(method="POST")})

    def test_model_accepts_objects_and_empty_values(self):
        for field_name in self.FIELD_NAMES:
            for value in (None, {}, {"resolution": {"name": "Done"}}):
                with self.subTest(field=field_name, value=value):
                    self._project(**{field_name: value}).clean()

    def test_model_rejects_values_that_are_not_json_objects(self):
        for field_name in self.FIELD_NAMES:
            for value in (141, "141", [141]):
                with self.subTest(field=field_name, value=value):
                    with self.assertRaises(ValidationError) as raised:
                        self._project(**{field_name: value}).clean()

                    self.assertEqual([field_name], list(raised.exception.message_dict))

    def test_serializer_accepts_objects_and_empty_values(self):
        for field_name in self.FIELD_NAMES:
            for value in (None, {}, {"resolution": {"name": "Done"}}):
                with self.subTest(field=field_name, value=value):
                    self._serializer().validate({"product": Mock(), field_name: value})

    def test_serializer_rejects_values_that_are_not_json_objects(self):
        for field_name in self.FIELD_NAMES:
            for value in (141, "141", [141]):
                with self.subTest(field=field_name, value=value):
                    with self.assertRaises(serializers.ValidationError) as raised:
                        self._serializer().validate({"product": Mock(), field_name: value})

                    self.assertEqual([field_name], list(raised.exception.detail))
