from django.core.exceptions import ValidationError
from django.test import SimpleTestCase

from dojo.models import JIRA_Instance, JIRA_Project


class JIRAProjectTransitionFieldsValidationTest(SimpleTestCase):

    """
    close_transition_fields / reopen_transition_fields are sent as the `fields`
    object of the JIRA transition call, so they must be a JSON object. A number
    such as a transition ID typed into the field produced the payload
    {"transition": {...}, "fields": 141}, which JIRA rejects.
    """

    FIELD_NAMES = ("close_transition_fields", "reopen_transition_fields")

    def _project(self, **fields):
        return JIRA_Project(jira_instance=JIRA_Instance(), **fields)

    def test_empty_and_object_values_are_valid(self):
        for field_name in self.FIELD_NAMES:
            for value in (None, {}, {"resolution": {"name": "Done"}}):
                with self.subTest(field=field_name, value=value):
                    self._project(**{field_name: value}).clean()

    def test_values_that_are_not_a_json_object_are_rejected(self):
        for field_name in self.FIELD_NAMES:
            for value in (141, 0, "141", [141], True):
                with self.subTest(field=field_name, value=value):
                    with self.assertRaises(ValidationError) as raised:
                        self._project(**{field_name: value}).clean()

                    self.assertEqual([field_name], list(raised.exception.message_dict))
                    self.assertIn("JSON object", raised.exception.message_dict[field_name][0])
                    self.assertIn("Transition ID", raised.exception.message_dict[field_name][0])

    def test_both_fields_are_reported_together(self):
        with self.assertRaises(ValidationError) as raised:
            self._project(close_transition_fields=141, reopen_transition_fields=491).clean()

        self.assertEqual(set(self.FIELD_NAMES), set(raised.exception.message_dict))

    def test_sla_notification_conflict_is_still_reported(self):
        with self.assertRaises(ValidationError) as raised:
            self._project(
                product_jira_sla_notification=True,
                suppress_sla_notification_comments=True,
                close_transition_fields=141,
            ).clean()

        self.assertEqual({"suppress_sla_notification_comments", "close_transition_fields"}, set(raised.exception.message_dict))
