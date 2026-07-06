import logging
from unittest import TestCase
from unittest.mock import Mock

import dojo.jira.helper as jira_helper

logger = logging.getLogger(__name__)


class JIRAHelperTest(TestCase):
    def _make_issue(self, status_category_key):
        issue = Mock()
        issue.fields.status.statusCategory.key = status_category_key
        return issue

    def test_issue_from_jira_is_active_with_new_status(self):
        self.assertTrue(jira_helper.issue_from_jira_is_active(self._make_issue("new")))

    def test_issue_from_jira_is_active_with_indeterminate_status(self):
        self.assertTrue(jira_helper.issue_from_jira_is_active(self._make_issue("indeterminate")))

    def test_issue_from_jira_is_active_with_done_status(self):
        self.assertFalse(jira_helper.issue_from_jira_is_active(self._make_issue("done")))

    def test_issue_from_jira_is_active_with_unknown_status(self):
        """Any key that is not 'done' is treated as active."""
        self.assertTrue(jira_helper.issue_from_jira_is_active(self._make_issue("custom_status")))

    def test_issue_from_jira_is_active_defaults_to_active_on_missing_attribute(self):
        """AttributeError anywhere in the fields.status.statusCategory.key chain defaults to active."""
        self.assertTrue(jira_helper.issue_from_jira_is_active(Mock(spec=[])))


class JIRAComponentFieldTest(TestCase):

    """
    SC-13173: the JIRA project `component` field holds a comma-separated list of
    component names. prepare_jira_issue_fields must split it into multiple Jira
    components so Jira receives [{"name": "A"}, {"name": "B"}] instead of a single
    component named "A,B".
    """

    def _fields(self, component_name):
        return jira_helper.prepare_jira_issue_fields(
            project_key="PROJ",
            issuetype_name="Bug",
            summary="summary",
            description="description",
            component_name=component_name,
        )

    def test_single_component(self):
        fields = self._fields("Security")
        self.assertEqual([{"name": "Security"}], fields["components"])

    def test_multiple_components_split_on_comma(self):
        fields = self._fields("Security,DevSecOps")
        self.assertEqual([{"name": "Security"}, {"name": "DevSecOps"}], fields["components"])

    def test_multiple_components_whitespace_trimmed(self):
        fields = self._fields("Security, DevSecOps ,  Platform")
        self.assertEqual(
            [{"name": "Security"}, {"name": "DevSecOps"}, {"name": "Platform"}],
            fields["components"],
        )

    def test_empty_entries_dropped(self):
        fields = self._fields("Security,,DevSecOps,")
        self.assertEqual([{"name": "Security"}, {"name": "DevSecOps"}], fields["components"])

    def test_no_component_omits_field(self):
        fields = self._fields("")
        self.assertNotIn("components", fields)

    def test_only_separators_omits_field(self):
        fields = self._fields(" , , ")
        self.assertNotIn("components", fields)
