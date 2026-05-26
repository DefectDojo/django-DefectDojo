import logging
from unittest.mock import Mock

import dojo.jira.helper as jira_helper
from unittest import TestCase

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
