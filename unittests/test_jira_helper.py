import logging
from unittest.mock import Mock

from dojo.jira_link import helper as jira_helper
from unittests.dojo_test_case import DojoTestCase

logger = logging.getLogger(__name__)


class JIRAHelperTest(DojoTestCase):

    """Unit tests for JIRA helper functions"""

    def create_mock_jira_issue(self, status_category_key=None, resolution=None):
        """
        Helper to create a mock JIRA issue with configurable status category and resolution.

        Args:
            status_category_key: The key for statusCategory (e.g., "new", "indeterminate", "done")
            resolution: Resolution value (None, "None", or a dict with resolution details)

        """
        issue = Mock()
        issue.fields = Mock()

        if status_category_key is not None:
            issue.fields.status = Mock()
            issue.fields.status.statusCategory = Mock()
            issue.fields.status.statusCategory.key = status_category_key
        else:
            # Simulate missing status or statusCategory
            del issue.fields.status

        issue.fields.resolution = resolution

        return issue

    def test_issue_from_jira_is_active_with_new_status(self):
        """Test that issues with 'new' status category are treated as active"""
        issue = self.create_mock_jira_issue(status_category_key="new")
        result = jira_helper.issue_from_jira_is_active(issue)
        self.assertTrue(result, "Issue with 'new' status category should be active")

    def test_issue_from_jira_is_active_with_indeterminate_status(self):
        """Test that issues with 'indeterminate' status category are treated as active"""
        issue = self.create_mock_jira_issue(status_category_key="indeterminate")
        result = jira_helper.issue_from_jira_is_active(issue)
        self.assertTrue(result, "Issue with 'indeterminate' status category should be active")

    def test_issue_from_jira_is_active_with_done_status(self):
        """Test that issues with 'done' status category are treated as inactive"""
        issue = self.create_mock_jira_issue(status_category_key="done")
        result = jira_helper.issue_from_jira_is_active(issue)
        self.assertFalse(result, "Issue with 'done' status category should be inactive")

    def test_issue_from_jira_is_active_with_unknown_status_and_no_resolution(self):
        """Test that issues with unknown status category fall back to resolution check"""
        issue = self.create_mock_jira_issue(status_category_key="custom_status", resolution=None)
        result = jira_helper.issue_from_jira_is_active(issue)
        self.assertTrue(result, "Issue with unknown status and no resolution should be active")

    def test_issue_from_jira_is_active_with_unknown_status_and_resolution(self):
        """Test that issues with unknown status category and resolution are treated as inactive"""
        resolution = {"id": "11", "name": "Fixed"}
        issue = self.create_mock_jira_issue(status_category_key="custom_status", resolution=resolution)
        result = jira_helper.issue_from_jira_is_active(issue)
        self.assertFalse(result, "Issue with unknown status and resolution should be inactive")

    def test_issue_from_jira_is_active_with_unknown_status_and_none_resolution(self):
        """Test that issues with unknown status category and 'None' resolution are treated as active"""
        issue = self.create_mock_jira_issue(status_category_key="custom_status", resolution="None")
        result = jira_helper.issue_from_jira_is_active(issue)
        self.assertTrue(result, "Issue with unknown status and 'None' resolution should be active")

    def test_issue_from_jira_is_active_without_status_category_and_no_resolution(self):
        """Test fallback to resolution check when status category is not available"""
        issue = Mock()
        issue.fields = Mock()
        issue.fields.resolution = None
        result = jira_helper.issue_from_jira_is_active(issue)
        self.assertTrue(result, "Issue without status category and no resolution should be active")

    def test_issue_from_jira_is_active_without_status_category_with_resolution(self):
        """Test fallback to resolution check when status category is not available"""
        issue = Mock()
        issue.fields = Mock()
        issue.fields.resolution = {"id": "11", "name": "Fixed"}
        result = jira_helper.issue_from_jira_is_active(issue)
        self.assertFalse(result, "Issue without status category but with resolution should be inactive")

    def test_issue_from_jira_is_active_without_status_category_with_none_string_resolution(self):
        """Test that 'None' string resolution is treated as active"""
        issue = Mock()
        issue.fields = Mock()
        issue.fields.resolution = "None"
        result = jira_helper.issue_from_jira_is_active(issue)
        self.assertTrue(result, "Issue with 'None' string resolution should be active")

    def test_issue_from_jira_is_active_without_fields(self):
        """Test that issues without fields attribute fall back gracefully"""
        issue = Mock(spec=[])  # Mock with no attributes
        result = jira_helper.issue_from_jira_is_active(issue)
        self.assertTrue(result, "Issue without fields should default to active")

    def test_issue_from_jira_is_active_with_missing_status_attribute(self):
        """Test AttributeError handling when status is missing"""
        issue = Mock()
        issue.fields = Mock(spec=["resolution"])  # Has fields but no status
        issue.fields.resolution = None
        result = jira_helper.issue_from_jira_is_active(issue)
        self.assertTrue(result, "Issue with missing status attribute should fall back to resolution check")

    def test_issue_from_jira_is_active_with_missing_status_category(self):
        """Test AttributeError handling when statusCategory is missing"""
        issue = Mock()
        issue.fields = Mock()
        issue.fields.status = Mock(spec=[])  # Has status but no statusCategory
        issue.fields.resolution = None
        result = jira_helper.issue_from_jira_is_active(issue)
        self.assertTrue(result, "Issue with missing statusCategory should fall back to resolution check")

    def test_issue_from_jira_is_active_with_missing_status_category_key(self):
        """Test AttributeError handling when statusCategory.key is missing"""
        issue = Mock()
        issue.fields = Mock()
        issue.fields.status = Mock()
        issue.fields.status.statusCategory = Mock(spec=[])  # Has statusCategory but no key
        issue.fields.resolution = None
        result = jira_helper.issue_from_jira_is_active(issue)
        self.assertTrue(result, "Issue with missing statusCategory.key should fall back to resolution check")

    def test_issue_from_jira_is_active_status_category_takes_precedence(self):
        """Test that status category takes precedence over resolution"""
        # Create an issue with "done" status but no resolution
        issue = self.create_mock_jira_issue(status_category_key="done", resolution=None)
        result = jira_helper.issue_from_jira_is_active(issue)
        self.assertFalse(result, "Status category should take precedence over resolution")

        # Create an issue with "new" status but has a resolution
        resolution = {"id": "11", "name": "Fixed"}
        issue = self.create_mock_jira_issue(status_category_key="new", resolution=resolution)
        result = jira_helper.issue_from_jira_is_active(issue)
        self.assertTrue(result, "Status category should take precedence over resolution")
