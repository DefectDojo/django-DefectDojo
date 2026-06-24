import logging
from unittest import TestCase
from unittest.mock import Mock, patch

import dojo.finding.helper as finding_helper
import dojo.jira.helper as jira_helper
from dojo.api_v2 import views as api_views
from dojo.finding import views as finding_views

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

    @patch("dojo.jira.helper.jira_transition", return_value=True)
    @patch("dojo.jira.helper.get_jira_connection")
    @patch("dojo.jira.helper.get_jira_issue")
    @patch("dojo.jira.helper.get_jira_instance")
    @patch("dojo.jira.helper.is_jira_configured_and_enabled", return_value=True)
    @patch("dojo.jira.helper.is_jira_enabled", return_value=True)
    def test_close_jira_issue_for_deleted_finding_closes_active_issue(
        self,
        is_jira_enabled,
        is_jira_configured_and_enabled,
        get_jira_instance,
        get_jira_issue,
        get_jira_connection,
        jira_transition,
    ):
        finding = Mock(id=1)
        finding.has_jira_issue = True
        jira_instance = Mock(close_status_key=41)
        jira_issue = Mock(jira_id="10001", jira_key="DD-1")
        jira = Mock()
        issue = self._make_issue("new")
        get_jira_instance.return_value = jira_instance
        get_jira_issue.return_value = jira_issue
        get_jira_connection.return_value = jira
        jira.issue.return_value = issue

        with (
            patch("dojo.jira.helper.is_delete_sync_allowed", return_value=True) as is_delete_sync_allowed,
            patch("dojo.jira.helper.add_simple_jira_comment", return_value=True) as add_simple_jira_comment,
        ):
            updated, message = jira_helper.close_jira_issue_for_deleted_finding(finding)

        self.assertTrue(updated)
        self.assertEqual("Jira issue DD-1 closed successfully.", message)
        is_jira_enabled.assert_called_once_with()
        is_delete_sync_allowed.assert_called_once_with(finding)
        is_jira_configured_and_enabled.assert_called_once_with(finding)
        jira.issue.assert_called_once_with("10001")
        jira_transition.assert_called_once_with(jira, issue, 41)
        add_simple_jira_comment.assert_called_once_with(
            jira_instance,
            jira_issue,
            "DefectDojo finding 1 was deleted. This Jira issue was closed automatically.",
        )
        jira_issue.save.assert_called_once_with(update_fields=["jira_change"])

    def test_close_jira_issue_for_deleted_finding_skips_when_sync_disabled(self):
        finding = Mock(id=1)
        finding.has_jira_issue = True

        with (
            patch("dojo.jira.helper.is_jira_enabled", return_value=True) as is_jira_enabled,
            patch("dojo.jira.helper.is_delete_sync_allowed", return_value=False) as is_delete_sync_allowed,
            patch("dojo.jira.helper.is_jira_configured_and_enabled") as is_jira_configured_and_enabled,
        ):
            updated, message = jira_helper.close_jira_issue_for_deleted_finding(finding)

        self.assertFalse(updated)
        self.assertEqual("Finding 1 is not configured to sync deleted findings to JIRA.", message)
        is_jira_enabled.assert_called_once_with()
        is_delete_sync_allowed.assert_called_once_with(finding)
        is_jira_configured_and_enabled.assert_not_called()

    def test_reassign_jira_issue_to_finding_moves_local_link(self):
        jira_issue = Mock()
        finding = Mock()

        jira_helper.reassign_jira_issue_to_finding(jira_issue, finding)

        self.assertEqual(finding, jira_issue.finding)
        self.assertIsNone(jira_issue.finding_group)
        self.assertIsNone(jira_issue.engagement)
        jira_issue.save.assert_called_once_with(
            update_fields=["finding", "finding_group", "engagement"],
        )

    def test_reassign_jira_issue_to_new_original_moves_local_link_and_comments(self):
        deleted_finding = Mock(id=1)
        new_original = Mock(id=2)
        new_original.has_jira_issue = False
        jira_issue = Mock()
        jira_instance = Mock()

        with (
            patch(
                "dojo.finding.helper.jira_services.is_delete_sync_allowed",
                return_value=True,
            ) as is_delete_sync_allowed,
            patch("dojo.finding.helper.jira_services.get_issue", return_value=jira_issue) as get_issue,
            patch("dojo.finding.helper.jira_services.get_instance", return_value=jira_instance) as get_instance,
            patch("dojo.finding.helper.jira_services.add_simple_comment", return_value=True) as add_simple_comment,
            patch("dojo.finding.helper.jira_services.reassign_issue_to_finding") as reassign_issue_to_finding,
        ):
            reassigned = finding_helper._reassign_jira_issue_to_new_original(deleted_finding, new_original)

        self.assertTrue(reassigned)
        is_delete_sync_allowed.assert_called_once_with(deleted_finding)
        get_issue.assert_called_once_with(deleted_finding)
        get_instance.assert_called_once_with(deleted_finding)
        add_simple_comment.assert_called_once_with(
            jira_instance,
            jira_issue,
            "DefectDojo finding 1 was deleted. This Jira issue was reassigned to finding 2.",
        )
        reassign_issue_to_finding.assert_called_once_with(jira_issue, new_original)
        self.assertTrue(deleted_finding._skip_jira_close_on_delete)

    def test_reassign_jira_issue_to_new_original_skips_when_new_original_has_jira_issue(self):
        deleted_finding = Mock(id=1)
        new_original = Mock(id=2)
        new_original.has_jira_issue = True

        with (
            patch("dojo.finding.helper.jira_services.get_issue") as get_issue,
            patch("dojo.finding.helper.jira_services.reassign_issue_to_finding") as reassign_issue_to_finding,
        ):
            reassigned = finding_helper._reassign_jira_issue_to_new_original(deleted_finding, new_original)

        self.assertFalse(reassigned)
        get_issue.assert_not_called()
        reassign_issue_to_finding.assert_not_called()

    @patch("dojo.finding.helper.delete_related_files")
    @patch("dojo.finding.helper.delete_related_notes")
    @patch("dojo.finding.helper.jira_services.close_issue_for_deleted_finding")
    def test_finding_pre_delete_closes_linked_jira_issue_before_cleanup(
        self,
        close_issue_for_deleted_finding,
        delete_related_notes,
        delete_related_files,
    ):
        finding = Mock(id=1)
        finding.has_jira_issue = True
        finding._skip_jira_close_on_delete = False

        with patch(
            "dojo.finding.helper.jira_services.is_delete_sync_allowed",
            return_value=True,
        ) as is_delete_sync_allowed:
            finding_helper.finding_pre_delete(sender=Mock(), instance=finding)

        is_delete_sync_allowed.assert_called_once_with(finding)
        close_issue_for_deleted_finding.assert_called_once_with(finding)
        finding.found_by.clear.assert_called_once_with()
        delete_related_notes.assert_called_once_with(finding)
        delete_related_files.assert_called_once_with(finding)

    @patch("dojo.finding.helper.delete_related_files")
    @patch("dojo.finding.helper.delete_related_notes")
    @patch("dojo.finding.helper.jira_services.close_issue_for_deleted_finding")
    def test_finding_pre_delete_skips_jira_close_when_sync_disabled(
        self,
        close_issue_for_deleted_finding,
        delete_related_notes,
        delete_related_files,
    ):
        finding = Mock(id=1)
        finding.has_jira_issue = True
        finding._skip_jira_close_on_delete = False

        with patch(
            "dojo.finding.helper.jira_services.is_delete_sync_allowed",
            return_value=False,
        ) as is_delete_sync_allowed:
            finding_helper.finding_pre_delete(sender=Mock(), instance=finding)

        is_delete_sync_allowed.assert_called_once_with(finding)
        close_issue_for_deleted_finding.assert_not_called()
        finding.found_by.clear.assert_called_once_with()
        delete_related_notes.assert_called_once_with(finding)
        delete_related_files.assert_called_once_with(finding)

    @patch("dojo.finding.helper.delete_related_files")
    @patch("dojo.finding.helper.delete_related_notes")
    @patch("dojo.finding.helper.jira_services.close_issue_for_deleted_finding")
    def test_finding_pre_delete_skips_jira_close_after_reassigning_issue(
        self,
        close_issue_for_deleted_finding,
        delete_related_notes,
        delete_related_files,
    ):
        finding = Mock(id=1)
        finding.has_jira_issue = True
        finding._skip_jira_close_on_delete = True

        finding_helper.finding_pre_delete(sender=Mock(), instance=finding)

        close_issue_for_deleted_finding.assert_not_called()
        finding.found_by.clear.assert_called_once_with()
        delete_related_notes.assert_called_once_with(finding)
        delete_related_files.assert_called_once_with(finding)


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
