import logging
from unittest import TestCase
from unittest.mock import Mock, patch

import dojo.finding.helper as finding_helper
import dojo.jira.helper as jira_helper
from dojo.models import Finding, JIRA_Instance, JIRA_Issue, JIRA_Project, Test_Type
from unittests.dojo_test_case import DojoTestCase

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

    @patch("dojo.jira.helper.dojo_dispatch_task")
    @patch("dojo.jira.helper.get_jira_project")
    @patch("dojo.jira.helper.get_jira_issue")
    @patch("dojo.jira.helper.is_jira_configured_and_enabled", return_value=True)
    @patch("dojo.jira.helper.is_jira_enabled", return_value=True)
    def test_close_jira_issue_for_deleted_finding_dispatches_with_durable_args(
        self,
        is_jira_enabled,
        is_jira_configured_and_enabled,
        get_jira_issue,
        get_jira_project,
        dojo_dispatch_task,
    ):
        finding = Mock(id=1)
        finding.has_jira_issue = True
        jira_issue = Mock(jira_id="10001", jira_key="DD-1")
        jira_instance = Mock(id=22)
        jira_project = Mock(jira_instance=jira_instance)
        get_jira_issue.return_value = jira_issue
        get_jira_project.return_value = jira_project

        with patch("dojo.jira.helper.is_delete_sync_allowed", return_value=True) as is_delete_sync_allowed:
            updated, message = jira_helper.close_jira_issue_for_deleted_finding(finding, push_to_jira=True)

        self.assertTrue(updated)
        self.assertEqual("Jira issue DD-1 close queued.", message)
        is_jira_enabled.assert_called_once_with()
        is_delete_sync_allowed.assert_called_once_with(finding, push_to_jira=True)
        is_jira_configured_and_enabled.assert_called_once_with(finding)
        get_jira_project.assert_called_once_with(jira_issue)
        dojo_dispatch_task.assert_called_once_with(
            jira_helper.close_deleted_finding_jira_issue,
            "10001",
            22,
            1,
        )

    def test_close_jira_issue_for_deleted_finding_skips_when_sync_disabled(self):
        finding = Mock(id=1)
        finding.has_jira_issue = True

        with (
            patch("dojo.jira.helper.is_jira_enabled", return_value=True) as is_jira_enabled,
            patch("dojo.jira.helper.is_delete_sync_allowed", return_value=False) as is_delete_sync_allowed,
            patch("dojo.jira.helper.is_jira_configured_and_enabled") as is_jira_configured_and_enabled,
        ):
            updated, message = jira_helper.close_jira_issue_for_deleted_finding(finding, push_to_jira=False)

        self.assertFalse(updated)
        self.assertEqual("Finding 1 is not configured to sync deleted findings to JIRA.", message)
        is_jira_enabled.assert_called_once_with()
        is_delete_sync_allowed.assert_called_once_with(finding, push_to_jira=False)
        is_jira_configured_and_enabled.assert_not_called()

    @patch("dojo.jira.helper.jira_transition", return_value=True)
    @patch("dojo.jira.helper.get_jira_connection")
    @patch("dojo.jira.helper.get_object_or_none")
    def test_close_deleted_finding_jira_issue_closes_active_issue(
        self,
        get_object_or_none,
        get_jira_connection,
        jira_transition,
    ):
        jira_instance = Mock(close_status_key=41)
        jira = Mock()
        issue = self._make_issue("new")
        get_object_or_none.return_value = jira_instance
        get_jira_connection.return_value = jira
        jira.issue.return_value = issue

        updated, message = jira_helper.close_deleted_finding_jira_issue("10001", 22, 1)

        self.assertTrue(updated)
        self.assertEqual("Jira issue 10001 closed successfully.", message)
        get_object_or_none.assert_called_once_with(JIRA_Instance, id=22)
        jira.issue.assert_called_once_with("10001")
        jira_transition.assert_called_once_with(jira, issue, 41)
        jira.add_comment.assert_called_once_with(
            "10001",
            "DefectDojo finding 1 was deleted. This Jira issue was closed automatically.",
        )

    def test_is_delete_sync_allowed_honors_explicit_false(self):
        finding = Mock()

        with (
            patch("dojo.jira.helper.is_push_to_jira", return_value=False) as is_push_to_jira,
            patch("dojo.jira.helper.is_keep_in_sync_with_jira") as is_keep_in_sync_with_jira,
            patch("dojo.jira.helper.is_push_all_issues") as is_push_all_issues,
        ):
            allowed = jira_helper.is_delete_sync_allowed(finding, push_to_jira=False)

        self.assertFalse(allowed)
        is_push_to_jira.assert_called_once_with(finding, push_to_jira_parameter=False)
        is_keep_in_sync_with_jira.assert_not_called()
        is_push_all_issues.assert_not_called()

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
        jira_issue = Mock(jira_id="10001")
        jira_instance = Mock(id=22)

        with (
            patch(
                "dojo.finding.helper.jira_services.is_delete_sync_allowed",
                return_value=True,
            ) as is_delete_sync_allowed,
            patch("dojo.finding.helper.jira_services.get_issue", return_value=jira_issue) as get_issue,
            patch("dojo.finding.helper.jira_services.get_instance", return_value=jira_instance) as get_instance,
            patch("dojo.finding.helper.jira_services.add_simple_comment_async", return_value=True) as add_simple_comment_async,
            patch("dojo.finding.helper.jira_services.reassign_issue_to_finding") as reassign_issue_to_finding,
        ):
            reassigned = finding_helper._reassign_jira_issue_to_new_original(
                deleted_finding,
                new_original,
                push_to_jira=True,
            )

        self.assertTrue(reassigned)
        is_delete_sync_allowed.assert_called_once_with(deleted_finding, push_to_jira=True)
        get_issue.assert_called_once_with(deleted_finding)
        get_instance.assert_called_once_with(deleted_finding)
        reassign_issue_to_finding.assert_called_once_with(jira_issue, new_original)
        add_simple_comment_async.assert_called_once_with(
            "10001",
            22,
            "DefectDojo finding 1 was deleted. This Jira issue was reassigned to finding 2.",
        )

    def test_reassign_jira_issue_to_new_original_skips_when_sync_disabled(self):
        deleted_finding = Mock(id=1)
        new_original = Mock(id=2)
        new_original.has_jira_issue = False

        with (
            patch("dojo.finding.helper.jira_services.is_delete_sync_allowed", return_value=False) as is_delete_sync_allowed,
            patch("dojo.finding.helper.jira_services.get_issue") as get_issue,
        ):
            reassigned = finding_helper._reassign_jira_issue_to_new_original(
                deleted_finding,
                new_original,
                push_to_jira=False,
            )

        self.assertFalse(reassigned)
        is_delete_sync_allowed.assert_called_once_with(deleted_finding, push_to_jira=False)
        get_issue.assert_not_called()

    def test_reassign_jira_issue_to_new_original_skips_when_new_original_has_jira_issue(self):
        deleted_finding = Mock(id=1)
        new_original = Mock(id=2)
        new_original.has_jira_issue = True

        with (
            patch("dojo.finding.helper.jira_services.get_issue") as get_issue,
            patch("dojo.finding.helper.jira_services.reassign_issue_to_finding") as reassign_issue_to_finding,
        ):
            reassigned = finding_helper._reassign_jira_issue_to_new_original(
                deleted_finding,
                new_original,
                push_to_jira=True,
            )

        self.assertFalse(reassigned)
        get_issue.assert_not_called()
        reassign_issue_to_finding.assert_not_called()

    @patch("dojo.finding.helper.delete_related_files")
    @patch("dojo.finding.helper.delete_related_notes")
    @patch("dojo.finding.helper.jira_services.close_issue_for_deleted_finding")
    def test_finding_pre_delete_only_cleans_related_data(
        self,
        close_issue_for_deleted_finding,
        delete_related_notes,
        delete_related_files,
    ):
        finding = Mock(id=1)
        finding.has_jira_issue = True

        finding_helper.finding_pre_delete(sender=Mock(), instance=finding)

        close_issue_for_deleted_finding.assert_not_called()
        finding.found_by.clear.assert_called_once_with()
        delete_related_notes.assert_called_once_with(finding)
        delete_related_files.assert_called_once_with(finding)


class JIRADeleteCascadeTest(DojoTestCase):
    def _make_issue(self, status_category_key):
        issue = Mock()
        issue.fields.status.statusCategory.key = status_category_key
        return issue

    def _make_synced_finding(self):
        self.system_settings(enable_jira=True)
        product_type = self.create_product_type("JIRA delete cascade")
        product = self.create_product("JIRA delete cascade product", prod_type=product_type)
        engagement = self.create_engagement("JIRA delete cascade engagement", product)
        test_type = Test_Type.objects.create(name="JIRA Delete Cascade Scan")
        test = self.create_test(
            engagement=engagement,
            scan_type=test_type.name,
            title="JIRA delete cascade test",
        )
        finding = Finding.objects.create(
            test=test,
            title="JIRA synced finding",
            severity="High",
        )
        jira_instance = JIRA_Instance.objects.create(
            configuration_name="JIRA delete cascade instance",
            url="https://jira.example.com",
            username="jira",
            password="jira",  # noqa: S106 - test fixture credential
            epic_name_id=1,
            open_status_key=2,
            close_status_key=3,
            info_mapping_severity="Info",
            low_mapping_severity="Low",
            medium_mapping_severity="Medium",
            high_mapping_severity="High",
            critical_mapping_severity="Critical",
            finding_jira_sync=True,
        )
        jira_project = JIRA_Project.objects.create(
            jira_instance=jira_instance,
            project_key="DD",
            product=product,
            push_all_issues=True,
            enabled=True,
        )
        JIRA_Issue.objects.create(
            jira_project=jira_project,
            jira_id="10001",
            jira_key="DD-1",
            finding=finding,
        )
        return engagement, test, finding

    @patch("dojo.finding.helper.jira_services.close_issue_for_deleted_finding")
    def test_deleting_test_with_synced_finding_does_not_close_jira_issue(self, close_issue_for_deleted_finding):
        _engagement, test, _finding = self._make_synced_finding()

        test.delete()

        close_issue_for_deleted_finding.assert_not_called()

    @patch("dojo.finding.helper.jira_services.close_issue_for_deleted_finding")
    def test_deleting_engagement_with_synced_finding_does_not_close_jira_issue(self, close_issue_for_deleted_finding):
        engagement, _test, _finding = self._make_synced_finding()

        engagement.delete()

        close_issue_for_deleted_finding.assert_not_called()

    @patch("dojo.finding.helper.jira_services.close_issue_for_deleted_finding")
    def test_deleting_finding_without_push_to_jira_does_not_close_jira_issue(self, close_issue_for_deleted_finding):
        _engagement, _test, finding = self._make_synced_finding()

        finding.delete(product_grading_option=False)

        close_issue_for_deleted_finding.assert_not_called()

    @patch("dojo.jira.helper.jira_transition", return_value=True)
    @patch("dojo.jira.helper.get_jira_connection")
    def test_deleting_finding_with_push_to_jira_closes_linked_jira_issue(
        self,
        get_jira_connection,
        jira_transition,
    ):
        _engagement, _test, finding = self._make_synced_finding()
        jira = Mock()
        issue = self._make_issue("new")
        get_jira_connection.return_value = jira
        jira.issue.return_value = issue
        finding_id = finding.id

        with patch("dojo.decorators.we_want_async", return_value=False):
            finding.delete(push_to_jira=True, product_grading_option=False)

        jira.issue.assert_called_once_with("10001")
        jira_transition.assert_called_once()
        jira.add_comment.assert_called_once_with(
            "10001",
            f"DefectDojo finding {finding_id} was deleted. This Jira issue was closed automatically.",
        )
        self.assertFalse(JIRA_Issue.objects.filter(jira_id="10001").exists())


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
