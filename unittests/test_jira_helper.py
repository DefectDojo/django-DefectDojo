import logging
from unittest import TestCase
from unittest.mock import Mock, patch

from celery.result import AsyncResult
from django.core.cache import cache
from django.test import override_settings
from jira.exceptions import JIRAError

import dojo.finding.helper as finding_helper
import dojo.jira.helper as jira_helper
from dojo.jira import services as jira_services
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


class JIRAEpicFormAsyncDispatchTest(TestCase):

    """
    Regression: saving an engagement with epic mapping enabled raised
    "TypeError: cannot unpack non-iterable AsyncResult object" from
    process_jira_epic_form.

    push_to_jira returns whatever dojo_dispatch_task returns: the task's
    (success, message) tuple when it runs in the foreground, but a Celery
    AsyncResult when it is dispatched to a worker. process_jira_epic_form
    unpacked the return value into two names unconditionally, so it only
    worked on the foreground path -- which is why every existing test for
    this view sets block_execution=True and never saw the failure.
    """

    def _form(self, *, push=True, epic_name=None, epic_priority=None):
        form = Mock()
        form.is_valid.return_value = True
        form.cleaned_data = {
            "push_to_jira": push,
            "epic_name": epic_name,
            "epic_priority": epic_priority,
        }
        return form

    def _run(self, push_return):
        """Drive process_jira_epic_form with push_to_jira returning push_return."""
        form = self._form()
        engagement = Mock(id=1, name="engagement")
        with (
            patch("dojo.jira.helper.get_system_setting", return_value=True),
            patch("dojo.jira.helper.JIRAEngagementForm", return_value=form),
            patch("dojo.jira.helper.get_jira_project", return_value=Mock()),
            patch("dojo.jira.helper.messages") as messages,
            patch("dojo.jira.helper.push_to_jira", return_value=push_return) as push,
        ):
            success, returned_form = jira_helper.process_jira_epic_form(
                Mock(POST={}), engagement=engagement,
            )
        return success, returned_form, push, messages

    def test_async_dispatch_returns_success_without_unpacking(self):
        """The async path hands back an AsyncResult, which must not be unpacked."""
        async_result = AsyncResult("11111111-2222-3333-4444-555555555555")

        success, returned_form, push, messages = self._run(async_result)

        self.assertTrue(
            success,
            msg=f"expected queued push to report success, got success={success}",
        )
        self.assertIsNotNone(returned_form)
        push.assert_called_once()
        _args, kwargs = messages.add_message.call_args
        self.assertEqual("alert-success", kwargs["extra_tags"])

    def test_sync_dispatch_success_tuple_is_still_honoured(self):
        """Control: the foreground path returns (True, message) and still succeeds."""
        success, returned_form, push, messages = self._run((True, "pushed"))

        self.assertTrue(
            success,
            msg=f"expected foreground success tuple to report success, got success={success}",
        )
        self.assertIsNotNone(returned_form)
        push.assert_called_once()
        _args, kwargs = messages.add_message.call_args
        self.assertEqual("alert-success", kwargs["extra_tags"])

    def test_sync_dispatch_failure_tuple_still_surfaces_the_message(self):
        """Control: a foreground failure must keep reporting the task's message."""
        success, _returned_form, _push, messages = self._run((False, "jira exploded"))

        self.assertFalse(
            success,
            msg=f"expected foreground failure tuple to report failure, got success={success}",
        )
        args, kwargs = messages.add_message.call_args
        self.assertIn("jira exploded", args)
        self.assertEqual("alert-danger", kwargs["extra_tags"])


class JIRAPushResultInterpretationTest(TestCase):

    """
    Regression: callers tested a push_to_jira return value for truthiness to
    decide whether the push worked. Both possible shapes -- a populated
    (success, message) tuple and an AsyncResult -- are truthy, so a failed push
    was reported to the user as a successful one and the failure branch was
    unreachable.
    """

    def test_queued_push_is_success_with_no_message(self):
        result = AsyncResult("11111111-2222-3333-4444-555555555555")
        self.assertEqual((True, None), jira_helper.interpret_push_result(result))

    def test_foreground_success_tuple_passes_through(self):
        self.assertEqual((True, "ok"), jira_helper.interpret_push_result((True, "ok")))

    def test_foreground_failure_tuple_reports_failure(self):
        success, message = jira_helper.interpret_push_result((False, "jira exploded"))
        self.assertFalse(
            success,
            msg=f"a (False, message) tuple must report failure, got success={success}",
        )
        self.assertEqual("jira exploded", message)

    def test_push_succeeded_rejects_a_failure_tuple(self):
        """The truthiness trap: bool((False, 'msg')) is True, push_succeeded must not be."""
        self.assertTrue(bool((False, "jira exploded")))
        self.assertFalse(jira_services.push_succeeded((False, "jira exploded")))

    def test_push_succeeded_accepts_a_queued_push(self):
        result = AsyncResult("11111111-2222-3333-4444-555555555555")
        self.assertTrue(jira_services.push_succeeded(result))


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


class JIRATransitionFieldsTest(TestCase):

    """
    SC-13320: some JIRA workflows require fields (e.g. a resolution or a
    justification custom field) to be present on the close/reopen transition
    screen, otherwise JIRA rejects the transition. The JIRA_Project
    close_transition_fields / reopen_transition_fields JSON is sent as the
    `fields` payload of the transition call.
    """

    CLOSE_FIELDS = {"resolution": {"name": "Won't Fix"}, "customfield_10200": "no repro #report-false-positive"}
    REOPEN_FIELDS = {"customfield_10201": "reopened by DefectDojo"}

    def _make_issue(self, status_category_key):
        issue = Mock()
        issue.fields.status.statusCategory.key = status_category_key
        return issue

    def test_jira_transition_without_fields_uses_legacy_call(self):
        jira = Mock()
        issue = Mock()

        self.assertTrue(jira_helper.jira_transition(jira, issue, 41))

        jira.transition_issue.assert_called_once_with(issue, 41)

    def test_jira_transition_with_empty_fields_uses_legacy_call(self):
        jira = Mock()
        issue = Mock()

        self.assertTrue(jira_helper.jira_transition(jira, issue, 41, fields={}))

        jira.transition_issue.assert_called_once_with(issue, 41)

    def test_jira_transition_with_fields_passes_fields(self):
        jira = Mock()
        issue = Mock()

        self.assertTrue(jira_helper.jira_transition(jira, issue, 41, fields=self.CLOSE_FIELDS))

        jira.transition_issue.assert_called_once_with(issue, 41, fields=self.CLOSE_FIELDS)

    @patch("dojo.jira.helper.jira_transition", return_value=True)
    @patch("dojo.jira.helper._safely_get_obj_status_for_jira", return_value=["Mitigated"])
    def test_push_status_to_jira_close_sends_close_transition_fields(self, status_mock, jira_transition):
        jira_instance = Mock(close_status_key=41, open_status_key=42)
        jira = Mock()
        issue = self._make_issue("new")
        obj = Mock(id=1)
        jira_project = Mock(close_transition_fields=self.CLOSE_FIELDS, reopen_transition_fields=None)

        updated = jira_helper.push_status_to_jira(obj, jira_instance, jira, issue, jira_project=jira_project)

        self.assertTrue(updated)
        jira_transition.assert_called_once_with(jira, issue, 41, fields=self.CLOSE_FIELDS)

    @patch("dojo.jira.helper.jira_transition", return_value=True)
    @patch("dojo.jira.helper._safely_get_obj_status_for_jira", return_value=["Active"])
    def test_push_status_to_jira_reopen_sends_reopen_transition_fields(self, status_mock, jira_transition):
        jira_instance = Mock(close_status_key=41, open_status_key=42)
        jira = Mock()
        issue = self._make_issue("done")
        obj = Mock(id=1)
        jira_project = Mock(close_transition_fields=None, reopen_transition_fields=self.REOPEN_FIELDS)

        updated = jira_helper.push_status_to_jira(obj, jira_instance, jira, issue, jira_project=jira_project)

        self.assertTrue(updated)
        jira_transition.assert_called_once_with(jira, issue, 42, fields=self.REOPEN_FIELDS)

    @patch("dojo.jira.helper.jira_transition", return_value=True)
    @patch("dojo.jira.helper._safely_get_obj_status_for_jira", return_value=["Mitigated"])
    @patch("dojo.jira.helper.get_jira_project", return_value=None)
    def test_push_status_to_jira_resolves_project_and_tolerates_none(self, get_jira_project, status_mock, jira_transition):
        jira_instance = Mock(close_status_key=41, open_status_key=42)
        jira = Mock()
        issue = self._make_issue("new")
        obj = Mock(id=1)

        updated = jira_helper.push_status_to_jira(obj, jira_instance, jira, issue)

        self.assertTrue(updated)
        get_jira_project.assert_called_once_with(obj)
        jira_transition.assert_called_once_with(jira, issue, 41, fields=None)

    @patch("dojo.jira.helper.requests.post")
    @patch("dojo.jira.helper.get_jira_issue")
    @patch("dojo.jira.helper.get_jira_instance")
    @patch("dojo.jira.helper.get_jira_project")
    @patch("dojo.jira.helper.is_jira_configured_and_enabled", return_value=True)
    @patch("dojo.jira.helper.is_jira_enabled", return_value=True)
    @patch("dojo.jira.helper.get_object_or_none")
    def test_close_epic_includes_close_transition_fields(
        self,
        get_object_or_none,
        is_jira_enabled,
        is_jira_configured_and_enabled,
        get_jira_project,
        get_jira_instance,
        get_jira_issue,
        requests_post,
    ):
        get_object_or_none.return_value = Mock(id=5)
        get_jira_project.return_value = Mock(
            enable_engagement_epic_mapping=True,
            close_transition_fields=self.CLOSE_FIELDS,
        )
        get_jira_instance.return_value = Mock(
            url="https://jira.example.com",
            username="user",
            password="pass",  # noqa: S106 - test fixture credential
            close_status_key=41,
        )
        get_jira_issue.return_value = Mock(jira_id="10001")
        requests_post.return_value = Mock(status_code=204)

        self.assertTrue(jira_helper.close_epic(5, push_to_jira=True))

        _args, kwargs = requests_post.call_args
        self.assertEqual({"transition": {"id": 41}, "fields": self.CLOSE_FIELDS}, kwargs["json"])

    @patch("dojo.jira.helper.requests.post")
    @patch("dojo.jira.helper.get_jira_issue")
    @patch("dojo.jira.helper.get_jira_instance")
    @patch("dojo.jira.helper.get_jira_project")
    @patch("dojo.jira.helper.is_jira_configured_and_enabled", return_value=True)
    @patch("dojo.jira.helper.is_jira_enabled", return_value=True)
    @patch("dojo.jira.helper.get_object_or_none")
    def test_close_epic_omits_fields_when_not_configured(
        self,
        get_object_or_none,
        is_jira_enabled,
        is_jira_configured_and_enabled,
        get_jira_project,
        get_jira_instance,
        get_jira_issue,
        requests_post,
    ):
        get_object_or_none.return_value = Mock(id=5)
        get_jira_project.return_value = Mock(
            enable_engagement_epic_mapping=True,
            close_transition_fields=None,
        )
        get_jira_instance.return_value = Mock(
            url="https://jira.example.com",
            username="user",
            password="pass",  # noqa: S106 - test fixture credential
            close_status_key=41,
        )
        get_jira_issue.return_value = Mock(jira_id="10001")
        requests_post.return_value = Mock(status_code=204)

        self.assertTrue(jira_helper.close_epic(5, push_to_jira=True))

        _args, kwargs = requests_post.call_args
        self.assertEqual({"transition": {"id": 41}}, kwargs["json"])


class JIRAConfigFailureBreakerTest(TestCase):

    """
    A misconfigured Jira project (renamed key, revoked Create Issue permission, issue type
    dropped from the scheme) fails identically for every object in an import. The remembered
    failure lets the rest of the batch fail fast instead of repeating the same doomed metadata
    call, error log and notification hundreds of times.
    """

    def setUp(self):
        cache.clear()
        self.jira_instance = Mock(id=7, default_issue_type="Task")

    def tearDown(self):
        cache.clear()

    def _note(self, exception, message="broken"):
        jira_helper.note_jira_config_failure(self.jira_instance, "DS", "Task", exception, message)

    def _get(self):
        return jira_helper.get_jira_config_failure(self.jira_instance, "DS", "Task")

    def test_status_none_failure_is_remembered(self):
        """A status of None is what DefectDojo raises when Jira returns no matching project."""
        self._note(JIRAError("Project misconfigured or no permissions in Jira ?"), "no project DS")
        self.assertEqual("no project DS", self._get())

    def test_permission_and_not_found_failures_are_remembered(self):
        for status_code in (400, 401, 403, 404):
            with self.subTest(status_code=status_code):
                cache.clear()
                self._note(JIRAError("nope", status_code=status_code))
                self.assertEqual("broken", self._get())

    def test_transient_failure_is_not_remembered(self):
        """A Jira-side 5xx or a timeout may well succeed for the next object, so do not skip it."""
        self._note(JIRAError("server error", status_code=500))
        self.assertIsNone(self._get())

    def test_failure_is_scoped_to_project_and_issue_type(self):
        self._note(JIRAError("no project"), "only DS/Task")
        self.assertIsNone(jira_helper.get_jira_config_failure(self.jira_instance, "OTHER", "Task"))
        self.assertIsNone(jira_helper.get_jira_config_failure(self.jira_instance, "DS", "Bug"))
        self.assertIsNone(jira_helper.get_jira_config_failure(Mock(id=8), "DS", "Task"))

    def test_clear_forgets_the_failure(self):
        self._note(JIRAError("no project"))
        jira_helper.clear_jira_config_failure(self.jira_instance, "DS", "Task")
        self.assertIsNone(self._get())

    @override_settings(JIRA_CONFIG_FAILURE_CACHE_TTL=0)
    def test_ttl_of_zero_disables_the_behavior(self):
        self._note(JIRAError("no project"))
        self.assertIsNone(self._get())

    @patch("dojo.jira.helper.get_jira_connection")
    @patch("dojo.jira.helper.log_jira_alert")
    @patch("dojo.jira.helper.get_jira_instance")
    @patch("dojo.jira.helper.get_jira_project")
    @patch("dojo.jira.helper.is_jira_configured_and_enabled", return_value=True)
    @patch("dojo.jira.helper.is_jira_enabled", return_value=True)
    def test_add_jira_issue_skips_without_calling_jira_or_notifying(
        self,
        is_jira_enabled,
        is_jira_configured_and_enabled,
        get_jira_project,
        get_jira_instance,
        log_jira_alert,
        get_jira_connection,
    ):
        get_jira_project.return_value = Mock(project_key="DS")
        get_jira_instance.return_value = self.jira_instance
        self._note(JIRAError("no project DS"), "remembered: no project DS")

        success, message = jira_helper.add_jira_issue(Mock(id=42))

        self.assertFalse(success)
        self.assertEqual("remembered: no project DS", message)
        get_jira_connection.assert_not_called()
        log_jira_alert.assert_not_called()
