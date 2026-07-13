import logging
from unittest import TestCase
from unittest.mock import Mock, patch

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
