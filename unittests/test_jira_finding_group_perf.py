"""Query-count regression test for pushing a finding group to JIRA.

Regression: DJANGO-42P8 — push_finding_group_to_jira loaded the group without
prefetching its findings, so the downstream JIRA helpers (jira_description,
jira_priority, get_sla_deadline, get_labels, get_tags, ...) each re-ran
``finding_group.findings.all()``, producing an N+1 on dojo_finding_group_findings.
"""
from unittest.mock import patch

from django.test import TestCase

from dojo.models import Dojo_User, Finding, Finding_Group, Test


class JiraFindingGroupPushQueryCountTest(TestCase):
    fixtures = ["dojo_testdata.json"]

    def _make_group(self, num_findings: int) -> Finding_Group:
        test = Test.objects.first()
        admin = Dojo_User.objects.get(username="admin")
        group = Finding_Group.objects.create(test=test, name="perf group", creator=admin)
        group.findings.add(*list(Finding.objects.all()[:num_findings]))
        return group

    @patch("dojo.jira.helper.add_jira_issue")
    @patch("dojo.jira.helper.update_jira_issue")
    def test_group_findings_prefetched_before_jira_helpers(self, mock_update, mock_add):  # noqa: ARG002
        """The group handed to the JIRA helpers must have its findings prefetched.

        The real helpers read ``finding_group.findings.all()`` several times; if the
        group is prefetched those reads hit the cache (0 queries). Without the fix
        each read is a fresh dojo_finding_group_findings query (N+1).
        """
        from dojo.jira.helper import push_finding_group_to_jira

        group = self._make_group(5)

        def _simulate_jira_helpers(obj, *args, **kwargs):  # noqa: ARG001
            with self.assertNumQueries(0):
                for _ in range(5):
                    list(obj.findings.all())
            return "ok", True

        mock_add.side_effect = _simulate_jira_helpers
        push_finding_group_to_jira(group.id)
        mock_add.assert_called_once()
