"""
JIRA push flow tests for API v3 (§10 backlog #2 -- JIRA push intent ported from
``unittests/test_jira_import_and_pushing_api.py``).

The v2 corpus is a VCR/cassette suite (``DojoVCRAPITestCase``) that records *real* JIRA HTTP
traffic and is deeply entangled with v2-only surfaces the v3 alpha deliberately lacks -- finding
**groups** (``group_by``), **epics**, **webhooks**, and the UI ``/finding/bulk`` flow. A dual-endpoint
shim over it is not economical (most scenarios pin those absent surfaces, and the cassettes are keyed
to the v2 request sequence). So per the §10 directive these are targeted v3 ports of the *key flows*,
mocking JIRA at the same layer the existing v3 tests do:

* import path -> ``dojo.jira.services.push`` (what ``default_importer`` and
  ``finding.helper.post_process_findings_batch`` both call -- see the coverage map in the debrief);
* finding write path -> ``dojo.finding.services.jira_services.push`` (as in
  ``test_apiv3_finding_writes.py``).

Never contacts a real JIRA. ``block_execution=True`` forces the importer's async post-processing to
run in-process so the push is observable within the request (mirrors the v2 corpus ``setUp``).

Coverage map (corpus scenario -> here / skip+reason) is in the module-level docstring of the debrief
and API_V3_PLAN.md §12.
"""
from __future__ import annotations

from unittest.mock import patch

from dojo.models import Finding, JIRA_Instance, JIRA_Project, UserContactInfo
from unittests.dojo_test_case import get_unit_tests_scans_path

from .base import ApiV3TestCase

# Import path: default_importer (grouped) and finding.helper post-processing (ungrouped) both call
# ``jira_services.push`` == this attribute; patching it catches every import-time push.
_IMPORT_PUSH = "dojo.jira.services.push"
# Finding write path: the service reference the v3 finding-write tests already patch.
_SVC_PUSH = "dojo.finding.services.jira_services.push"
_SVC_KEEP_IN_SYNC = "dojo.finding.services.jira_services.is_keep_in_sync"

_ZAP = "ZAP Scan"
_SCAN = "0_zap_sample.xml"


class _JiraV3Base(ApiV3TestCase):

    def setUp(self):
        super().setUp()
        self.system_settings(enable_jira=True)
        # Force async post-processing (jira push, grading, dedup) to run in-process so the push is
        # observable within the import request -- mirrors the v2 corpus setUp.
        UserContactInfo.objects.update_or_create(user=self.admin, defaults={"block_execution": True})

    def _scan_file(self):
        return (get_unit_tests_scans_path("zap") / _SCAN).open(encoding="utf-8")

    def _import(self, *, engagement: int = 1, expected: int = 200, **extra) -> dict:
        with self._scan_file() as scan:
            payload = {"scan_type": _ZAP, "mode": "import", "engagement": engagement, "file": scan,
                       "active": "true", "verified": "true", **extra}
            response = self.client.post(self.v3_url("import"), payload, format="multipart")
        self.assertEqual(expected, response.status_code, response.content[:1000])
        return response.json()

    def _reimport(self, test_id: int, *, expected: int = 200, **extra) -> dict:
        with self._scan_file() as scan:
            payload = {"scan_type": _ZAP, "mode": "reimport", "test": test_id, "file": scan,
                       "active": "true", "verified": "true", **extra}
            response = self.client.post(self.v3_url("import"), payload, format="multipart")
        self.assertEqual(expected, response.status_code, response.content[:1000])
        return response.json()

    @staticmethod
    def _pushed_finding_ids(mock_push) -> set[int]:
        return {call.args[0].id for call in mock_push.call_args_list if isinstance(call.args[0], Finding)}

    @staticmethod
    def _test_finding_ids(test_id: int) -> set[int]:
        return set(Finding.objects.filter(test_id=test_id).values_list("id", flat=True))


class TestApiV3ImportJiraPush(_JiraV3Base):

    """Import/reimport push behaviour (corpus: ``test_import_*`` non-group scenarios)."""

    def setUp(self):
        super().setUp()
        # Keep every parsed finding (no dedup collapse) so "each finding is pushed" is exact.
        self.system_settings(enable_deduplication=False)

    def test_import_with_push_to_jira_pushes_each_finding(self):
        # Corpus: test_import_with_push_to_jira. Engagement 1 -> product 2 has an enabled JIRA project.
        with patch(_IMPORT_PUSH, return_value=(True, "ok")) as push:
            body = self._import(push_to_jira="true")
        test_id = body["test"]["id"]
        self.assertTrue(push.called, "push_to_jira=true must push")
        # Each finding in the new test is pushed exactly to the JIRA layer (set-equality is robust to
        # any double-dispatch and to call ordering).
        self.assertEqual(self._test_finding_ids(test_id), self._pushed_finding_ids(push))
        self.assertGreater(len(self._test_finding_ids(test_id)), 0)

    def test_import_without_push_to_jira_does_not_push(self):
        # Corpus: test_import_no_push_to_jira / test_import_with_push_to_jira_is_false.
        with patch(_IMPORT_PUSH, return_value=(True, "ok")) as push:
            self._import()  # push_to_jira omitted -> defaults False
        push.assert_not_called()

    def test_import_push_to_jira_false_does_not_push(self):
        with patch(_IMPORT_PUSH, return_value=(True, "ok")) as push:
            self._import(push_to_jira="false")
        push.assert_not_called()

    def test_import_push_all_issues_forces_push(self):
        # Corpus: test_import_no_push_to_jira_but_push_all. push_all_issues on the JIRA project forces
        # the push even though the request omits push_to_jira (the importer OR-s it via is_keep_in_sync).
        JIRA_Project.objects.filter(product__engagement__id=1).update(push_all_issues=True)
        with patch(_IMPORT_PUSH, return_value=(True, "ok")) as push:
            body = self._import()  # no push_to_jira
        test_id = body["test"]["id"]
        self.assertTrue(push.called, "push_all_issues must force pushing on import")
        self.assertEqual(self._test_finding_ids(test_id), self._pushed_finding_ids(push))

    def test_reimport_with_push_to_jira_pushes(self):
        # Corpus: test_import_no_push_to_jira_reimport_with_push_to_jira.
        with patch(_IMPORT_PUSH, return_value=(True, "ok")) as push:
            body = self._import()  # import without push
        push.assert_not_called()
        test_id = body["test"]["id"]
        with patch(_IMPORT_PUSH, return_value=(True, "ok")) as push:
            self._reimport(test_id, push_to_jira="true")
        self.assertTrue(push.called, "reimport push_to_jira=true must push")

    def test_reimport_without_push_to_jira_does_not_push(self):
        # Corpus: test_import_no_push_to_jira_reimport_no_push_to_jira.
        with patch(_IMPORT_PUSH, return_value=(True, "ok")):
            body = self._import()
        test_id = body["test"]["id"]
        with patch(_IMPORT_PUSH, return_value=(True, "ok")) as push:
            self._reimport(test_id, push_to_jira="false")
        push.assert_not_called()

    def test_import_jira_push_failure_does_not_fail_import(self):
        # Divergence from finding PATCH/PUT (which surface push failures as 400): the import path is
        # fire-and-forget for JIRA -- a failed push is logged, not raised, so the import still returns
        # 200 (mirrors v2, where the importer does not propagate JIRA errors). Documented in §12.
        with patch(_IMPORT_PUSH, return_value=(False, "jira exploded")) as push:
            body = self._import(push_to_jira="true", expected=200)
        self.assertTrue(push.called)
        self.assertIn("test", body)


class TestApiV3FindingWriteJiraProjectSetting(_JiraV3Base):

    """
    Finding PATCH/PUT push semantics vs the JIRA project setting -- the route OR-s the request's
    ``push_to_jira`` with ``jira_project.push_all_issues`` (routes.py). The keep-in-sync /
    push-failure-as-400 / explicit-push cases already live in ``test_apiv3_finding_writes.py``;
    this class adds ONLY the ``push_all_issues`` OR-ing gap.
    """

    def setUp(self):
        super().setUp()
        # A finding whose product has an enabled JIRA project so ``jira_services.get_project`` in the
        # route resolves it (engagement 1 -> product 2 -> project pk=2, product-level).
        self.finding = Finding.objects.filter(test__engagement__id=1, risk_accepted=False).first()
        self.assertIsNotNone(self.finding, "fixture must have a finding under engagement 1")
        project = JIRA_Project.objects.filter(product=self.finding.test.engagement.product).first()
        if project is None:
            project = JIRA_Project.objects.create(
                product=self.finding.test.engagement.product,
                jira_instance=JIRA_Instance.objects.first(), project_key="TEST",
            )
        self.project = project

    def test_patch_push_all_issues_forces_push(self):
        self.project.push_all_issues = True
        self.project.enabled = True
        self.project.save()
        with patch(_SVC_KEEP_IN_SYNC, return_value=False), patch(_SVC_PUSH, return_value=(True, "ok")) as push:
            response = self.client.patch(
                self.v3_url(f"findings/{self.finding.id}"), {"severity": "Low"}, format="json",
            )
        self.assertEqual(200, response.status_code, response.content[:500])
        push.assert_called_once()  # push_all_issues OR-ed in by the route despite no push_to_jira
        self.assertTrue(push.call_args.kwargs.get("force_sync"))

    def test_patch_no_push_when_project_not_push_all(self):
        self.project.push_all_issues = False
        self.project.enabled = True
        self.project.save()
        with patch(_SVC_KEEP_IN_SYNC, return_value=False), patch(_SVC_PUSH, return_value=(True, "ok")) as push:
            response = self.client.patch(
                self.v3_url(f"findings/{self.finding.id}"), {"severity": "Low"}, format="json",
            )
        self.assertEqual(200, response.status_code, response.content[:500])
        push.assert_not_called()

    def test_put_push_all_issues_forces_push(self):
        self.project.push_all_issues = True
        self.project.enabled = True
        self.project.save()
        payload = {
            "title": self.finding.title, "severity": "High", "description": "put replace",
            "active": True, "verified": False,
        }
        with patch(_SVC_KEEP_IN_SYNC, return_value=False), patch(_SVC_PUSH, return_value=(True, "ok")) as push:
            response = self.client.put(self.v3_url(f"findings/{self.finding.id}"), payload, format="json")
        self.assertEqual(200, response.status_code, response.content[:500])
        push.assert_called_once()
        self.assertTrue(push.call_args.kwargs.get("force_sync"))
