"""
Finding write-path tests for API v3 (OS3b, PART 2/3).

Exercises the ``dojo/finding/services.py`` extraction (D7) via the v3 routes: create/update/delete
happy paths, side-effect assertions with JIRA **mocked** (the service imports ``jira_services`` as
``dojo.finding.services.jira_services`` -- patched here), vulnerability-id persistence incl. the
``cve`` mirror field, CWE handling, the mitigated-edit rules in both ``EDITABLE_MITIGATED_DATA``
states, risk-acceptance invariants, and RBAC (404 unauthorized, 403 not-modifiable).
"""
from __future__ import annotations

from unittest.mock import patch

from django.test import override_settings

from dojo.models import Dojo_User, Finding, Finding_CWE, Test, User, Vulnerability_Id

from .base import ApiV3TestCase

_PUSH = "dojo.finding.services.jira_services.push"
_KEEP_IN_SYNC = "dojo.finding.services.jira_services.is_keep_in_sync"


def _finding_payload(test_id: int, **overrides) -> dict:
    payload = {
        "test": test_id,
        "title": "v3 write finding",
        "severity": "High",
        "description": "created via api v3",
        "active": True,
        "verified": False,
    }
    payload.update(overrides)
    return payload


class TestApiV3FindingCreate(ApiV3TestCase):

    def setUp(self):
        super().setUp()
        self.test = Test.objects.first()

    def test_create_happy_path(self):
        response = self.client.post(self.v3_url("findings"), _finding_payload(self.test.id), format="json")
        self.assertEqual(201, response.status_code, response.content[:500])
        body = response.json()
        self.assertEqual("V3 Write Finding", body["title"])  # title-cased on save
        self.assertEqual(self.test.id, body["test"]["id"])
        created = Finding.objects.get(pk=body["id"])
        self.assertEqual(self.admin, created.reporter)  # reporter defaults to the request user

    def test_create_persists_vulnerability_ids_and_cve(self):
        payload = _finding_payload(self.test.id, vulnerability_ids=["CVE-2020-1234", "CVE-2020-5678"])
        response = self.client.post(self.v3_url("findings"), payload, format="json")
        self.assertEqual(201, response.status_code, response.content[:500])
        created = Finding.objects.get(pk=response.json()["id"])
        vids = set(Vulnerability_Id.objects.filter(finding=created).values_list("vulnerability_id", flat=True))
        self.assertEqual({"CVE-2020-1234", "CVE-2020-5678"}, vids)
        self.assertEqual("CVE-2020-1234", created.cve)  # first vuln id mirrored into cve

    def test_create_persists_cwe_row(self):
        response = self.client.post(self.v3_url("findings"), _finding_payload(self.test.id, cwe=79), format="json")
        self.assertEqual(201, response.status_code, response.content[:500])
        created = Finding.objects.get(pk=response.json()["id"])
        self.assertEqual(79, created.cwe)
        self.assertTrue(Finding_CWE.objects.filter(finding=created, cwe="CWE-79").exists())

    def test_create_duplicate_active_invariant_is_400(self):
        payload = _finding_payload(self.test.id, active=True, duplicate=True)
        response = self.client.post(self.v3_url("findings"), payload, format="json")
        self.assertEqual(400, response.status_code)
        self.assertEqual("application/problem+json", response["Content-Type"])

    def test_create_false_positive_verified_invariant_is_400(self):
        payload = _finding_payload(self.test.id, verified=True, false_p=True)
        response = self.client.post(self.v3_url("findings"), payload, format="json")
        self.assertEqual(400, response.status_code)

    def test_create_bad_severity_is_400(self):
        payload = _finding_payload(self.test.id, severity="Catastrophic")
        response = self.client.post(self.v3_url("findings"), payload, format="json")
        self.assertEqual(400, response.status_code)

    def test_create_push_to_jira_calls_service(self):
        with patch(_PUSH) as push:
            payload = _finding_payload(self.test.id, push_to_jira=True)
            response = self.client.post(self.v3_url("findings"), payload, format="json")
        self.assertEqual(201, response.status_code, response.content[:500])
        push.assert_called_once()


class TestApiV3FindingUpdate(ApiV3TestCase):

    def setUp(self):
        super().setUp()
        self.finding = Finding.objects.filter(risk_accepted=False).first()

    def test_update_scalar(self):
        response = self.client.patch(
            self.v3_url(f"findings/{self.finding.id}"), {"severity": "Low"}, format="json",
        )
        self.assertEqual(200, response.status_code, response.content[:500])
        self.finding.refresh_from_db()
        self.assertEqual("Low", self.finding.severity)

    def test_update_vulnerability_ids(self):
        response = self.client.patch(
            self.v3_url(f"findings/{self.finding.id}"),
            {"vulnerability_ids": ["CVE-2019-9999"]}, format="json",
        )
        self.assertEqual(200, response.status_code, response.content[:500])
        self.finding.refresh_from_db()
        self.assertEqual("CVE-2019-9999", self.finding.cve)
        self.assertTrue(Vulnerability_Id.objects.filter(finding=self.finding, vulnerability_id="CVE-2019-9999").exists())

    def test_update_cwe_resyncs_finding_cwe(self):
        response = self.client.patch(
            self.v3_url(f"findings/{self.finding.id}"), {"cwe": 89}, format="json",
        )
        self.assertEqual(200, response.status_code, response.content[:500])
        self.finding.refresh_from_db()
        self.assertEqual(89, self.finding.cwe)
        self.assertTrue(Finding_CWE.objects.filter(finding=self.finding, cwe="CWE-89").exists())

    def test_update_duplicate_active_invariant_is_400(self):
        self.finding.active = True
        self.finding.save()
        response = self.client.patch(
            self.v3_url(f"findings/{self.finding.id}"), {"duplicate": True}, format="json",
        )
        self.assertEqual(400, response.status_code)

    def test_update_risk_accept_disabled_is_400(self):
        product = self.finding.test.engagement.product
        product.enable_simple_risk_acceptance = False
        product.save()
        response = self.client.patch(
            self.v3_url(f"findings/{self.finding.id}"),
            {"risk_accepted": True, "active": False}, format="json",
        )
        self.assertEqual(400, response.status_code)

    def test_update_active_and_risk_accepted_is_400(self):
        product = self.finding.test.engagement.product
        product.enable_simple_risk_acceptance = True
        product.save()
        response = self.client.patch(
            self.v3_url(f"findings/{self.finding.id}"),
            {"risk_accepted": True, "active": True}, format="json",
        )
        self.assertEqual(400, response.status_code)

    @override_settings(EDITABLE_MITIGATED_DATA=False)
    def test_update_mitigated_blocked_when_disabled(self):
        response = self.client.patch(
            self.v3_url(f"findings/{self.finding.id}"),
            {"mitigated": "2024-01-01T00:00:00Z"}, format="json",
        )
        self.assertEqual(400, response.status_code)

    @override_settings(EDITABLE_MITIGATED_DATA=True)
    def test_update_mitigated_allowed_for_superuser_when_enabled(self):
        # admin is a superuser; can_edit_mitigated_data requires EDITABLE_MITIGATED_DATA + superuser.
        response = self.client.patch(
            self.v3_url(f"findings/{self.finding.id}"),
            {"mitigated": "2024-01-01T00:00:00Z"}, format="json",
        )
        self.assertEqual(200, response.status_code, response.content[:500])

    def test_update_keep_in_sync_pushes_synchronously(self):
        with patch(_KEEP_IN_SYNC, return_value=True), patch(_PUSH, return_value=(True, "ok")) as push:
            response = self.client.patch(
                self.v3_url(f"findings/{self.finding.id}"), {"severity": "Medium"}, format="json",
            )
        self.assertEqual(200, response.status_code, response.content[:500])
        push.assert_called_once()
        self.assertTrue(push.call_args.kwargs.get("force_sync"))

    def test_update_jira_push_failure_is_400(self):
        with patch(_KEEP_IN_SYNC, return_value=False), patch(_PUSH, return_value=(False, "jira exploded")):
            response = self.client.patch(
                self.v3_url(f"findings/{self.finding.id}"),
                {"severity": "Medium", "push_to_jira": True}, format="json",
            )
        self.assertEqual(400, response.status_code)


class TestApiV3FindingReplace(ApiV3TestCase):

    """PUT full-replace: validates FindingReplace, resets omitted optionals, flows through the service."""

    def setUp(self):
        super().setUp()
        self.finding = Finding.objects.filter(risk_accepted=False, is_mitigated=False).first()

    def _put(self, **overrides):
        payload = {
            "title": "v3 put finding",
            "severity": "High",
            "description": "replaced via put",
            "active": True,
            "verified": False,
        }
        payload.update(overrides)
        return self.client.put(self.v3_url(f"findings/{self.finding.id}"), payload, format="json")

    def test_put_full_replace_resets_omitted_optionals(self):
        # Set an optional via PATCH, then PUT without it -> it resets to the schema default.
        self.client.patch(
            self.v3_url(f"findings/{self.finding.id}"), {"impact": "temporary impact"}, format="json",
        )
        self.finding.refresh_from_db()
        self.assertEqual("temporary impact", self.finding.impact)
        response = self._put()
        self.assertEqual(200, response.status_code, response.content[:500])
        self.finding.refresh_from_db()
        self.assertIsNone(self.finding.impact)  # omitted from PUT -> reset to default (None)
        self.assertEqual("V3 Put Finding", self.finding.title)  # title-cased on save

    def test_put_non_null_boolean_resets_to_model_default(self):
        # A non-null status bool set via PATCH resets to its model default (False), not None (§12).
        self.client.patch(
            self.v3_url(f"findings/{self.finding.id}"), {"out_of_scope": True}, format="json",
        )
        self.finding.refresh_from_db()
        self.assertTrue(self.finding.out_of_scope)
        self.assertEqual(200, self._put().status_code)
        self.finding.refresh_from_db()
        self.assertFalse(self.finding.out_of_scope)

    def test_put_missing_required_is_400(self):
        response = self.client.put(
            self.v3_url(f"findings/{self.finding.id}"),
            {"title": "x", "description": "y", "active": True, "verified": False},  # no severity
            format="json",
        )
        self.assertEqual(400, response.status_code)
        self.assertEqual("application/problem+json", response["Content-Type"])

    def test_put_unknown_field_is_400(self):
        # `test` is not writable on replace (editable=False) -> rejected as unknown (extra=forbid).
        response = self._put(test=self.finding.test_id)
        self.assertEqual(400, response.status_code)

    def test_put_side_effects_flow_through_service_jira(self):
        with patch(_KEEP_IN_SYNC, return_value=True), patch(_PUSH, return_value=(True, "ok")) as push:
            response = self._put()
        self.assertEqual(200, response.status_code, response.content[:500])
        push.assert_called_once()
        self.assertTrue(push.call_args.kwargs.get("force_sync"))

    def test_put_unauthorized_is_404(self):
        limited = User.objects.create_user(username="v3_put_limited", password="x")  # noqa: S106
        client = self.token_client(user=limited)
        response = client.put(
            self.v3_url(f"findings/{self.finding.id}"),
            {"title": "x", "severity": "High", "description": "y", "active": True, "verified": False},
            format="json",
        )
        self.assertEqual(404, response.status_code)

    def test_put_visible_but_not_editable_is_403(self):
        # OS legacy authz can't express view-but-not-edit; exercise the 403 code path by failing the
        # edit permission check while the object stays visible to the admin (§12, OS5 pattern).
        with patch("dojo.finding.api_v3.routes.user_has_permission", return_value=False):
            response = self._put()
        self.assertEqual(403, response.status_code, response.content[:300])


class TestApiV3FindingDelete(ApiV3TestCase):

    def test_delete(self):
        finding = Finding.objects.first()
        response = self.client.delete(self.v3_url(f"findings/{finding.id}"))
        self.assertEqual(204, response.status_code)
        self.assertFalse(Finding.objects.filter(pk=finding.id).exists())

    def test_delete_runs_jira_sync_with_v2_default(self):
        # D17 regression pin (API_V3_DIVERGENCE_ANALYSIS.md): v3 delete must pass the v2 tri-state
        # default push_to_jira=None so finding_delete's JIRA close/reassign runs. A bare
        # finding.delete() hits the model's suppress-sentinel and silently skips it.
        # Use a fresh standalone finding: mocking finding_delete skips its dedup FK reassignment,
        # so deleting a fixture finding referenced via duplicate_finding would violate the FK.
        finding = Finding.objects.first()
        finding.pk = None
        finding.title = "d17 regression pin"
        finding.save()
        with patch("dojo.finding.helper.finding_delete") as mock_finding_delete:
            response = self.client.delete(self.v3_url(f"findings/{finding.id}"))
        self.assertEqual(204, response.status_code)
        mock_finding_delete.assert_called_once()
        self.assertIsNone(mock_finding_delete.call_args.kwargs.get("push_to_jira", "MISSING"))


class TestApiV3FindingWriteRbac(ApiV3TestCase):

    def setUp(self):
        super().setUp()
        self.limited = User.objects.create_user(username="v3_fw_limited", password="x")  # noqa: S106
        self.member = Dojo_User.objects.create_user(username="v3_fw_member", password="x")  # noqa: S106
        self.finding = Finding.objects.first()
        self.product = self.finding.test.engagement.product
        self.product.authorized_users.add(self.member)

    def test_unauthorized_finding_update_is_404(self):
        client = self.token_client(user=self.limited)
        response = client.patch(self.v3_url(f"findings/{self.finding.id}"), {"severity": "Low"}, format="json")
        self.assertEqual(404, response.status_code)

    def test_unauthorized_finding_delete_is_404(self):
        client = self.token_client(user=self.limited)
        response = client.delete(self.v3_url(f"findings/{self.finding.id}"))
        self.assertEqual(404, response.status_code)

    def test_create_on_unauthorized_test_is_403(self):
        client = self.token_client(user=self.limited)
        response = client.post(
            self.v3_url("findings"), _finding_payload(self.finding.test_id), format="json",
        )
        self.assertEqual(403, response.status_code, response.content[:300])

    def test_member_can_view_but_delete_is_403(self):
        # OS legacy RBAC: membership grants view+edit; delete is staff-only, so the not-modifiable
        # 403 is demonstrated on delete (Finding_Edit is not staff-gated in OS legacy -- §12).
        client = self.token_client(user=self.member)
        self.get_json(f"findings/{self.finding.id}", client=client)
        response = client.delete(self.v3_url(f"findings/{self.finding.id}"))
        self.assertEqual(403, response.status_code, response.content[:300])
