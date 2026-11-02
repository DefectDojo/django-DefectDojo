"""
Regression tests: marking a finding as a duplicate by hand must not hide a finding that is still open.

A duplicate is inactive, and a mitigated original is not shown in any active view, so marking an
open finding as the duplicate of a mitigated one made the open finding disappear. Automatic
deduplication already refuses this (``is_duplicate_reopen``, PR 9558). These tests pin the same
rule on the manual paths: the UI "mark as duplicate" view, and "set as original" in the UI and in
API v2. A false-positive or out-of-scope original is a person's decision about that finding and
stays allowed, as it is for automatic deduplication.
"""
from django.contrib.auth.models import User
from django.contrib.messages import get_messages
from django.test import override_settings
from django.utils import timezone
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.finding.deduplication import manual_duplicate_hides_open_finding
from dojo.models import Finding
from unittests.dojo_test_case import DojoAPITestCase, versioned_fixtures

# dojo_testdata.json: finding 2 is an open cluster root (3-6 are its duplicates); finding 7 is a
# standalone inactive finding in the same test.
OPEN_ROOT = 2
OTHER = 7


def _mitigate(finding_id, **extra):
    Finding.objects.filter(pk=finding_id).update(
        active=False, is_mitigated=True, mitigated=timezone.now(), duplicate=False, duplicate_finding=None, **extra,
    )


@versioned_fixtures
@override_settings(SECURE_SSL_REDIRECT=False)
class ManualDuplicateOntoMitigatedTest(DojoAPITestCase):

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.admin = User.objects.get(username="admin")
        self.api = APIClient()
        self.api.credentials(HTTP_AUTHORIZATION="Token " + Token.objects.get(user=self.admin).key)

    def _assert_untouched_open(self, finding_id):
        finding = Finding.objects.get(pk=finding_id)
        self.assertFalse(finding.duplicate)
        self.assertIsNone(finding.duplicate_finding_id)
        self.assertTrue(finding.active)

    # ---- the shared rule ----------------------------------------------------------------

    def test_rule_resolves_the_cluster_root(self):
        _mitigate(OTHER)
        Finding.objects.filter(pk=3).update(duplicate=True, duplicate_finding_id=OTHER)
        open_finding = Finding.objects.get(pk=OPEN_ROOT)
        # Marking against a duplicate means pointing at its root, which is mitigated.
        self.assertTrue(manual_duplicate_hides_open_finding(open_finding, Finding.objects.get(pk=3)))

    def test_rule_allows_a_false_positive_original(self):
        _mitigate(OTHER, false_p=True)
        self.assertFalse(
            manual_duplicate_hides_open_finding(Finding.objects.get(pk=OPEN_ROOT), Finding.objects.get(pk=OTHER)),
        )

    def test_rule_allows_marking_a_finding_that_is_itself_mitigated(self):
        _mitigate(OTHER)
        _mitigate(OPEN_ROOT)
        self.assertFalse(
            manual_duplicate_hides_open_finding(Finding.objects.get(pk=OPEN_ROOT), Finding.objects.get(pk=OTHER)),
        )

    # ---- API v2: set as original ----------------------------------------------------------

    def test_api_set_as_original_refuses_a_mitigated_original(self):
        _mitigate(OTHER)
        response = self.api.post(f"/api/v2/findings/{OPEN_ROOT}/original/{OTHER}/")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, response.content[:500])
        self.assertIn("mitigated", response.json()["detail"])
        self._assert_untouched_open(OPEN_ROOT)

    def test_api_set_as_original_allows_a_false_positive_original(self):
        _mitigate(OTHER, false_p=True)
        response = self.api.post(f"/api/v2/findings/{OPEN_ROOT}/original/{OTHER}/")
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT, response.content[:500])
        self.assertEqual(Finding.objects.get(pk=OPEN_ROOT).duplicate_finding_id, OTHER)

    def test_api_set_as_original_refuses_when_the_moved_root_is_open(self):
        # Finding 3 is a duplicate of the open root 2. Re-rooting 3's cluster onto a mitigated
        # finding would move the open root under it too.
        _mitigate(OTHER)
        response = self.api.post(f"/api/v2/findings/3/original/{OTHER}/")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, response.content[:500])
        self._assert_untouched_open(OPEN_ROOT)
        self.assertEqual(Finding.objects.get(pk=3).duplicate_finding_id, OPEN_ROOT)

    # ---- UI: mark as duplicate ------------------------------------------------------------

    def test_ui_mark_duplicate_refuses_a_mitigated_original(self):
        _mitigate(OTHER)
        self.client.force_login(self.admin)
        response = self.client.post(f"/finding/{OPEN_ROOT}/duplicate/{OTHER}")
        self.assertEqual(response.status_code, 302)
        self._assert_untouched_open(OPEN_ROOT)
        texts = [str(m) for m in get_messages(response.wsgi_request)]
        self.assertTrue(any("mitigated" in t for t in texts), texts)

    def test_ui_mark_duplicate_still_works_on_an_open_original(self):
        self.client.force_login(self.admin)
        response = self.client.post(f"/finding/{OTHER}/duplicate/{OPEN_ROOT}")
        self.assertEqual(response.status_code, 302)
        marked = Finding.objects.get(pk=OTHER)
        self.assertTrue(marked.duplicate)
        self.assertEqual(marked.duplicate_finding_id, OPEN_ROOT)

    # ---- UI: set as original --------------------------------------------------------------

    def test_ui_set_as_original_refuses_a_mitigated_original(self):
        _mitigate(OTHER)
        self.client.force_login(self.admin)
        response = self.client.post(f"/finding/{OPEN_ROOT}/original/{OTHER}")
        self.assertEqual(response.status_code, 302)
        self._assert_untouched_open(OPEN_ROOT)
        texts = [str(m) for m in get_messages(response.wsgi_request)]
        self.assertTrue(any("mitigated" in t for t in texts), texts)
