"""
Regression tests: the UI "mark as duplicate" view must keep a duplicate cluster one level deep.

The view (``finding/<duplicate_id>/duplicate/<original_id>``) points the duplicate at the original's
cluster root. Without guards, a POST could mark a finding as a duplicate of itself, mark a cluster's
root as a duplicate of one of its own members (the root then points at itself and the cluster has
no active original), mark a finding under an orphaned duplicate (it was saved as a duplicate of
nothing), or mark a cluster's root under another original while its members kept pointing at it
(a two-level chain). Each test posts to the real route and reloads the rows.
"""
from django.contrib.auth.models import User
from django.contrib.messages import get_messages
from django.test import override_settings
from django.utils import timezone

from dojo.models import Finding, Test, Test_Type
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures

# dojo_testdata.json: finding 2 is an active cluster root and 3-6 are its duplicates; finding 7 is a
# standalone inactive finding in the same test.
ROOT = 2
MEMBERS = (3, 4, 5, 6)
OTHER = 7


@versioned_fixtures
@override_settings(SECURE_SSL_REDIRECT=False)
class MarkFindingDuplicateSelfReferenceTest(DojoTestCase):

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.client.force_login(User.objects.get(username="admin"))

    def _state(self, *ids):
        return {
            f.id: (f.duplicate, f.duplicate_finding_id, f.active)
            for f in Finding.objects.filter(pk__in=ids).order_by("pk")
        }

    def _mark(self, duplicate_id, original_id):
        response = self.client.post(f"/finding/{duplicate_id}/duplicate/{original_id}")
        self.assertEqual(response.status_code, 302)
        return [str(m) for m in get_messages(response.wsgi_request)]

    def _assert_refused(self, duplicate_id, original_id, expected_text):
        ids = (ROOT, *MEMBERS, OTHER)
        before = self._state(*ids)
        texts = self._mark(duplicate_id, original_id)
        self.assertEqual(self._state(*ids), before)
        self.assertTrue(any(expected_text in t for t in texts), texts)

    def test_refuses_a_finding_marked_as_a_duplicate_of_itself(self):
        self._assert_refused(ROOT, ROOT, "cannot be marked as a duplicate of itself")

    def test_refuses_a_standalone_finding_marked_as_a_duplicate_of_itself(self):
        self._assert_refused(OTHER, OTHER, "cannot be marked as a duplicate of itself")

    def test_refuses_a_cluster_root_marked_as_a_duplicate_of_its_own_member(self):
        # Finding 3 is a duplicate of 2, so marking 2 from 3's page would point 2 at itself.
        self._assert_refused(ROOT, MEMBERS[0], f"Finding {MEMBERS[0]} is a duplicate of finding {ROOT}")

    def test_refuses_a_finding_marked_under_an_orphaned_duplicate(self):
        # A duplicate whose original is gone heads a cluster with no active finding.
        orphan = MEMBERS[-1]
        Finding.objects.filter(pk=orphan).update(duplicate_finding=None)
        self._assert_refused(OTHER, orphan, f"Finding {orphan} is itself a duplicate")

    def test_marking_a_cluster_root_moves_its_members_onto_the_new_original(self):
        # One member sits in its own test type and was left active by older data.
        engagement = Finding.objects.get(pk=ROOT).test.engagement
        other_type = Test_Type.objects.create(name="Mark Duplicate Other Type")
        now = timezone.now()
        other_test = Test.objects.create(engagement=engagement, test_type=other_type, target_start=now, target_end=now)
        Finding.objects.filter(pk=MEMBERS[0]).update(test=other_test, active=True, verified=True)

        self._mark(ROOT, OTHER)

        for finding in Finding.objects.filter(pk__in=(ROOT, *MEMBERS)):
            self.assertEqual(
                (finding.duplicate, finding.duplicate_finding_id, finding.active, finding.verified),
                (True, OTHER, False, False),
                finding.id,
            )
        original = Finding.objects.get(pk=OTHER)
        self.assertFalse(original.duplicate)
        self.assertIn(other_type, original.found_by.all())

    def test_marking_from_a_member_page_lands_under_the_root(self):
        self._mark(OTHER, MEMBERS[0])
        self.assertEqual(self._state(OTHER), {OTHER: (True, ROOT, False)})
