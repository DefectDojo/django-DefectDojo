"""
Regression tests: the UI "mark as duplicate" view must keep a duplicate cluster one level deep.

The view (``finding/<duplicate_id>/duplicate/<original_id>``) points the duplicate at the original's
cluster root. Without guards, a POST could mark a finding as a duplicate of itself, mark a cluster's
root as a duplicate of one of its own members (the root then points at itself and the cluster has
no active original), mark a finding under an orphaned duplicate (it was saved as a duplicate of
nothing), or mark a cluster's root under another original while its members kept pointing at it
(a two-level chain). The marked finding's own duplicates move onto the root with it, so the engagement
deduplication rule applies to each of them too, and a root or a member outside the marked finding's product is
refused. The refusal names resetting the member's duplicate status as the remedy, so its similar-finding row offers it.
Each test posts to the real route and reloads the rows.
"""
from django.contrib.auth.models import User
from django.contrib.messages import get_messages
from django.test import override_settings
from django.utils import timezone

from dojo.finding.ui.views import (
    ENGAGEMENT_DEDUPLICATION_MISMATCH_MESSAGE,
    calculate_possible_related_actions_for_similar_finding,
)
from dojo.models import Engagement, Finding, Test, Test_Type
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

    def test_refuses_moving_an_open_member_under_a_mitigated_original(self):
        # The marked root is itself mitigated, so it may go under a mitigated original, but one of its
        # duplicates was left active by older data: moving it would hide a finding that is still open.
        now = timezone.now()
        Finding.objects.filter(pk__in=(ROOT, OTHER)).update(active=False, is_mitigated=True, mitigated=now)
        Finding.objects.filter(pk=MEMBERS[0]).update(active=True)
        self._assert_refused(ROOT, OTHER, f"finding {MEMBERS[0]}, a duplicate of finding {ROOT}, is still open")

    def test_moves_inactive_members_under_a_mitigated_original(self):
        # Members that are already inactive are not hidden by the move, so the mark goes ahead.
        now = timezone.now()
        Finding.objects.filter(pk__in=(ROOT, OTHER)).update(active=False, is_mitigated=True, mitigated=now)
        self._mark(ROOT, OTHER)
        self.assertEqual(
            set(Finding.objects.filter(pk__in=(ROOT, *MEMBERS)).values_list("duplicate_finding_id", flat=True)),
            {OTHER},
        )

    def test_an_original_pointing_at_the_marked_finding_is_not_moved(self):
        # Older data can leave a non-duplicate original whose duplicate_finding still names the marked
        # finding. It is the root of the mark, so it must not be swept up with the marked finding's members.
        Finding.objects.filter(pk=OTHER).update(duplicate_finding=ROOT, active=True)
        self._mark(ROOT, OTHER)
        self.assertEqual(self._state(OTHER), {OTHER: (False, ROOT, True)})
        self.assertEqual(self._state(ROOT), {ROOT: (True, OTHER, False)})

    def _move_root_to_other_engagement(self, *, dedupe_on_engagement, root_dedupe_on_engagement=None):
        # Engagement 3 belongs to the same product as finding 2's engagement (1). Engagement 1 holds
        # findings 3 and 7; engagement 3 takes the root.
        if root_dedupe_on_engagement is None:
            root_dedupe_on_engagement = dedupe_on_engagement
        engagement = Engagement.objects.get(pk=3)
        Engagement.objects.filter(pk=1).update(deduplication_on_engagement=dedupe_on_engagement)
        Engagement.objects.filter(pk=3).update(deduplication_on_engagement=root_dedupe_on_engagement)
        test = Finding.objects.get(pk=ROOT).test
        now = timezone.now()
        other_test = Test.objects.create(
            engagement=engagement, test_type=test.test_type, target_start=now, target_end=now,
        )
        Finding.objects.filter(pk=ROOT).update(test=other_test)

    def test_refuses_a_mark_under_a_root_in_another_engagement_with_engagement_deduplication(self):
        # Finding 3 shares finding 7's engagement, but the mark would point 7 at 3's root, finding 2,
        # which now sits in another engagement.
        self._move_root_to_other_engagement(dedupe_on_engagement=True)
        self._assert_refused(OTHER, MEMBERS[0], ENGAGEMENT_DEDUPLICATION_MISMATCH_MESSAGE)

    def test_refuses_a_mark_under_a_root_whose_engagement_alone_has_engagement_deduplication(self):
        # Neither the marked finding's engagement nor the original's has the setting; only the root's does.
        self._move_root_to_other_engagement(dedupe_on_engagement=False, root_dedupe_on_engagement=True)
        self._assert_refused(OTHER, MEMBERS[0], ENGAGEMENT_DEDUPLICATION_MISMATCH_MESSAGE)

    def test_marks_under_a_root_in_another_engagement_without_engagement_deduplication(self):
        self._move_root_to_other_engagement(dedupe_on_engagement=False)
        self._mark(OTHER, MEMBERS[0])
        self.assertEqual(self._state(OTHER), {OTHER: (True, ROOT, False)})

    def test_marks_under_a_root_in_the_same_engagement_from_a_member_in_another(self):
        # The member sits in another engagement, but the root the mark points at shares finding 7's.
        engagement = Engagement.objects.get(pk=3)
        test = Finding.objects.get(pk=MEMBERS[0]).test
        now = timezone.now()
        other_test = Test.objects.create(
            engagement=engagement, test_type=test.test_type, target_start=now, target_end=now,
        )
        Finding.objects.filter(pk=MEMBERS[0]).update(test=other_test)
        self._mark(OTHER, MEMBERS[0])
        self.assertEqual(self._state(OTHER), {OTHER: (True, ROOT, False)})

    # A member of the marked finding moves onto the root with it, so the engagement rule applies to each
    # member as it does to the marked finding.
    def _move_member_of_other_to_another_engagement(self, *, member_dedupe, root_dedupe):
        # Finding 4 becomes a duplicate of finding 7 and moves to engagement 4 (test 4), in the same product
        # as engagement 1, which holds the root (finding 2) and finding 7.
        Engagement.objects.filter(pk=1).update(deduplication_on_engagement=root_dedupe)
        Engagement.objects.filter(pk=4).update(deduplication_on_engagement=member_dedupe)
        Finding.objects.filter(pk=MEMBERS[1]).update(duplicate_finding=OTHER, test=Test.objects.get(pk=4))

    def test_refuses_moving_a_member_into_another_engagement_with_engagement_deduplication(self):
        self._move_member_of_other_to_another_engagement(member_dedupe=True, root_dedupe=True)
        self._assert_refused(OTHER, MEMBERS[0], f"Finding {MEMBERS[1]}, a duplicate of finding {OTHER}")

    def test_refuses_moving_a_member_whose_engagement_alone_has_engagement_deduplication(self):
        self._move_member_of_other_to_another_engagement(member_dedupe=True, root_dedupe=False)
        self._assert_refused(OTHER, MEMBERS[0], f"Finding {MEMBERS[1]}, a duplicate of finding {OTHER}")

    def test_refuses_moving_a_member_when_the_root_engagement_alone_has_engagement_deduplication(self):
        self._move_member_of_other_to_another_engagement(member_dedupe=False, root_dedupe=True)
        self._assert_refused(OTHER, MEMBERS[0], f"Finding {MEMBERS[1]}, a duplicate of finding {OTHER}")

    def test_moves_a_member_in_another_engagement_without_engagement_deduplication(self):
        self._move_member_of_other_to_another_engagement(member_dedupe=False, root_dedupe=False)
        self._mark(OTHER, MEMBERS[0])
        self.assertEqual(
            self._state(OTHER, MEMBERS[1]), {MEMBERS[1]: (True, ROOT, False), OTHER: (True, ROOT, False)},
        )

    def test_refuses_a_mark_under_a_root_in_another_product(self):
        # Only reachable with inconsistent data: the root (finding 2) sits in test 13, engagement 2, product 1,
        # while its member 3 and finding 7 stay in product 2. Engagement deduplication is off everywhere.
        Engagement.objects.all().update(deduplication_on_engagement=False)
        Finding.objects.filter(pk=ROOT).update(test=Test.objects.get(pk=13))
        ids = (ROOT, *MEMBERS, OTHER)
        before = self._state(*ids)
        response = self.client.post(f"/finding/{OTHER}/duplicate/{MEMBERS[0]}")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self._state(*ids), before)

    def _move_member_of_other_to_another_product(self, *, dedupe_on_engagement):
        # Finding 4 becomes a duplicate of finding 7 and moves to test 13 (engagement 2, product 1), while finding 7,
        # its root 2 and finding 3 stay in product 2. Only reachable with inconsistent data.
        Engagement.objects.all().update(deduplication_on_engagement=dedupe_on_engagement)
        Finding.objects.filter(pk=MEMBERS[1]).update(duplicate_finding=OTHER, test=Test.objects.get(pk=13))

    def test_refuses_moving_a_member_in_another_product(self):
        self._move_member_of_other_to_another_product(dedupe_on_engagement=False)
        ids = (ROOT, *MEMBERS, OTHER)
        before = self._state(*ids)
        response = self.client.post(f"/finding/{OTHER}/duplicate/{MEMBERS[0]}")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self._state(*ids), before)

    def test_refuses_moving_a_member_in_another_product_with_engagement_deduplication(self):
        # The product refusal comes first, so engagement deduplication does not turn it into the engagement message.
        self._move_member_of_other_to_another_product(dedupe_on_engagement=True)
        ids = (ROOT, *MEMBERS, OTHER)
        before = self._state(*ids)
        response = self.client.post(f"/finding/{OTHER}/duplicate/{MEMBERS[0]}")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self._state(*ids), before)

    def _actions(self, page_id, row_id):
        page, row = Finding.objects.get(pk=page_id), Finding.objects.get(pk=row_id)
        return [entry["action"] for entry in calculate_possible_related_actions_for_similar_finding(None, page, row)]

    def test_a_duplicate_row_in_another_engagement_offers_the_reset_the_refusal_names(self):
        # The refused mark names finding 4: on the root's page its row is in another engagement, so the linking
        # actions are refused, but resetting its duplicate status stays available.
        self._move_member_of_other_to_another_engagement(member_dedupe=True, root_dedupe=True)
        self._assert_refused(OTHER, MEMBERS[0], f"Finding {MEMBERS[1]}, a duplicate of finding {OTHER}")
        self.assertEqual(self._actions(ROOT, MEMBERS[1]), ["reset_finding_duplicate_status"])
        # The row template shows None alone when the first action is None, so the reset must come first to render.
        response = self.client.get(f"/finding/{ROOT}")
        self.assertEqual(response.status_code, 200)
        self.assertIn(f"/finding/{MEMBERS[1]}/duplicate/reset", response.content.decode())

    def test_a_row_in_another_engagement_that_is_not_a_duplicate_offers_nothing(self):
        Engagement.objects.filter(pk__in=(1, 4)).update(deduplication_on_engagement=True)
        Finding.objects.filter(pk=OTHER).update(test=Test.objects.get(pk=4))
        self.assertEqual(self._actions(ROOT, OTHER), ["None"])
