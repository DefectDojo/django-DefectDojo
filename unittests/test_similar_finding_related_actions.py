"""
The classic View Finding page offers actions on each similar finding row.

Regression: the menu gated Mark as Duplicate on the finding on the page, while the mark route compares the
similar finding with the page finding's cluster root (the finding it lands under). On a duplicate's page whose
root sits in another engagement with deduplication_on_engagement on, the menu offered a mark the route refuses
and hid one it accepts. Each action is now offered where its route accepts it: Set as Original compares with
the page finding, and Reset Duplicate Status compares no engagements.
"""
from django.contrib.auth.models import User
from django.test import RequestFactory, override_settings
from django.utils import timezone

from dojo.finding.ui.views import calculate_possible_related_actions_for_similar_finding
from dojo.models import Engagement, Finding, Test
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures

# dojo_testdata.json: finding 2 is a cluster root and 3-6 are its duplicates; finding 7 is a standalone
# finding in the same test. Engagements 1 (which holds them) and 3 belong to the same product.
ROOT = 2
PAGE = 3
SAME_ENGAGEMENT_AS_PAGE = 7


@versioned_fixtures
@override_settings(SECURE_SSL_REDIRECT=False)
class SimilarFindingRelatedActionsTest(DojoTestCase):

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.user = User.objects.get(username="admin")
        self.client.force_login(self.user)

    def _actions(self, page_id, similar_id):
        request = RequestFactory().get(f"/finding/{page_id}")
        request.user = self.user
        actions = calculate_possible_related_actions_for_similar_finding(
            request, Finding.objects.get(pk=page_id), Finding.objects.get(pk=similar_id),
        )
        return [action["action"] for action in actions]

    def _split_root_from_page(self, *, dedupe_on_engagement):
        """Move the root into engagement 3 and add a standalone finding there; return that finding's id."""
        Engagement.objects.filter(pk__in=(1, 3)).update(deduplication_on_engagement=dedupe_on_engagement)
        root = Finding.objects.get(pk=ROOT)
        now = timezone.now()
        other_test = Test.objects.create(
            engagement=Engagement.objects.get(pk=3), test_type=root.test.test_type, target_start=now, target_end=now,
        )
        Finding.objects.filter(pk=ROOT).update(test=other_test)
        same_engagement_as_root = Finding.objects.get(pk=SAME_ENGAGEMENT_AS_PAGE)
        same_engagement_as_root.pk = None
        same_engagement_as_root.test = other_test
        same_engagement_as_root.save(dedupe_option=False)
        return same_engagement_as_root.id

    def _mark(self, duplicate_id, original_id):
        response = self.client.post(f"/finding/{duplicate_id}/duplicate/{original_id}")
        self.assertEqual(response.status_code, 302)
        duplicate = Finding.objects.get(pk=duplicate_id)
        return duplicate.duplicate, duplicate.duplicate_finding_id

    def test_hides_the_mark_on_a_row_outside_the_root_engagement(self):
        self._split_root_from_page(dedupe_on_engagement=True)
        actions = self._actions(PAGE, SAME_ENGAGEMENT_AS_PAGE)
        self.assertNotIn("mark_finding_duplicate", actions)
        # Set as Original compares the similar finding with the page finding, which shares its engagement.
        self.assertEqual(actions, ["set_finding_as_original"])
        # The route refuses the mark the menu used to offer.
        self.assertEqual(self._mark(SAME_ENGAGEMENT_AS_PAGE, PAGE), (False, None))

    def test_offers_the_mark_on_a_row_in_the_root_engagement(self):
        similar_id = self._split_root_from_page(dedupe_on_engagement=True)
        actions = self._actions(PAGE, similar_id)
        # Set as Original stays gated on the page finding, which sits in another engagement.
        self.assertEqual(actions, ["mark_finding_duplicate"])
        # The route accepts the mark the menu used to hide, and it lands under the root.
        self.assertEqual(self._mark(similar_id, PAGE), (True, ROOT))

    def test_offers_both_actions_without_engagement_deduplication(self):
        similar_id = self._split_root_from_page(dedupe_on_engagement=False)
        for row in (SAME_ENGAGEMENT_AS_PAGE, similar_id):
            self.assertEqual(self._actions(PAGE, row), ["mark_finding_duplicate", "set_finding_as_original"], row)

    def test_offers_both_actions_from_the_root_page(self):
        # On the root's own page the root is the finding on the page, so both gates agree.
        similar_id = self._split_root_from_page(dedupe_on_engagement=True)
        self.assertEqual(self._actions(ROOT, similar_id), ["mark_finding_duplicate", "set_finding_as_original"])
        self.assertEqual(self._actions(ROOT, SAME_ENGAGEMENT_AS_PAGE), ["None"])

    def _make_duplicate_of_another_cluster(self, finding_id):
        other_root = Finding.objects.get(pk=finding_id)
        other_root.pk = None
        other_root.save(dedupe_option=False)
        Finding.objects.filter(pk=finding_id).update(duplicate=True, duplicate_finding=other_root, active=False)

    def test_offers_reset_on_a_duplicate_row_outside_the_page_engagement(self):
        # A duplicate from another cluster in the root's engagement: the mark lands under the root, so it is
        # offered, and the reset route compares no engagements, so Reset Duplicate Status is offered too.
        similar_id = self._split_root_from_page(dedupe_on_engagement=True)
        self._make_duplicate_of_another_cluster(similar_id)
        self.assertEqual(self._actions(PAGE, similar_id), ["reset_finding_duplicate_status", "mark_finding_duplicate"])

    def test_offers_only_reset_on_a_duplicate_row_outside_both_engagements(self):
        # Neither the page finding nor the root shares the row's engagement, so only the reset is left.
        similar_id = self._split_root_from_page(dedupe_on_engagement=True)
        product = Finding.objects.get(pk=PAGE).test.engagement.product
        now = timezone.now()
        third = Engagement.objects.create(
            product=product, target_start=now, target_end=now, deduplication_on_engagement=True,
        )
        test = Finding.objects.get(pk=similar_id).test
        third_test = Test.objects.create(engagement=third, test_type=test.test_type, target_start=now, target_end=now)
        Finding.objects.filter(pk=similar_id).update(test=third_test)
        self.assertEqual(self._actions(PAGE, similar_id), ["None"])
        self._make_duplicate_of_another_cluster(similar_id)
        self.assertEqual(self._actions(PAGE, similar_id), ["reset_finding_duplicate_status"])
        response = self.client.post(f"/finding/{similar_id}/duplicate/reset")
        self.assertEqual(response.status_code, 302)
        self.assertFalse(Finding.objects.get(pk=similar_id).duplicate)

    def test_the_view_finding_page_offers_the_mark_where_the_route_accepts_it(self):
        similar_id = self._split_root_from_page(dedupe_on_engagement=True)
        response = self.client.get(f"/finding/{PAGE}")
        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        # The row in the page finding's engagement offers Set as Original only.
        self.assertIn(f"/finding/{PAGE}/original/{SAME_ENGAGEMENT_AS_PAGE}", content)
        self.assertNotIn(f"/finding/{SAME_ENGAGEMENT_AS_PAGE}/duplicate/{PAGE}", content)
        # The row in the root's engagement offers Mark as Duplicate only.
        self.assertIn(f"/finding/{similar_id}/duplicate/{PAGE}", content)
        self.assertNotIn(f"/finding/{PAGE}/original/{similar_id}", content)

    def test_the_root_row_offers_nothing(self):
        self._split_root_from_page(dedupe_on_engagement=True)
        self.assertEqual(self._actions(PAGE, ROOT), ["None"])
