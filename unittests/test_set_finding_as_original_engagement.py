"""
Regression tests: Set as Original applies the engagement deduplication rule to every finding it moves.

``POST /api/v2/findings/{finding}/original/{new_original}/`` (also what the classic Set as Original button and
the Pro Similar Findings menu call) moves the page finding's whole cluster under the new original: its old root
and that root's other duplicates, not only the page finding. Each of them may not move under an original in
another engagement while either engagement has deduplication_on_engagement, the same rule a manual Mark as
Duplicate applies to the members it moves. The old root ends up an inactive duplicate like every other member.
The Similar Findings menu offers Set as Original only on the rows the route accepts. Each route test posts to the
real route and reloads the rows.
"""
from django.db import connection
from django.test import RequestFactory, override_settings
from django.test.utils import CaptureQueriesContext
from django.utils.timezone import now
from rest_framework.test import APIClient

from dojo.finding.ui.views import calculate_possible_related_actions_for_similar_finding
from dojo.models import Dojo_User, Engagement, Finding, Product, Product_Type, Test, Test_Type
from unittests.dojo_test_case import DojoAPITestCase


@override_settings(SECURE_SSL_REDIRECT=False)
class SetFindingAsOriginalEngagementTest(DojoAPITestCase):

    """
    One product with two engagements. In engagement ``home``: the active cluster root, its four inactive
    duplicates, and an open standalone finding (the new original). Engagement ``away`` starts empty; a test moves
    the root or a member there.
    """

    @classmethod
    def setUpTestData(cls):
        cls.user = Dojo_User.objects.create(username="set_original_admin", is_staff=True, is_superuser=True)
        test_type = Test_Type.objects.create(name="Set Original Engagement Type")
        product = Product.objects.create(
            name="Set Original Engagement",
            prod_type=Product_Type.objects.create(name="Set Original Engagement PT"),
            description="d",
        )
        cls.home, cls.away = (
            Engagement.objects.create(name=name, product=product, target_start=now(), target_end=now())
            for name in ("Set Original Home", "Set Original Away")
        )
        cls.home_test, cls.away_test = (
            Test.objects.create(engagement=engagement, test_type=test_type, target_start=now(), target_end=now())
            for engagement in (cls.home, cls.away)
        )

        def finding(title):
            return Finding.objects.create(
                title=title, test=cls.home_test, reporter=cls.user, severity="High", active=True, verified=True,
            ).id

        cls.root = finding("Set Original root")
        cls.members = tuple(finding(f"Set Original member {n}") for n in range(4))
        cls.other = finding("Set Original other")
        Finding.objects.filter(pk__in=cls.members).update(
            duplicate=True, duplicate_finding=cls.root, active=False, verified=False,
        )
        cls.cluster = (cls.root, *cls.members, cls.other)

    def setUp(self):
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    def _state(self):
        return {
            f.id: (f.duplicate, f.duplicate_finding_id, f.active, f.verified)
            for f in Finding.objects.filter(pk__in=self.cluster).order_by("pk")
        }

    def _set_original(self, page_id, new_original_id):
        return self.client.post(f"/api/v2/findings/{page_id}/original/{new_original_id}/")

    def _engagements(self, *, home_dedupe, away_dedupe):
        Engagement.objects.filter(pk=self.home.pk).update(deduplication_on_engagement=home_dedupe)
        Engagement.objects.filter(pk=self.away.pk).update(deduplication_on_engagement=away_dedupe)

    def _move_away(self, *finding_ids):
        Finding.objects.filter(pk__in=finding_ids).update(test=self.away_test)

    def _assert_refused(self, page_id, new_original_id, named_id):
        before = self._state()
        response = self._set_original(page_id, new_original_id)
        self.assertEqual(response.status_code, 400, response.content)
        detail = response.json()["detail"]
        self.assertIn(f"Finding {named_id}", detail)
        self.assertIn("deduplication on engagement", detail)
        self.assertEqual(self._state(), before)

    def _assert_moved(self, page_id, new_original_id):
        response = self._set_original(page_id, new_original_id)
        self.assertEqual(response.status_code, 204, response.content)
        state = self._state()
        for finding_id in (self.root, *self.members):
            self.assertEqual(state[finding_id], (True, self.other, False, False), finding_id)
        self.assertEqual(state[self.other][:3], (False, None, True))

    # The old root, reached through a duplicate's page

    def test_refuses_moving_the_old_root_into_an_engagement_with_engagement_deduplication(self):
        # The page finding and the new original share the home engagement, which deduplicates; the root's does not.
        self._engagements(home_dedupe=True, away_dedupe=False)
        self._move_away(self.root)
        self._assert_refused(self.members[0], self.other, self.root)

    def test_refuses_moving_the_old_root_whose_engagement_alone_has_engagement_deduplication(self):
        self._engagements(home_dedupe=False, away_dedupe=True)
        self._move_away(self.root)
        self._assert_refused(self.members[0], self.other, self.root)

    def test_moves_the_old_root_from_another_engagement_without_engagement_deduplication(self):
        self._engagements(home_dedupe=False, away_dedupe=False)
        self._move_away(self.root)
        self._assert_moved(self.members[0], self.other)

    def test_the_old_root_becomes_an_inactive_duplicate(self):
        # Same engagement: the move goes ahead, and the old root no longer stays open beside its new original.
        self._assert_moved(self.members[0], self.other)

    # The other members, reached through the root's page or a duplicate's page

    def test_refuses_moving_a_member_into_an_engagement_with_engagement_deduplication(self):
        self._engagements(home_dedupe=True, away_dedupe=False)
        self._move_away(self.members[1])
        self._assert_refused(self.root, self.other, self.members[1])

    def test_refuses_moving_a_member_whose_engagement_alone_has_engagement_deduplication(self):
        self._engagements(home_dedupe=False, away_dedupe=True)
        self._move_away(self.members[1])
        self._assert_refused(self.members[0], self.other, self.members[1])

    def test_moves_a_member_from_another_engagement_without_engagement_deduplication(self):
        self._engagements(home_dedupe=False, away_dedupe=False)
        self._move_away(self.members[1])
        self._assert_moved(self.root, self.other)

    def test_a_root_page_becomes_an_inactive_duplicate(self):
        # Set as Original from the root's own page: the root is the old root, so it closes like one.
        self._assert_moved(self.root, self.other)

    def test_promoting_a_member_leaves_the_rest_of_the_cluster_under_it(self):
        # The new original is a member of the page's own cluster: it is never refused against itself.
        self._engagements(home_dedupe=True, away_dedupe=True)
        new_original = self.members[1]
        response = self._set_original(self.members[0], new_original)
        self.assertEqual(response.status_code, 204, response.content)
        state = self._state()
        self.assertEqual(state[new_original][:2], (False, None))
        for finding_id in (self.root, self.members[0], self.members[2], self.members[3]):
            self.assertEqual(state[finding_id][:3], (True, new_original, False), finding_id)

    def test_setting_the_current_root_as_original_moves_nothing_and_is_not_refused(self):
        # From a duplicate's page the row's own root is the new original: the cluster already sits under it, so a
        # duplicate that already crosses an engagement is not a reason to refuse.
        self._engagements(home_dedupe=True, away_dedupe=True)
        self._move_away(self.members[1])
        before = self._state()
        response = self._set_original(self.members[0], self.root)
        self.assertEqual(response.status_code, 204, response.content)
        self.assertEqual(self._state(), before)

    # The Similar Findings menu (classic page, and the Pro menu through the same helper)

    def _actions(self, page_id, similar_id):
        request = RequestFactory().get(f"/finding/{page_id}")
        request.user = self.user
        return calculate_possible_related_actions_for_similar_finding(
            request, Finding.objects.get(pk=page_id), Finding.objects.get(pk=similar_id),
        )

    def test_the_menu_hides_set_as_original_where_a_duplicate_would_cross(self):
        # The row and the root share the page's engagement, so Mark as Duplicate stays; Set as Original would move
        # the duplicate in the other engagement, so the route refuses it and the menu does not offer it.
        self._engagements(home_dedupe=True, away_dedupe=False)
        self._move_away(self.members[1])
        self.assertEqual([a["action"] for a in self._actions(self.members[0], self.other)], ["mark_finding_duplicate"])
        self.assertEqual(self._set_original(self.members[0], self.other).status_code, 400)

    def test_the_menu_names_the_finding_that_would_cross_when_nothing_is_left(self):
        # The root in the other engagement blocks both actions on a row in the page's engagement: the row says
        # which finding Set as Original would move across.
        self._engagements(home_dedupe=True, away_dedupe=False)
        self._move_away(self.root)
        actions = self._actions(self.members[0], self.other)
        self.assertEqual([a["action"] for a in actions], ["None"])
        self.assertIn(f"would move finding {self.root}", actions[0]["reason"])

    def test_the_menu_offers_set_as_original_where_the_route_accepts_it(self):
        self._engagements(home_dedupe=False, away_dedupe=False)
        self._move_away(self.root, self.members[1])
        self.assertEqual(
            [a["action"] for a in self._actions(self.members[0], self.other)],
            ["mark_finding_duplicate", "set_finding_as_original"],
        )
        self.assertEqual(self._set_original(self.members[0], self.other).status_code, 204)

    def test_the_menu_reads_the_cluster_once_per_page(self):
        # Every similar-finding row of one page shares the cluster's engagements: one grouped query on the first row
        # that offers Set as Original, none on the rows after it.
        page = Finding.objects.get(pk=self.root)
        request = RequestFactory().get(f"/finding/{page.id}")
        request.user = self.user

        def cluster_reads():
            with CaptureQueriesContext(connection) as queries:
                calculate_possible_related_actions_for_similar_finding(
                    request, page, Finding.objects.get(pk=self.other),
                )
            return sum('MIN("dojo_finding"."id")' in query["sql"] for query in queries.captured_queries)

        self.assertEqual(cluster_reads(), 1)
        self.assertEqual(cluster_reads(), 0)
