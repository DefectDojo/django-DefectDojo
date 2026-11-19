"""
Regression tests: Set as Original on an inactive duplicate leaves the cluster with no open finding.

Every member of a cluster is an inactive duplicate, so promoting one to original used to leave it inactive while the
old original closed: nothing in the cluster was open any more. The new original takes over the open or closed status
(``active``, ``verified`` and the mitigation fields) of the finding it replaces as the head of the cluster. A target
that is a duplicate in another cluster is refused, as the Similar Findings menu never offers it. Each test posts to
the real API v2 route (or the classic view the Set as Original button calls) and reloads every row.
"""
import datetime

from django.contrib.messages.storage.fallback import FallbackStorage
from django.test import RequestFactory, override_settings
from django.utils.timezone import now
from rest_framework.test import APIClient

from dojo.finding.ui.views import set_finding_as_original
from dojo.models import Dojo_User, Engagement, Finding, Product, Product_Type, Test, Test_Type
from unittests.dojo_test_case import DojoAPITestCase

STATUS_FIELDS = ("duplicate", "duplicate_finding_id", "active", "verified", "is_mitigated", "mitigated", "mitigated_by_id")


@override_settings(SECURE_SSL_REDIRECT=False)
class SetFindingAsOriginalClusterStatusTest(DojoAPITestCase):

    """One test holding a cluster (an open, verified root R with inactive duplicates M1 and M2) and an outside cluster."""

    def setUp(self):
        self.user = Dojo_User.objects.create(username="set_original_status", is_staff=True, is_superuser=True)
        product = Product.objects.create(
            name="Set Original Status",
            prod_type=Product_Type.objects.create(name="Set Original Status PT"),
            description="d",
        )
        engagement = Engagement.objects.create(
            name="Set Original Status", product=product, target_start=now(), target_end=now(),
        )
        self.test = Test.objects.create(
            engagement=engagement,
            test_type=Test_Type.objects.create(name="Set Original Status Type"),
            target_start=now(),
            target_end=now(),
        )
        self.root = self._finding("root", active=True, verified=True)
        self.m1 = self._finding("m1", duplicate=True, duplicate_finding=self.root)
        self.m2 = self._finding("m2", duplicate=True, duplicate_finding=self.root)
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    def _finding(self, title, *, active=False, verified=False, **fields):
        return Finding.objects.create(
            title=f"Set Original Status {title}", test=self.test, reporter=self.user, severity="High",
            active=active, verified=verified, **fields,
        )

    def _state(self, *findings):
        return {
            f.id: tuple(getattr(f, field) for field in STATUS_FIELDS)
            for f in Finding.objects.filter(pk__in=[finding.id for finding in findings])
        }

    def _post(self, page, new_original):
        return self.client.post(f"/api/v2/findings/{page.id}/original/{new_original.id}/")

    def _assert_promoted(self, new_original, closed, *, mitigated=None, mitigated_by=None, active=True, verified=True):
        state = self._state(new_original, *closed)
        is_mitigated = mitigated is not None
        expected = {
            new_original.id: (False, None, active, verified, is_mitigated, mitigated, mitigated_by),
            **{f.id: (True, new_original.id, False, False, *state[f.id][4:]) for f in closed},
        }
        self.assertEqual(state, expected, msg=f"fields {STATUS_FIELDS}, persisted {state}")

    def test_from_a_member_page_the_new_original_takes_over_the_open_root(self):
        response = self._post(self.m1, self.m2)
        self.assertEqual(response.status_code, 204, response.content)
        self._assert_promoted(self.m2, (self.root, self.m1))

    def test_from_the_root_page_the_new_original_takes_over_the_open_root(self):
        response = self._post(self.root, self.m2)
        self.assertEqual(response.status_code, 204, response.content)
        self._assert_promoted(self.m2, (self.root, self.m1))

    def test_ui_view_from_the_root_page_takes_over_the_open_root(self):
        request = RequestFactory().post(f"/finding/{self.root.id}/original/{self.m2.id}")
        request.user = self.user
        request.session = {}
        request._messages = FallbackStorage(request)
        response = set_finding_as_original(request, self.root.id, self.m2.id)
        self.assertEqual(response.status_code, 302, response.content[:500])
        self.assertEqual([str(m) for m in request._messages], [])
        self._assert_promoted(self.m2, (self.root, self.m1))

    def test_a_mitigated_cluster_stays_mitigated(self):
        mitigated = datetime.datetime(2026, 1, 2, 3, 4, 5, tzinfo=datetime.UTC)
        Finding.objects.filter(pk=self.root.id).update(
            active=False, verified=True, is_mitigated=True, mitigated=mitigated, mitigated_by=self.user,
        )
        # From the root's page: from a member's page, the open member would be hidden under a mitigated root, which
        # is refused before anything moves.
        response = self._post(self.root, self.m2)
        self.assertEqual(response.status_code, 204, response.content)
        self._assert_promoted(
            self.m2, (self.root, self.m1), mitigated=mitigated, mitigated_by=self.user.id, active=False, verified=True,
        )

    def test_swapping_back_keeps_the_cluster_open(self):
        # The reported sequence: two open findings P and T, T set as the original from P's page, then P set back as
        # the original from T's page.
        page = self._finding("page", active=True, verified=True)
        target = self._finding("target", active=True, verified=True)
        self.assertEqual(self._post(page, target).status_code, 204)
        response = self._post(target, page)
        self.assertEqual(response.status_code, 204, response.content)
        self._assert_promoted(page, (target,))

    def test_an_orphan_duplicate_takes_over_the_page_finding(self):
        # A duplicate whose original is gone heads no cluster; the menu offers it, so it is promoted, not refused.
        orphan = self._finding("orphan", duplicate=True)
        page = self._finding("page", active=True, verified=True)
        response = self._post(page, orphan)
        self.assertEqual(response.status_code, 204, response.content)
        self._assert_promoted(orphan, (page,))

    def test_an_open_new_original_keeps_its_own_status(self):
        # Control: a target that is no duplicate is already open, so nothing is copied onto it.
        target = self._finding("target", active=True, verified=False)
        response = self._post(self.m1, target)
        self.assertEqual(response.status_code, 204, response.content)
        self._assert_promoted(target, (self.root, self.m1, self.m2), verified=False)

    def test_a_duplicate_in_another_cluster_is_refused(self):
        other_root = self._finding("other root", active=True, verified=True)
        other_member = self._finding("other member", duplicate=True, duplicate_finding=other_root)
        page = self._finding("page", active=True, verified=True)
        for page_finding in (page, self.root, self.m1):
            with self.subTest(page=page_finding.title):
                before = self._state(self.root, self.m1, self.m2, other_root, other_member, page)
                response = self._post(page_finding, other_member)
                self.assertEqual(response.status_code, 400, response.content)
                self.assertEqual(
                    response.json()["detail"],
                    f"Finding {other_member.id} is a duplicate of finding {other_root.id}, which is not in the "
                    f"cluster of finding {page_finding.id}, so it cannot become its original. Use Reset Duplicate "
                    f"Status on finding {other_member.id} first.",
                )
                self.assertEqual(self._state(self.root, self.m1, self.m2, other_root, other_member, page), before)
