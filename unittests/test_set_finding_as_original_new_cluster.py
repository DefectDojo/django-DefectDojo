"""
Regression tests: Set as Original from a finding in no cluster leaves it an unverified duplicate.

Setting another finding as the original from the page of a finding that is in no cluster starts a new cluster: the
page finding becomes an inactive duplicate of the chosen original. Every other path that makes a finding a duplicate
(Mark as Duplicate, and Set as Original on an existing cluster) also clears ``verified``, so this one must too. Each
test reloads the rows after a POST: one to the real API v2 route, one to the classic view the Set as Original button
calls (called directly, so the test does not depend on which UI a deployment serves).
"""
from django.contrib.messages.storage.fallback import FallbackStorage
from django.test import RequestFactory, override_settings
from django.utils.timezone import now
from rest_framework.test import APIClient

from dojo.finding.ui.views import set_finding_as_original
from dojo.models import Dojo_User, Engagement, Finding, Product, Product_Type, Test, Test_Type
from unittests.dojo_test_case import DojoAPITestCase


@override_settings(SECURE_SSL_REDIRECT=False)
class SetFindingAsOriginalNewClusterTest(DojoAPITestCase):

    """One product, one test, and two open, verified findings that are in no cluster."""

    @classmethod
    def setUpTestData(cls):
        cls.user = Dojo_User.objects.create(username="set_original_new_cluster", is_staff=True, is_superuser=True)
        product = Product.objects.create(
            name="Set Original New Cluster",
            prod_type=Product_Type.objects.create(name="Set Original New Cluster PT"),
            description="d",
        )
        engagement = Engagement.objects.create(
            name="Set Original New Cluster", product=product, target_start=now(), target_end=now(),
        )
        test = Test.objects.create(
            engagement=engagement,
            test_type=Test_Type.objects.create(name="Set Original New Cluster Type"),
            target_start=now(),
            target_end=now(),
        )
        cls.page, cls.other = (
            Finding.objects.create(
                title=title, test=test, reporter=cls.user, severity="High", active=True, verified=True,
            ).id
            for title in ("Set Original page", "Set Original other")
        )

    def _assert_new_cluster(self):
        state = {
            f.id: (f.duplicate, f.duplicate_finding_id, f.active, f.verified)
            for f in Finding.objects.filter(pk__in=(self.page, self.other))
        }
        # (duplicate, duplicate_finding, active, verified): the page finding is an inactive, unverified duplicate of
        # the new original, which keeps its open, verified status.
        self.assertEqual(
            state,
            {self.page: (True, self.other, False, False), self.other: (False, None, True, True)},
            msg=f"persisted {state}",
        )

    def test_api_set_as_original_unverifies_the_new_duplicate(self):
        client = APIClient()
        client.force_authenticate(self.user)
        response = client.post(f"/api/v2/findings/{self.page}/original/{self.other}/")
        self.assertEqual(response.status_code, 204, response.content)
        self._assert_new_cluster()

    def test_ui_set_as_original_unverifies_the_new_duplicate(self):
        request = RequestFactory().post(f"/finding/{self.page}/original/{self.other}")
        request.user = self.user
        request.session = {}
        request._messages = FallbackStorage(request)
        response = set_finding_as_original(request, self.page, self.other)
        self.assertEqual(response.status_code, 302, response.content[:500])
        self.assertEqual([str(m) for m in request._messages], [])
        self._assert_new_cluster()
