"""Tests for the authorized_users scoping of the *_for_queryset helpers."""

from dojo.endpoint.queries import get_authorized_endpoints_for_queryset
from dojo.finding.queries import get_authorized_findings_for_queryset
from dojo.models import Dojo_User, Endpoint, Finding, Test

from .dojo_test_case import DojoTestCase, skip_unless_v2, versioned_fixtures


@versioned_fixtures
class TestAuthorizedQuerysetFilters(DojoTestCase):

    """
    A non-staff user authorized on a product (via authorized_users) should
    have the *_for_queryset helpers scope a passed-in queryset down to the
    objects belonging to that product.
    """

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.user = Dojo_User.objects.create(username="aqf_user", is_active=True)
        self.product = Test.objects.get(id=3).engagement.product
        self.product.authorized_users.add(self.user)

    def test_findings_for_queryset_scoped_to_authorized_product(self):
        finds = get_authorized_findings_for_queryset("delete", Finding.objects.all(), user=self.user)
        self.assertGreater(finds.count(), 0)
        self.assertTrue(all(f.test.engagement.product_id == self.product.id for f in finds))
        outside = Finding.objects.exclude(test__engagement__product=self.product).first()
        self.assertIsNotNone(outside)
        self.assertNotIn(outside, finds)

    @skip_unless_v2
    def test_endpoints_for_queryset_scoped_to_authorized_product(self):
        endpoint = Endpoint.objects.create(product=self.product, host="aqf.example.com")
        eps = get_authorized_endpoints_for_queryset("delete", Endpoint.objects.all(), user=self.user)
        self.assertIn(endpoint, eps)
        self.assertTrue(all(e.product_id == self.product.id for e in eps))
        outside = Endpoint.objects.exclude(product=self.product).first()
        self.assertIsNotNone(outside)
        self.assertNotIn(outside, eps)
