"""
Regression test for product scoping in ``product_endpoint_report``.

The view is authorized against the product in the URL, but its Locations branch
built its queryset from every Location with an active finding and never filtered
by that product. The report for one product therefore listed locations belonging
to other products as well. The legacy branch immediately below it has always
filtered on ``product``, so the two branches disagreed.

This is report scope, not authorization: the surrounding filter still limits
output to what the caller may see. The defect is that the report does not answer
the question it was asked, which matters where products model separate customers.
"""
from django.urls import reverse
from django.utils.timezone import now

from dojo.location.models import Location
from dojo.models import (
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
    User,
)
from dojo.url.models import URL
from unittests.dojo_test_case import DojoTestCase, skip_unless_v3, versioned_fixtures


@skip_unless_v3
@versioned_fixtures
class TestProductEndpointReportProductScoping(DojoTestCase):

    """Two products, each with its own location and active finding."""

    fixtures = ["dojo_testdata.json"]

    @classmethod
    def setUpTestData(cls):
        prod_type, _ = Product_Type.objects.get_or_create(name="RptProdScope PT")
        test_type, _ = Test_Type.objects.get_or_create(name="RptProdScope Scan")

        def build(name, host):
            product = Product.objects.create(name=name, description=name, prod_type=prod_type)
            engagement = Engagement.objects.create(
                product=product, name=f"{name} eng",
                target_start=now().date(), target_end=now().date(),
            )
            test = Test.objects.create(
                engagement=engagement, test_type=test_type,
                target_start=now(), target_end=now(),
            )
            finding = Finding.objects.create(
                test=test, title=f"{name} finding", severity="High", numerical_severity="S1",
                active=True, verified=True, description=f"body of {name}",
            )
            location = URL.get_or_create_from_values(protocol="https", host=host, path="app").location
            location.associate_with_finding(finding, audit_time=now())
            location.associate_with_product(product)
            return product, location

        cls.product_a, cls.location_a = build("RptProdScope Product A", "a.rptprodscope.example.com")
        cls.product_b, cls.location_b = build("RptProdScope Product B", "b.rptprodscope.example.com")

        # A superuser, so authorization is not what limits the report here. The
        # only thing that should scope it is the product named in the URL.
        cls.admin = User.objects.create(
            username="rptprodscope_admin", is_superuser=True, is_staff=True, is_active=True,
        )

    def _report_locations(self, product):
        self.client.force_login(self.admin)
        response = self.client.get(
            reverse("product_endpoint_report", args=(product.id,)),
            {"_generate": "", "report_type": "HTML"},
        )
        self.assertEqual(response.status_code, 200)
        return {location.id for location in response.context["endpoints"]}

    def test_report_excludes_other_products_locations(self):
        returned = self._report_locations(self.product_a)
        self.assertIn(self.location_a.id, returned)
        self.assertNotIn(self.location_b.id, returned)

    def test_report_for_the_other_product_is_scoped_too(self):
        returned = self._report_locations(self.product_b)
        self.assertIn(self.location_b.id, returned)
        self.assertNotIn(self.location_a.id, returned)

    def test_report_omits_locations_with_no_active_finding(self):
        quiet = URL.get_or_create_from_values(
            protocol="https", host="quiet.rptprodscope.example.com", path="app",
        ).location
        quiet.associate_with_product(self.product_a)
        self.assertNotIn(quiet.id, self._report_locations(self.product_a))
        # Guard the join: adding the product filter must not widen the queryset
        # to locations that have no active finding.
        self.assertTrue(Location.objects.filter(id=quiet.id).exists())
