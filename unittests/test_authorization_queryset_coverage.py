"""
Coverage matrix for the OS object-scoping auth-filter queries.

For every product-scoped filter, a non-staff user authorized on one product
(via authorized_users) must see only objects under that product, a user with
no access must see nothing, and a superuser must see everything. This is the
breadth guard that the earlier (superuser-only) coverage lacked — it would
have caught an allow-all `_for_queryset` regression on any of these filters.
"""

from unittest.mock import patch

from dojo.endpoint.queries import get_authorized_endpoint_status, get_authorized_endpoints
from dojo.engagement.queries import get_authorized_engagements
from dojo.finding.queries import (
    get_authorized_findings,
    get_authorized_findings_for_queryset,
)
from dojo.finding_group.queries import get_authorized_finding_groups
from dojo.models import Dojo_User, Endpoint, Finding, Test
from dojo.product.queries import (
    get_authorized_app_analysis,
    get_authorized_engagement_presets,
    get_authorized_languages,
    get_authorized_product_api_scan_configurations,
    get_authorized_products,
)
from dojo.product_type.queries import get_authorized_product_types
from dojo.risk_acceptance.queries import get_authorized_risk_acceptances
from dojo.test.queries import get_authorized_test_imports, get_authorized_tests
from dojo.vulnerability.queries import get_authorized_finding_vulnerability_references

from .dojo_test_case import DojoTestCase, skip_unless_v2, versioned_fixtures

_GCU = "dojo.authorization.query_registrations.get_current_user"


@versioned_fixtures
class TestAuthorizationQuerysetCoverage(DojoTestCase):

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.product = Test.objects.get(id=3).engagement.product
        self.scoped_user = Dojo_User.objects.create(username="cov_scoped", is_active=True)
        self.product.authorized_users.add(self.scoped_user)
        self.no_access_user = Dojo_User.objects.create(username="cov_noaccess", is_active=True)
        self.superuser = Dojo_User.objects.create(username="cov_super", is_active=True, is_superuser=True)
        # The fixture must have data outside the authorized product, otherwise
        # the "no leak" assertions would be vacuous.
        self.assertTrue(Finding.objects.exclude(test__engagement__product=self.product).exists())

    # (label, callable -> queryset, "<product id field on the result model>")
    @property
    def _cases(self):
        return [
            ("engagements", lambda: get_authorized_engagements("view"), "product__id"),
            ("tests", lambda: get_authorized_tests("view"), "engagement__product__id"),
            ("test_imports", lambda: get_authorized_test_imports("view"), "test__engagement__product__id"),
            ("risk_acceptances", lambda: get_authorized_risk_acceptances("view"), "engagement__product__id"),
            ("finding_groups", lambda: get_authorized_finding_groups("view"), "test__engagement__product__id"),
            ("findings", lambda: get_authorized_findings("view"), "test__engagement__product__id"),
            ("findings_for_queryset",
             lambda: get_authorized_findings_for_queryset("view", Finding.objects.all()),
             "test__engagement__product__id"),
            ("vulnerability_references", lambda: get_authorized_finding_vulnerability_references("view"),
             "finding__test__engagement__product__id"),
            ("app_analysis", lambda: get_authorized_app_analysis("view"), "product__id"),
            ("languages", lambda: get_authorized_languages("view"), "product__id"),
            ("engagement_presets", lambda: get_authorized_engagement_presets("view"), "product__id"),
            ("product_api_scan_configurations",
             lambda: get_authorized_product_api_scan_configurations("view"), "product__id"),
            ("products", lambda: get_authorized_products("view"), "id"),
        ]

    def test_scoped_user_sees_only_authorized_product(self):
        with patch(_GCU, return_value=self.scoped_user):
            for label, call, id_field in self._cases:
                with self.subTest(filter=label):
                    leaked = set(call().values_list(id_field, flat=True)) - {self.product.id}
                    self.assertEqual(leaked, set(), msg=f"{label} returned objects outside the authorized product")

    def test_no_access_user_sees_nothing(self):
        with patch(_GCU, return_value=self.no_access_user):
            for label, call, _ in self._cases:
                with self.subTest(filter=label):
                    self.assertEqual(call().count(), 0, msg=f"{label} leaked objects to an unauthorized user")

    def test_superuser_sees_everything(self):
        with patch(_GCU, return_value=self.superuser):
            for label, call, _ in self._cases:
                with self.subTest(filter=label):
                    qs = call()
                    self.assertEqual(
                        qs.count(), qs.model.objects.count(),
                        msg=f"{label} did not return all objects for a superuser",
                    )

    @skip_unless_v2
    def test_endpoints_scoping(self):
        # Endpoint is deprecated under V3 (Locations); exercise under V2 only.
        ep_in = Endpoint.objects.create(product=self.product, host="cov-in.example.com")
        other_product = Test.objects.exclude(engagement__product=self.product).first().engagement.product
        ep_out = Endpoint.objects.create(product=other_product, host="cov-out.example.com")

        with patch(_GCU, return_value=self.scoped_user):
            for label, call in [
                ("endpoints", lambda: get_authorized_endpoints("view")),
                ("endpoints_for_queryset", lambda: get_authorized_endpoints("view")),
            ]:
                with self.subTest(filter=label):
                    eps = call()
                    self.assertIn(ep_in, eps)
                    self.assertNotIn(ep_out, eps)

        with patch(_GCU, return_value=self.no_access_user):
            self.assertEqual(get_authorized_endpoints("view").count(), 0)
            self.assertEqual(get_authorized_endpoint_status("view").count(), 0)

        with patch(_GCU, return_value=self.superuser):
            self.assertEqual(get_authorized_endpoints("view").count(), Endpoint.objects.count())

    def test_product_types_scoping(self):
        # get_authorized_product_types keys off product_type.authorized_users, so
        # a product-only member sees none; a product-type member sees their type.
        with patch(_GCU, return_value=self.no_access_user):
            self.assertEqual(get_authorized_product_types("view").count(), 0)
        with patch(_GCU, return_value=self.superuser):
            self.assertEqual(
                get_authorized_product_types("view").count(),
                self.product.prod_type.__class__.objects.count(),
            )
        pt_user = Dojo_User.objects.create(username="cov_pt", is_active=True)
        self.product.prod_type.authorized_users.add(pt_user)
        with patch(_GCU, return_value=pt_user):
            pts = get_authorized_product_types("view")
            self.assertEqual(set(pts.values_list("id", flat=True)), {self.product.prod_type_id})
