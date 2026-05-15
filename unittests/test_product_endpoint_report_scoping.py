from django.test import Client
from django.utils.timezone import now

from dojo.authorization.roles_permissions import Roles
from dojo.models import (
    Endpoint,
    Endpoint_Status,
    Engagement,
    Finding,
    Product,
    Product_Member,
    Product_Type,
    Role,
    Test,
    Test_Type,
    User,
)
from unittests.dojo_test_case import DojoTestCase, skip_unless_v2


@skip_unless_v2
class TestProductEndpointReportScoping(DojoTestCase):

    """
    The legacy `product_endpoint_report` view must only return endpoints and
    findings belonging to the requested product. Previously the Endpoint
    queryset was filtered by finding flags only and not scoped by product,
    so an unrelated product's findings appeared in the report.
    """

    fixtures = ["dojo_testdata.json"]

    MARKER_A = "PRODUCT_A_UNIQUE_MARKER_b3c8aa1f"
    MARKER_B = "PRODUCT_B_UNIQUE_MARKER_d9e2bc54"

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.get(username="admin")
        cls.prod_type, _ = Product_Type.objects.get_or_create(name="Scoping Test PT")
        cls.test_type, _ = Test_Type.objects.get_or_create(name="Scoping Test Scan")

        cls.product_a = Product.objects.create(
            name="Scoping Test Product A",
            description=cls.MARKER_A,
            prod_type=cls.prod_type,
        )
        cls.product_b = Product.objects.create(
            name="Scoping Test Product B",
            description=cls.MARKER_B,
            prod_type=cls.prod_type,
        )

        cls.finding_a = cls._create_finding_with_endpoint(
            cls.product_a, "Finding for A", cls.MARKER_A, host="a.example.com",
        )
        cls.finding_b = cls._create_finding_with_endpoint(
            cls.product_b, "Finding for B", cls.MARKER_B, host="b.example.com",
        )

        cls.restricted_user = User.objects.create_user(
            username="report_scoping_reader",
            password="not-a-real-secret",  # noqa: S106 - test fixture user
        )
        reader_role = Role.objects.get(id=Roles.Reader)
        Product_Member.objects.create(
            user=cls.restricted_user,
            product=cls.product_a,
            role=reader_role,
        )

    @classmethod
    def _create_finding_with_endpoint(cls, product, title, description, *, host):
        engagement = Engagement.objects.create(
            name=f"{product.name} Engagement",
            product=product,
            target_start=now(),
            target_end=now(),
        )
        test = Test.objects.create(
            engagement=engagement,
            test_type=cls.test_type,
            title=f"{product.name} Test",
            target_start=now(),
            target_end=now(),
        )
        finding = Finding.objects.create(
            test=test,
            title=title,
            description=description,
            severity="High",
            numerical_severity="S0",
            active=True,
            verified=True,
            false_p=False,
            duplicate=False,
            out_of_scope=False,
            mitigated=None,
            reporter=cls.user,
        )
        endpoint = Endpoint.objects.create(
            host=host,
            protocol="https",
            product=product,
        )
        Endpoint_Status.objects.create(
            endpoint=endpoint,
            finding=finding,
            mitigated=False,
            false_positive=False,
            out_of_scope=False,
            risk_accepted=False,
        )
        finding.endpoints.add(endpoint)
        return finding

    def setUp(self):
        super().setUp()
        self.client = Client()
        self.client.force_login(self.user)

    def test_product_endpoint_report_only_includes_target_product_findings(self):
        url = f"/product/{self.product_a.id}/endpoint/report?_generate=1&report_type=HTML"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.content[:500])
        body = response.content.decode()

        self.assertIn(self.MARKER_A, body, "Expected Product A's finding description in report")
        self.assertNotIn(
            self.MARKER_B,
            body,
            "Product B's finding description must not appear in Product A's report",
        )

    def test_product_b_report_only_includes_product_b_findings(self):
        url = f"/product/{self.product_b.id}/endpoint/report?_generate=1&report_type=HTML"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.content[:500])
        body = response.content.decode()

        self.assertIn(self.MARKER_B, body)
        self.assertNotIn(self.MARKER_A, body)

    def test_reports_findings_only_includes_user_authorized_findings(self):
        # /reports/findings was previously unscoped; a Reader on Product A should
        # see Product A's findings only. The template renders the title, not
        # the description, so we assert against the unique titles.
        restricted_client = Client()
        restricted_client.force_login(self.restricted_user)
        response = restricted_client.get("/reports/findings")
        self.assertEqual(response.status_code, 200, response.content[:500])
        body = response.content.decode()
        self.assertIn("Finding for A", body)
        self.assertNotIn("Finding for B", body)

    def test_reports_endpoints_only_includes_user_authorized_endpoints(self):
        # /reports/endpoints was previously unscoped; a Reader on Product A
        # should only see Product A's endpoints.
        restricted_client = Client()
        restricted_client.force_login(self.restricted_user)
        response = restricted_client.get("/reports/endpoints")
        self.assertEqual(response.status_code, 200, response.content[:500])
        body = response.content.decode()
        self.assertIn("a.example.com", body)
        self.assertNotIn("b.example.com", body)
