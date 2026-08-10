from django.urls import reverse
from django.utils.timezone import now
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.authorization.roles_permissions import Roles
from dojo.models import (
    Dojo_User,
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
from unittests.dojo_test_case import DojoAPITestCase, skip_unless_v2


@skip_unless_v2
class EndpointStatusCrossProductAuthzTest(DojoAPITestCase):

    """Tests for the Endpoint_Status ViewSet permission checks."""

    fixtures = ["dojo_testdata.json"]

    @classmethod
    def setUpTestData(cls):
        prod_type, _ = Product_Type.objects.get_or_create(name="EPS-XProd PT")
        test_type, _ = Test_Type.objects.get_or_create(name="EPS-XProd Scan")
        writer_role = Role.objects.get(id=Roles.Writer)

        cls.product_a = Product.objects.create(
            name="EPS-XProd Product A",
            description="A",
            prod_type=prod_type,
        )
        cls.product_b = Product.objects.create(
            name="EPS-XProd Product B",
            description="B",
            prod_type=prod_type,
        )

        cls.alice = User.objects.create_user(
            username="eps_xprod_alice",
            password="not-a-real-secret",  # noqa: S106 - test fixture user
        )
        Product_Member.objects.create(user=cls.alice, product=cls.product_a, role=writer_role)
        # Legacy authorization is membership-based via authorized_users;
        # mirror the Product_Member row so the user can edit Product A.
        cls.product_a.authorized_users.add(Dojo_User.objects.get(pk=cls.alice.pk))

        cls.endpoint_a = Endpoint.objects.create(
            product=cls.product_a, protocol="http", host="a.example.com",
        )
        cls.endpoint_b = Endpoint.objects.create(
            product=cls.product_b, protocol="http", host="b.example.com",
        )

        cls.finding_a = cls._make_finding(cls.product_a, test_type, title="Finding A")
        cls.finding_b = cls._make_finding(cls.product_b, test_type, title="Finding B")

        cls.url = reverse("endpoint_status-list")

    @classmethod
    def _make_finding(cls, product, test_type, *, title):
        engagement = Engagement.objects.create(
            name=f"{product.name} Engagement",
            product=product,
            target_start=now(),
            target_end=now(),
        )
        test = Test.objects.create(
            engagement=engagement,
            test_type=test_type,
            target_start=now(),
            target_end=now(),
        )
        return Finding.objects.create(
            test=test,
            title=title,
            description=title,
            severity="High",
            numerical_severity="S0",
            active=True,
            verified=True,
        )

    def setUp(self):
        super().setUp()
        token, _ = Token.objects.get_or_create(user=self.alice)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)

    # ---------- create-time cross-product checks ----------

    def test_create_with_alice_endpoint_and_bob_finding_is_rejected(self):
        response = self.client.post(self.url, {
            "endpoint": self.endpoint_a.id,
            "finding": self.finding_b.id,
        })
        # Permission-layer denial: finding-side check should reject.
        self.assertIn(response.status_code, {403, 404}, response.content[:500])
        self.assertFalse(
            Endpoint_Status.objects.filter(
                endpoint=self.endpoint_a, finding=self.finding_b,
            ).exists(),
        )

    def test_create_with_both_in_alice_product_is_allowed(self):
        response = self.client.post(self.url, {
            "endpoint": self.endpoint_a.id,
            "finding": self.finding_a.id,
        })
        self.assertEqual(201, response.status_code, response.content[:500])

    # ---------- PATCH-time cross-product checks ----------

    def test_patch_cannot_move_row_into_bob_product(self):
        # Alice creates a legitimate row inside Product A.
        row = Endpoint_Status.objects.create(
            endpoint=self.endpoint_a, finding=self.finding_a,
        )
        relative = f"{self.url}{row.id}/"

        # Status-flag-only PATCH must still work.
        response = self.client.patch(relative, {"false_positive": True}, format="json")
        self.assertEqual(200, response.status_code, response.content[:500])

        # FK PATCH into Product B must be rejected (both endpoint+finding).
        response = self.client.patch(relative, {
            "endpoint": self.endpoint_b.id,
            "finding": self.finding_b.id,
            "false_positive": True,
            "out_of_scope": True,
            "risk_accepted": True,
        }, format="json")
        self.assertIn(response.status_code, {400, 403, 404}, response.content[:500])

        row.refresh_from_db()
        self.assertEqual(row.endpoint_id, self.endpoint_a.id)
        self.assertEqual(row.finding_id, self.finding_a.id)

    def test_patch_with_cross_product_finding_only_is_rejected(self):
        # Same-product baseline row.
        row = Endpoint_Status.objects.create(
            endpoint=self.endpoint_a, finding=self.finding_a,
        )
        relative = f"{self.url}{row.id}/"

        # Swapping just the finding into Product B should fail (mismatched products
        # or unauthorized target finding).
        response = self.client.patch(relative, {"finding": self.finding_b.id}, format="json")
        self.assertIn(response.status_code, {400, 403, 404}, response.content[:500])

        row.refresh_from_db()
        self.assertEqual(row.finding_id, self.finding_a.id)
