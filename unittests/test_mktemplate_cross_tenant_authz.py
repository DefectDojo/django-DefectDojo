from django.contrib.auth.models import Permission
from django.urls import reverse
from django.utils.timezone import now

from dojo.authorization.roles_permissions import Roles
from dojo.models import (
    Dojo_User,
    Engagement,
    Finding,
    Finding_Template,
    Product,
    Product_Member,
    Product_Type,
    Role,
    Test,
    Test_Type,
    User,
)
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures


@versioned_fixtures
class MkTemplateCrossTenantAuthzTest(DojoTestCase):

    """
    Regression tests for `mktemplate`. Making a finding into a global
    Finding_Template must require object-level view access to that finding and
    must not run on a GET. A user authorized on one product must not be able to
    copy another product's finding into globally scoped template storage.
    """

    fixtures = ["dojo_testdata.json"]

    @classmethod
    def setUpTestData(cls):
        pt_a, _ = Product_Type.objects.get_or_create(name="MKT-A PT")
        pt_b, _ = Product_Type.objects.get_or_create(name="MKT-B PT")
        test_type, _ = Test_Type.objects.get_or_create(name="MKT Scan")
        writer = Role.objects.get(id=Roles.Writer)

        cls.product_a = Product.objects.create(name="MKT Product A", description="A", prod_type=pt_a)
        cls.product_b = Product.objects.create(name="MKT Product B", description="B", prod_type=pt_b)

        cls.finding_a = cls._make_finding(cls.product_a, test_type, title="MKT own finding A")
        cls.finding_b = cls._make_finding(
            cls.product_b, test_type, title="MKT secret finding B",
            description="MKT_SECRET_BODY_B", severity="Critical",
        )

        # Attacker: non-staff, non-superuser, authorized on product A only, and
        # holding exactly the one configuration permission that satisfies the
        # global "add" gate (the reported carve-out).
        cls.attacker = User.objects.create_user(username="mkt_attacker", password="not-a-real-secret")  # noqa: S106
        cls.attacker.is_staff = False
        cls.attacker.is_superuser = False
        cls.attacker.save()
        cls.attacker.user_permissions.add(
            Permission.objects.get(content_type__app_label="dojo", codename="add_product_type"),
        )
        Product_Member.objects.create(user=cls.attacker, product=cls.product_a, role=writer)
        cls.product_a.authorized_users.add(Dojo_User.objects.get(pk=cls.attacker.pk))

    @classmethod
    def _make_finding(cls, product, test_type, *, title, description="body", severity="High"):
        eng = Engagement.objects.create(name=f"{product.name} Eng", product=product, target_start=now(), target_end=now())
        test = Test.objects.create(engagement=eng, test_type=test_type, target_start=now(), target_end=now())
        return Finding.objects.create(
            test=test, title=title, description=description,
            severity=severity, numerical_severity="S0", active=True,
        )

    def setUp(self):
        super().setUp()
        self.client.force_login(self.attacker)

    def test_get_is_rejected_and_creates_nothing(self):
        # The capture must not fire on a GET (require_POST), so a stored <img>
        # or top-level navigation carrying the victim's session cannot trigger it.
        before = Finding_Template.objects.count()
        response = self.client.get(reverse("mktemplate", args=(self.finding_b.id,)))
        self.assertEqual(response.status_code, 405)
        self.assertEqual(Finding_Template.objects.count(), before)

    def test_cross_tenant_post_denied_and_creates_nothing(self):
        # POST for a finding in product B (attacker has no access) must be
        # refused by the object-level check, and no template may be created.
        before = Finding_Template.objects.count()
        response = self.client.post(reverse("mktemplate", args=(self.finding_b.id,)))
        self.assertIn(response.status_code, {403, 400, 404}, response.content[:300])
        self.assertEqual(Finding_Template.objects.count(), before)
        self.assertFalse(Finding_Template.objects.filter(title=self.finding_b.title).exists())

    def test_own_finding_post_still_allowed(self):
        # The legitimate path must keep working: a user who can view a finding
        # and holds global "add" can still template their own finding.
        response = self.client.post(reverse("mktemplate", args=(self.finding_a.id,)))
        self.assertEqual(response.status_code, 302)
        self.assertTrue(Finding_Template.objects.filter(title=self.finding_a.title).exists())
