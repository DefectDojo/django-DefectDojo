from django.utils.timezone import now

from dojo.authorization.roles_permissions import Permissions, Roles
from dojo.location.models import Location, LocationFindingReference, LocationProductReference
from dojo.location.queries import get_authorized_location_finding_reference
from dojo.location.status import FindingLocationStatus, ProductLocationStatus
from dojo.models import (
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
from unittests.dojo_test_case import DojoTestCase


class TestLocationFindingReferenceAuthorization(DojoTestCase):

    """
    `get_authorized_location_finding_reference` was anchoring authorization to
    Location.products (the set of products associated with the location).
    When two products share a location, a Reader on Product A could read
    LocationFindingReference rows for findings that belong to Product B.

    Authorization must be anchored to the finding's own product
    (finding.test.engagement.product), so this test sets up a shared location
    and verifies each Reader only sees their product's references.
    """

    fixtures = ["dojo_testdata.json"]

    @classmethod
    def setUpTestData(cls):
        prod_type, _ = Product_Type.objects.get_or_create(name="LocFRef PT")
        test_type, _ = Test_Type.objects.get_or_create(name="LocFRef Scan")
        reader_role = Role.objects.get(id=Roles.Reader)

        cls.product_a = Product.objects.create(
            name="LocFRef Product A",
            description="A",
            prod_type=prod_type,
        )
        cls.product_b = Product.objects.create(
            name="LocFRef Product B",
            description="B",
            prod_type=prod_type,
        )

        cls.alice = User.objects.create_user(
            username="locfref_alice",
            password="not-a-real-secret",  # noqa: S106 - test fixture user
        )
        cls.bob = User.objects.create_user(
            username="locfref_bob",
            password="not-a-real-secret",  # noqa: S106 - test fixture user
        )
        Product_Member.objects.create(user=cls.alice, product=cls.product_a, role=reader_role)
        Product_Member.objects.create(user=cls.bob, product=cls.product_b, role=reader_role)

        cls.finding_a = cls._make_finding(cls.product_a, test_type, title="Finding A")
        cls.finding_b = cls._make_finding(cls.product_b, test_type, title="Finding B")

        # Shared location across both products.
        cls.shared_location = Location.objects.create(
            location_type="URL",
            location_value="https://shared.example.com/",
        )
        LocationProductReference.objects.create(
            location=cls.shared_location,
            product=cls.product_a,
            status=ProductLocationStatus.Active,
        )
        LocationProductReference.objects.create(
            location=cls.shared_location,
            product=cls.product_b,
            status=ProductLocationStatus.Active,
        )
        cls.ref_a = LocationFindingReference.objects.create(
            location=cls.shared_location,
            finding=cls.finding_a,
            status=FindingLocationStatus.Active,
        )
        cls.ref_b = LocationFindingReference.objects.create(
            location=cls.shared_location,
            finding=cls.finding_b,
            status=FindingLocationStatus.Active,
        )

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
            title=f"{product.name} Test",
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

    def test_alice_sees_only_product_a_finding_references(self):
        results = list(
            get_authorized_location_finding_reference(
                Permissions.Location_View, user=self.alice,
            ).filter(location=self.shared_location),
        )
        result_ids = {ref.id for ref in results}
        self.assertEqual(result_ids, {self.ref_a.id})

    def test_bob_sees_only_product_b_finding_references(self):
        results = list(
            get_authorized_location_finding_reference(
                Permissions.Location_View, user=self.bob,
            ).filter(location=self.shared_location),
        )
        result_ids = {ref.id for ref in results}
        self.assertEqual(result_ids, {self.ref_b.id})

    def test_superuser_sees_both_finding_references(self):
        admin = User.objects.get(username="admin")
        results = list(
            get_authorized_location_finding_reference(
                Permissions.Location_View, user=admin,
            ).filter(location=self.shared_location),
        )
        result_ids = {ref.id for ref in results}
        self.assertEqual(result_ids, {self.ref_a.id, self.ref_b.id})
