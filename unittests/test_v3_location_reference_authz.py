"""
Regression tests: the V3 location/endpoint reference write paths limit the
references a request may select to the objects the requesting user is authorized
for. Each test asserts an authorized reference is accepted and an unauthorized
one is rejected, for the Finding endpoints field, the import endpoint_to_add
field, and bulk-mitigate reference updates.
"""
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from django.utils.timezone import now
from rest_framework.exceptions import ValidationError as DRFValidationError
from rest_framework.test import APIRequestFactory

from dojo.api_v2.serializers import ImportScanSerializer
from dojo.authorization.roles_permissions import Roles
from dojo.location.models import (
    LocationFindingReference,
    LocationProductReference,
)
from dojo.location.status import FindingLocationStatus
from dojo.models import (
    Dojo_User,
    Engagement,
    Finding,
    Product,
    Product_Member,
    Product_Type,
    Role,
    Test,
    Test_Type,
)
from dojo.url.models import URL
from unittests.dojo_test_case import DojoAPITestCase, skip_unless_v3

GENERIC_FINDINGS = b'{"findings": [{"title": "probe", "severity": "Info", "description": "probe"}]}'


@skip_unless_v3
class V3LocationReferenceAuthzTests(DojoAPITestCase):

    """Two products, two users; each user is authorized only for their own product."""

    @classmethod
    def setUpTestData(cls):
        cls.pt = Product_Type.objects.create(name="v3_locref_pt")
        cls.product_a = Product.objects.create(name="v3_locref_a", description="a", prod_type=cls.pt)
        cls.product_b = Product.objects.create(name="v3_locref_b", description="b", prod_type=cls.pt)

        cls.user_a = Dojo_User.objects.create(username="v3_locref_user_a", is_active=True)
        cls.user_b = Dojo_User.objects.create(username="v3_locref_user_b", is_active=True)
        # Grant membership two ways so the test is authorization-backend agnostic:
        # legacy authorized_users (honored by the OS backend) and a Product_Member
        # Owner role (honored by the Pro backend).
        owner = Role.objects.get(id=Roles.Owner)
        for product, user in ((cls.product_a, cls.user_a), (cls.product_b, cls.user_b)):
            product.authorized_users.add(user)
            Product_Member.objects.create(product=product, user=user, role=owner)

        cls.test_type, _ = Test_Type.objects.get_or_create(name="v3_locref_scan")

        cls.finding_a = cls._make_finding(cls.product_a, cls.user_a, "finding_a")
        cls.engagement_a = cls.finding_a.test.engagement
        cls.finding_b = cls._make_finding(cls.product_b, cls.user_b, "finding_b")

        # A location on product_b (authorized only for user_b).
        url_b = URL.get_or_create_from_object(URL.from_value("https://b.example.test/x"))
        cls.lfr_b = url_b.location.associate_with_finding(cls.finding_b)
        cls.location_b = url_b.location

        # A location on product_a (authorized for user_a) for the accepted-case controls.
        cls.finding_a_extra = cls._make_finding(cls.product_a, cls.user_a, "finding_a_extra")
        url_a = URL.get_or_create_from_object(URL.from_value("https://a.example.test/ok"))
        cls.lfr_a = url_a.location.associate_with_finding(cls.finding_a_extra)
        cls.location_a = url_a.location

        # A location associated with both products, with an active reference from product_b.
        url_shared = URL.get_or_create_from_object(URL.from_value("https://shared.example.test/s"))
        cls.location_shared = url_shared.location
        cls.location_shared.associate_with_product(cls.product_a)
        cls.lfr_shared_b = LocationFindingReference.objects.create(
            location=cls.location_shared, finding=cls.finding_b, status=FindingLocationStatus.Active,
        )

    @classmethod
    def _make_finding(cls, product, user, title):
        engagement = Engagement.objects.create(name=title + "_eng", product=product, target_start=now(), target_end=now())
        test = Test.objects.create(engagement=engagement, test_type=cls.test_type, target_start=now(), target_end=now())
        return Finding.objects.create(
            test=test, title=title, description="x", severity="High",
            numerical_severity="S0", active=True, verified=True, reporter=user,
        )

    # Finding endpoints field
    def test_finding_endpoints_rejects_unauthorized_reference(self):
        self.client.force_authenticate(user=self.user_a)
        response = self.client.patch(
            reverse("finding-list") + f"{self.finding_a.id}/",
            {"endpoints": [self.lfr_b.id], "push_to_jira": False}, format="json", secure=True,
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(
            LocationProductReference.objects.filter(location=self.location_b, product=self.product_a).exists(),
        )

    def test_finding_endpoints_allows_authorized_reference(self):
        self.client.force_authenticate(user=self.user_a)
        response = self.client.patch(
            reverse("finding-list") + f"{self.finding_a.id}/",
            {"endpoints": [self.lfr_a.id], "push_to_jira": False}, format="json", secure=True,
        )
        self.assertEqual(response.status_code, 200)

    # import endpoint_to_add
    def test_import_endpoint_to_add_rejects_unauthorized_reference(self):
        self.client.force_authenticate(user=self.user_a)
        response = self.client.post(reverse("importscan-list"), {
            "engagement": self.engagement_a.id,
            "scan_type": "Generic Findings Import",
            "endpoint_to_add": self.location_b.id,
            "file": SimpleUploadedFile("s.json", GENERIC_FINDINGS, content_type="application/json"),
        }, secure=True)
        self.assertEqual(response.status_code, 400)
        self.assertFalse(
            LocationProductReference.objects.filter(location=self.location_b, product=self.product_a).exists(),
        )

    def test_import_endpoint_to_add_allows_authorized_reference(self):
        # Checked at the field level so the assertion is about the queryset scoping,
        # not the downstream import pipeline.
        request = APIRequestFactory().post(reverse("importscan-list"))
        request.user = self.user_a
        field = ImportScanSerializer(context={"request": request}).fields["endpoint_to_add"]
        self.assertEqual(field.to_internal_value(self.location_a.id), self.location_a)
        with self.assertRaises(DRFValidationError):
            field.to_internal_value(self.location_b.id)

    # bulk mitigate reference updates
    def test_bulk_mitigate_scopes_reference_updates(self):
        self.client.force_login(self.user_a)
        response = self.client.post(
            reverse("endpoints_bulk_update_all_product", args=(self.product_a.id,)),
            data={"endpoints_to_update": self.location_shared.id}, secure=True,
        )
        self.assertIn(response.status_code, (200, 302))
        self.lfr_shared_b.refresh_from_db()
        # A reference outside the acting product is left unchanged.
        self.assertEqual(self.lfr_shared_b.status, FindingLocationStatus.Active)
