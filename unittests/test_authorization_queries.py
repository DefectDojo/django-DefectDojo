"""
Unit tests for get_authorized_*() query functions.

Tests the query functions that filter querysets based on user permissions.
These tests verify that the authorization queries return correct results
for various user permission scenarios.
"""
from unittest.mock import patch

from django.conf import settings
from django.utils import timezone

from dojo.authorization.roles_permissions import Permissions
from dojo.endpoint.queries import get_authorized_endpoint_status, get_authorized_endpoints
from dojo.engagement.queries import get_authorized_engagements
from dojo.finding.queries import (
    get_authorized_findings,
    get_authorized_findings_for_queryset,
    get_authorized_stub_findings,
    get_authorized_vulnerability_ids,
)
from dojo.finding_group.queries import get_authorized_finding_groups
from dojo.group.queries import get_authorized_groups
from dojo.location.models import LocationFindingReference, LocationProductReference
from dojo.location.queries import (
    get_authorized_location_finding_reference,
    get_authorized_location_product_reference,
    get_authorized_locations,
)
from dojo.models import (
    Dojo_Group,
    Dojo_Group_Member,
    Dojo_User,
    Endpoint,
    Endpoint_Status,
    Engagement,
    Finding,
    Finding_Group,
    Global_Role,
    Product,
    Product_Group,
    Product_Member,
    Product_Type,
    Product_Type_Group,
    Product_Type_Member,
    Role,
    Stub_Finding,
    Test,
    Test_Type,
    Vulnerability_Id,
)
from dojo.product.queries import get_authorized_products
from dojo.product_type.queries import get_authorized_product_types
from dojo.test.queries import get_authorized_tests
from dojo.url.models import URL

from .dojo_test_case import DojoTestCase, skip_unless_v2, skip_unless_v3


class AuthorizationQueriesTestBase(DojoTestCase):

    """Base class with common test data setup for authorization query tests."""

    @classmethod
    def setUpTestData(cls):
        # Create roles reference
        cls.reader_role = Role.objects.get(name="Reader")
        cls.writer_role = Role.objects.get(name="Writer")
        cls.owner_role = Role.objects.get(name="Owner")

        # Get or create test users - use get_or_create to avoid duplicates
        cls.superuser, _ = Dojo_User.objects.get_or_create(
            username="auth_test_superuser",
            defaults={"is_superuser": True, "is_active": True},
        )
        cls.superuser.is_superuser = True
        cls.superuser.save()

        cls.user_no_perms, _ = Dojo_User.objects.get_or_create(
            username="auth_test_no_perms",
            defaults={"is_active": True},
        )
        cls.user_global_reader, _ = Dojo_User.objects.get_or_create(
            username="auth_test_global_reader",
            defaults={"is_active": True},
        )
        cls.user_product_member, _ = Dojo_User.objects.get_or_create(
            username="auth_test_product_member",
            defaults={"is_active": True},
        )
        cls.user_product_type_member, _ = Dojo_User.objects.get_or_create(
            username="auth_test_product_type_member",
            defaults={"is_active": True},
        )
        cls.user_group_product_member, _ = Dojo_User.objects.get_or_create(
            username="auth_test_group_product_member",
            defaults={"is_active": True},
        )
        cls.user_group_product_type_member, _ = Dojo_User.objects.get_or_create(
            username="auth_test_group_product_type_member",
            defaults={"is_active": True},
        )

        # Create global role for global reader (get_or_create to avoid duplicates)
        Global_Role.objects.get_or_create(
            user=cls.user_global_reader,
            defaults={"role": cls.reader_role},
        )

        # Create product types
        cls.product_type_1, _ = Product_Type.objects.get_or_create(name="Auth Test PT 1")
        cls.product_type_2, _ = Product_Type.objects.get_or_create(name="Auth Test PT 2")

        # Create products
        cls.product_1, _ = Product.objects.get_or_create(
            name="Auth Test Product 1",
            description="Test",
            defaults={"prod_type": cls.product_type_1},
        )
        cls.product_2, _ = Product.objects.get_or_create(
            name="Auth Test Product 2",
            description="Test",
            defaults={"prod_type": cls.product_type_2},
        )

        # Create product membership for user_product_member (only to product_1)
        Product_Member.objects.get_or_create(
            user=cls.user_product_member,
            product=cls.product_1,
            defaults={"role": cls.reader_role},
        )

        # Create product type membership for user_product_type_member (only to product_type_1)
        Product_Type_Member.objects.get_or_create(
            user=cls.user_product_type_member,
            product_type=cls.product_type_1,
            defaults={"role": cls.reader_role},
        )

        # Create groups for group-based access
        cls.group_product, _ = Dojo_Group.objects.get_or_create(name="Auth Test Group Product")
        cls.group_product_type, _ = Dojo_Group.objects.get_or_create(name="Auth Test Group Product Type")

        # Add users to groups
        Dojo_Group_Member.objects.get_or_create(
            user=cls.user_group_product_member,
            group=cls.group_product,
            defaults={"role": cls.reader_role},
        )
        Dojo_Group_Member.objects.get_or_create(
            user=cls.user_group_product_type_member,
            group=cls.group_product_type,
            defaults={"role": cls.reader_role},
        )

        # Create product group membership (group_product -> product_1)
        Product_Group.objects.get_or_create(
            product=cls.product_1,
            group=cls.group_product,
            defaults={"role": cls.reader_role},
        )

        # Create product type group membership (group_product_type -> product_type_1)
        Product_Type_Group.objects.get_or_create(
            product_type=cls.product_type_1,
            group=cls.group_product_type,
            defaults={"role": cls.reader_role},
        )

        # Create test type
        cls.test_type, _ = Test_Type.objects.get_or_create(name="Auth Test Type")

        # Create engagements
        cls.engagement_1, _ = Engagement.objects.get_or_create(
            name="Auth Test Engagement 1",
            product=cls.product_1,
            defaults={
                "target_start": timezone.now(),
                "target_end": timezone.now(),
            },
        )
        cls.engagement_2, _ = Engagement.objects.get_or_create(
            name="Auth Test Engagement 2",
            product=cls.product_2,
            defaults={
                "target_start": timezone.now(),
                "target_end": timezone.now(),
            },
        )

        # Create tests
        cls.test_1, _ = Test.objects.get_or_create(
            engagement=cls.engagement_1,
            test_type=cls.test_type,
            defaults={
                "target_start": timezone.now(),
                "target_end": timezone.now(),
            },
        )
        cls.test_2, _ = Test.objects.get_or_create(
            engagement=cls.engagement_2,
            test_type=cls.test_type,
            defaults={
                "target_start": timezone.now(),
                "target_end": timezone.now(),
            },
        )

        # Create findings - reporter is required
        cls.finding_1, _ = Finding.objects.get_or_create(
            test=cls.test_1,
            title="Auth Test Finding 1",
            defaults={
                "severity": "High",
                "active": True,
                "verified": True,
                "numerical_severity": "S1",
                "reporter": cls.superuser,
            },
        )
        cls.finding_2, _ = Finding.objects.get_or_create(
            test=cls.test_2,
            title="Auth Test Finding 2",
            defaults={
                "severity": "Medium",
                "active": True,
                "verified": True,
                "numerical_severity": "S2",
                "reporter": cls.superuser,
            },
        )

        # Create stub findings - reporter is required
        cls.stub_finding_1, _ = Stub_Finding.objects.get_or_create(
            test=cls.test_1,
            title="Auth Test Stub Finding 1",
            defaults={
                "severity": "High",
                "reporter": cls.superuser,
            },
        )
        cls.stub_finding_2, _ = Stub_Finding.objects.get_or_create(
            test=cls.test_2,
            title="Auth Test Stub Finding 2",
            defaults={
                "severity": "Medium",
                "reporter": cls.superuser,
            },
        )

        # Create vulnerability IDs
        cls.vuln_id_1, _ = Vulnerability_Id.objects.get_or_create(
            finding=cls.finding_1,
            vulnerability_id="CVE-2024-0001",
        )
        cls.vuln_id_2, _ = Vulnerability_Id.objects.get_or_create(
            finding=cls.finding_2,
            vulnerability_id="CVE-2024-0002",
        )

        if settings.V3_FEATURE_LOCATIONS:
            # Create locations
            cls.url_1 = URL.get_or_create_from_values(
                host="auth-test-1.example.com",
            )
            cls.location_finding_ref_1, _ = LocationFindingReference.objects.get_or_create(
                location=cls.url_1.location,
                finding=cls.finding_1,
            )
            cls.location_product_ref_1, _ = LocationProductReference.objects.get_or_create(
                location=cls.url_1.location,
                product=cls.product_1,
            )
            cls.url_2 = URL.get_or_create_from_values(
                host="auth-test-2.example.com",
            )
            cls.location_finding_ref_2, _ = LocationFindingReference.objects.get_or_create(
                location=cls.url_2.location,
                finding=cls.finding_2,
            )
            cls.location_product_ref_2, _ = LocationProductReference.objects.get_or_create(
                location=cls.url_2.location,
                product=cls.product_2,
            )
        else:
            # TODO: Delete this after the move to Locations
            # Create endpoints
            cls.endpoint_1, _ = Endpoint.objects.get_or_create(
                product=cls.product_1,
                host="auth-test-1.example.com",
            )
            cls.endpoint_2, _ = Endpoint.objects.get_or_create(
                product=cls.product_2,
                host="auth-test-2.example.com",
            )

            # Create endpoint statuses
            cls.endpoint_status_1, _ = Endpoint_Status.objects.get_or_create(
                endpoint=cls.endpoint_1,
                finding=cls.finding_1,
            )
            cls.endpoint_status_2, _ = Endpoint_Status.objects.get_or_create(
                endpoint=cls.endpoint_2,
                finding=cls.finding_2,
            )


class TestGetAuthorizedFindings(AuthorizationQueriesTestBase):

    """Tests for get_authorized_findings()"""

    def test_superuser_gets_all_findings(self):
        """Superuser should get all findings"""
        findings = get_authorized_findings(Permissions.Finding_View, user=self.superuser)
        self.assertIn(self.finding_1, findings)
        self.assertIn(self.finding_2, findings)

    def test_user_no_permissions_gets_empty(self):
        """User with no permissions should not get test findings"""
        findings = get_authorized_findings(Permissions.Finding_View, user=self.user_no_perms)
        self.assertNotIn(self.finding_1, findings)
        self.assertNotIn(self.finding_2, findings)

    def test_user_global_reader_gets_all(self):
        """User with global reader role should get all findings"""
        findings = get_authorized_findings(Permissions.Finding_View, user=self.user_global_reader)
        self.assertIn(self.finding_1, findings)
        self.assertIn(self.finding_2, findings)

    def test_user_product_member_gets_product_findings(self):
        """User with product membership should get only that product's findings"""
        findings = get_authorized_findings(Permissions.Finding_View, user=self.user_product_member)
        self.assertIn(self.finding_1, findings)
        self.assertNotIn(self.finding_2, findings)

    def test_user_product_type_member_gets_product_type_findings(self):
        """User with product type membership should get all findings in that product type"""
        findings = get_authorized_findings(Permissions.Finding_View, user=self.user_product_type_member)
        self.assertIn(self.finding_1, findings)
        self.assertNotIn(self.finding_2, findings)

    def test_user_group_product_member_gets_group_findings(self):
        """User in group with product access should get those findings"""
        findings = get_authorized_findings(Permissions.Finding_View, user=self.user_group_product_member)
        self.assertIn(self.finding_1, findings)
        self.assertNotIn(self.finding_2, findings)

    def test_user_group_product_type_member_gets_group_findings(self):
        """User in group with product type access should get those findings"""
        findings = get_authorized_findings(Permissions.Finding_View, user=self.user_group_product_type_member)
        self.assertIn(self.finding_1, findings)
        self.assertNotIn(self.finding_2, findings)

    def test_queryset_parameter_filters_correctly(self):
        """Passing a queryset should filter within that queryset"""
        base_queryset = Finding.objects.filter(severity="High")
        findings = get_authorized_findings_for_queryset(Permissions.Finding_View, base_queryset, user=self.superuser)
        self.assertIn(self.finding_1, findings)
        self.assertNotIn(self.finding_2, findings)

    def test_none_user_returns_empty(self):
        """None user should return empty queryset"""
        with patch("dojo.finding.queries.get_current_user", return_value=None):
            findings = get_authorized_findings(Permissions.Finding_View)
            self.assertEqual(findings.count(), 0)


class TestGetAuthorizedStubFindings(AuthorizationQueriesTestBase):

    """Tests for get_authorized_stub_findings() - uses get_current_user()"""

    @patch("dojo.finding.queries.get_current_user")
    def test_superuser_gets_all_stub_findings(self, mock_get_current_user):
        """Superuser should get all stub findings"""
        mock_get_current_user.return_value = self.superuser
        stub_findings = get_authorized_stub_findings(Permissions.Finding_View)
        self.assertIn(self.stub_finding_1, stub_findings)
        self.assertIn(self.stub_finding_2, stub_findings)

    @patch("dojo.finding.queries.get_current_user")
    def test_user_no_permissions_gets_empty(self, mock_get_current_user):
        """User with no permissions should not get test stub findings"""
        mock_get_current_user.return_value = self.user_no_perms
        stub_findings = get_authorized_stub_findings(Permissions.Finding_View)
        self.assertNotIn(self.stub_finding_1, stub_findings)
        self.assertNotIn(self.stub_finding_2, stub_findings)

    @patch("dojo.finding.queries.get_current_user")
    def test_user_product_member_gets_product_stub_findings(self, mock_get_current_user):
        """User with product membership should get only that product's stub findings"""
        mock_get_current_user.return_value = self.user_product_member
        stub_findings = get_authorized_stub_findings(Permissions.Finding_View)
        self.assertIn(self.stub_finding_1, stub_findings)
        self.assertNotIn(self.stub_finding_2, stub_findings)


class TestGetAuthorizedVulnerabilityIds(AuthorizationQueriesTestBase):

    """Tests for get_authorized_vulnerability_ids()"""

    def test_superuser_gets_all_vulnerability_ids(self):
        """Superuser should get all vulnerability IDs"""
        vuln_ids = get_authorized_vulnerability_ids(Permissions.Finding_View, user=self.superuser)
        self.assertIn(self.vuln_id_1, vuln_ids)
        self.assertIn(self.vuln_id_2, vuln_ids)

    def test_user_no_permissions_gets_empty(self):
        """User with no permissions should not get test vulnerability IDs"""
        vuln_ids = get_authorized_vulnerability_ids(Permissions.Finding_View, user=self.user_no_perms)
        self.assertNotIn(self.vuln_id_1, vuln_ids)
        self.assertNotIn(self.vuln_id_2, vuln_ids)

    def test_user_product_member_gets_product_vulnerability_ids(self):
        """User with product membership should get only that product's vulnerability IDs"""
        vuln_ids = get_authorized_vulnerability_ids(Permissions.Finding_View, user=self.user_product_member)
        self.assertIn(self.vuln_id_1, vuln_ids)
        self.assertNotIn(self.vuln_id_2, vuln_ids)


class TestGetAuthorizedProducts(AuthorizationQueriesTestBase):

    """Tests for get_authorized_products()"""

    def test_superuser_gets_all_products(self):
        """Superuser should get all products"""
        products = get_authorized_products(Permissions.Product_View, user=self.superuser)
        self.assertIn(self.product_1, products)
        self.assertIn(self.product_2, products)

    def test_user_no_permissions_gets_empty(self):
        """User with no permissions should not get test products"""
        products = get_authorized_products(Permissions.Product_View, user=self.user_no_perms)
        self.assertNotIn(self.product_1, products)
        self.assertNotIn(self.product_2, products)

    def test_user_global_reader_gets_all(self):
        """User with global reader role should get all products"""
        products = get_authorized_products(Permissions.Product_View, user=self.user_global_reader)
        self.assertIn(self.product_1, products)
        self.assertIn(self.product_2, products)

    def test_user_product_member_gets_own_products(self):
        """User with product membership should get only that product"""
        products = get_authorized_products(Permissions.Product_View, user=self.user_product_member)
        self.assertIn(self.product_1, products)
        self.assertNotIn(self.product_2, products)

    def test_user_product_type_member_gets_type_products(self):
        """User with product type membership should get products in that type"""
        products = get_authorized_products(Permissions.Product_View, user=self.user_product_type_member)
        self.assertIn(self.product_1, products)
        self.assertNotIn(self.product_2, products)

    def test_user_group_product_member_gets_group_products(self):
        """User in group with product access should get those products"""
        products = get_authorized_products(Permissions.Product_View, user=self.user_group_product_member)
        self.assertIn(self.product_1, products)
        self.assertNotIn(self.product_2, products)

    def test_user_group_product_type_member_gets_group_products(self):
        """User in group with product type access should get products in that type"""
        products = get_authorized_products(Permissions.Product_View, user=self.user_group_product_type_member)
        self.assertIn(self.product_1, products)
        self.assertNotIn(self.product_2, products)


class TestGetAuthorizedProductTypes(AuthorizationQueriesTestBase):

    """Tests for get_authorized_product_types() - uses get_current_user()"""

    @patch("dojo.product_type.queries.get_current_user")
    def test_superuser_gets_all_product_types(self, mock_get_current_user):
        """Superuser should get all product types"""
        mock_get_current_user.return_value = self.superuser
        product_types = get_authorized_product_types(Permissions.Product_Type_View)
        self.assertIn(self.product_type_1, product_types)
        self.assertIn(self.product_type_2, product_types)

    @patch("dojo.product_type.queries.get_current_user")
    def test_user_no_permissions_gets_empty(self, mock_get_current_user):
        """User with no permissions should not get test product types"""
        mock_get_current_user.return_value = self.user_no_perms
        product_types = get_authorized_product_types(Permissions.Product_Type_View)
        self.assertNotIn(self.product_type_1, product_types)
        self.assertNotIn(self.product_type_2, product_types)

    @patch("dojo.product_type.queries.get_current_user")
    def test_user_global_reader_gets_all(self, mock_get_current_user):
        """User with global reader role should get all product types"""
        mock_get_current_user.return_value = self.user_global_reader
        product_types = get_authorized_product_types(Permissions.Product_Type_View)
        self.assertIn(self.product_type_1, product_types)
        self.assertIn(self.product_type_2, product_types)

    @patch("dojo.product_type.queries.get_current_user")
    def test_user_product_type_member_gets_own_types(self, mock_get_current_user):
        """User with product type membership should get only that type"""
        mock_get_current_user.return_value = self.user_product_type_member
        product_types = get_authorized_product_types(Permissions.Product_Type_View)
        self.assertIn(self.product_type_1, product_types)
        self.assertNotIn(self.product_type_2, product_types)

    @patch("dojo.product_type.queries.get_current_user")
    def test_user_group_product_type_member_gets_group_types(self, mock_get_current_user):
        """User in group with product type access should get that type"""
        mock_get_current_user.return_value = self.user_group_product_type_member
        product_types = get_authorized_product_types(Permissions.Product_Type_View)
        self.assertIn(self.product_type_1, product_types)
        self.assertNotIn(self.product_type_2, product_types)


class TestGetAuthorizedEngagements(AuthorizationQueriesTestBase):

    """Tests for get_authorized_engagements() - uses get_current_user()"""

    @patch("dojo.engagement.queries.get_current_user")
    def test_superuser_gets_all_engagements(self, mock_get_current_user):
        """Superuser should get all engagements"""
        mock_get_current_user.return_value = self.superuser
        engagements = get_authorized_engagements(Permissions.Engagement_View)
        self.assertIn(self.engagement_1, engagements)
        self.assertIn(self.engagement_2, engagements)

    @patch("dojo.engagement.queries.get_current_user")
    def test_user_no_permissions_gets_empty(self, mock_get_current_user):
        """User with no permissions should not get test engagements"""
        mock_get_current_user.return_value = self.user_no_perms
        engagements = get_authorized_engagements(Permissions.Engagement_View)
        self.assertNotIn(self.engagement_1, engagements)
        self.assertNotIn(self.engagement_2, engagements)

    @patch("dojo.engagement.queries.get_current_user")
    def test_user_global_reader_gets_all(self, mock_get_current_user):
        """User with global reader role should get all engagements"""
        mock_get_current_user.return_value = self.user_global_reader
        engagements = get_authorized_engagements(Permissions.Engagement_View)
        self.assertIn(self.engagement_1, engagements)
        self.assertIn(self.engagement_2, engagements)

    @patch("dojo.engagement.queries.get_current_user")
    def test_user_product_member_gets_product_engagements(self, mock_get_current_user):
        """User with product membership should get only that product's engagements"""
        mock_get_current_user.return_value = self.user_product_member
        engagements = get_authorized_engagements(Permissions.Engagement_View)
        self.assertIn(self.engagement_1, engagements)
        self.assertNotIn(self.engagement_2, engagements)

    @patch("dojo.engagement.queries.get_current_user")
    def test_user_product_type_member_gets_product_type_engagements(self, mock_get_current_user):
        """User with product type membership should get engagements in that type"""
        mock_get_current_user.return_value = self.user_product_type_member
        engagements = get_authorized_engagements(Permissions.Engagement_View)
        self.assertIn(self.engagement_1, engagements)
        self.assertNotIn(self.engagement_2, engagements)


class TestGetAuthorizedTests(AuthorizationQueriesTestBase):

    """Tests for get_authorized_tests() - uses get_current_user()"""

    @patch("dojo.test.queries.get_current_user")
    def test_superuser_gets_all_tests(self, mock_get_current_user):
        """Superuser should get all tests"""
        mock_get_current_user.return_value = self.superuser
        tests = get_authorized_tests(Permissions.Test_View)
        self.assertIn(self.test_1, tests)
        self.assertIn(self.test_2, tests)

    @patch("dojo.test.queries.get_current_user")
    def test_user_no_permissions_gets_empty(self, mock_get_current_user):
        """User with no permissions should not get test tests"""
        mock_get_current_user.return_value = self.user_no_perms
        tests = get_authorized_tests(Permissions.Test_View)
        self.assertNotIn(self.test_1, tests)
        self.assertNotIn(self.test_2, tests)

    @patch("dojo.test.queries.get_current_user")
    def test_user_product_member_gets_product_tests(self, mock_get_current_user):
        """User with product membership should get only that product's tests"""
        mock_get_current_user.return_value = self.user_product_member
        tests = get_authorized_tests(Permissions.Test_View)
        self.assertIn(self.test_1, tests)
        self.assertNotIn(self.test_2, tests)


@skip_unless_v3
class TestGetAuthorizedLocations(AuthorizationQueriesTestBase):

    """Tests for get_authorized_locations()"""

    def test_superuser_gets_all_locations(self):
        """Superuser should get all locations"""
        locations = get_authorized_locations(Permissions.Location_View, user=self.superuser)
        self.assertIn(self.url_1.location, locations)
        self.assertIn(self.url_2.location, locations)

    def test_user_no_permissions_gets_empty(self):
        """User with no permissions should not get test locations"""
        locations = get_authorized_locations(Permissions.Location_View, user=self.user_no_perms)
        self.assertNotIn(self.url_1.location, locations)
        self.assertNotIn(self.url_2.location, locations)

    def test_user_product_member_gets_product_locations(self):
        """User with product membership should get only that product's endpoints"""
        locations = get_authorized_locations(Permissions.Location_View, user=self.user_product_member)
        self.assertIn(self.url_1.location, locations)
        self.assertNotIn(self.url_2.location, locations)


@skip_unless_v3
class TestGetAuthorizedLocationFindingReferences(AuthorizationQueriesTestBase):

    """Tests for get_authorized_location_finding_reference()"""

    def test_superuser_gets_all_location_finding_references(self):
        """Superuser should get all location finding references"""
        finding_refs = get_authorized_location_finding_reference(Permissions.Location_View, user=self.superuser)
        self.assertIn(self.location_finding_ref_1, finding_refs)
        self.assertIn(self.location_finding_ref_2, finding_refs)

    def test_user_no_permissions_gets_empty(self):
        """User with no permissions should get no location finding references"""
        finding_refs = get_authorized_location_finding_reference(Permissions.Location_View, user=self.user_no_perms)
        self.assertNotIn(self.location_finding_ref_1, finding_refs)
        self.assertNotIn(self.location_finding_ref_2, finding_refs)

    def test_user_product_member_gets_product_location_finding_references(self):
        """User with product membership should get only that product's finding references"""
        finding_refs = get_authorized_location_finding_reference(Permissions.Location_View, user=self.user_product_member)
        self.assertIn(self.location_finding_ref_1, finding_refs)
        self.assertNotIn(self.location_finding_ref_2, finding_refs)


@skip_unless_v3
class TestGetAuthorizedLocationProductReferences(AuthorizationQueriesTestBase):

    """Tests for get_authorized_location_product_reference()"""

    def test_superuser_gets_all_location_finding_references(self):
        """Superuser should get all location product references"""
        product_refs = get_authorized_location_product_reference(Permissions.Location_View, user=self.superuser)
        self.assertIn(self.location_product_ref_1, product_refs)
        self.assertIn(self.location_product_ref_2, product_refs)

    def test_user_no_permissions_gets_empty(self):
        """User with no permissions should get no location finding references"""
        product_refs = get_authorized_location_product_reference(Permissions.Location_View, user=self.user_no_perms)
        self.assertNotIn(self.location_product_ref_1, product_refs)
        self.assertNotIn(self.location_product_ref_2, product_refs)

    def test_user_product_member_gets_product_location_product_references(self):
        """User with product membership should get only that product's location product references"""
        product_refs = get_authorized_location_product_reference(Permissions.Location_View, user=self.user_product_member)
        self.assertIn(self.location_product_ref_1, product_refs)
        self.assertNotIn(self.location_product_ref_2, product_refs)


# TODO: Delete this after the move to Locations
@skip_unless_v2
class TestGetAuthorizedEndpoints(AuthorizationQueriesTestBase):

    """Tests for get_authorized_endpoints()"""

    def test_superuser_gets_all_endpoints(self):
        """Superuser should get all endpoints"""
        endpoints = get_authorized_endpoints(Permissions.Location_View, user=self.superuser)
        self.assertIn(self.endpoint_1, endpoints)
        self.assertIn(self.endpoint_2, endpoints)

    def test_user_no_permissions_gets_empty(self):
        """User with no permissions should not get test endpoints"""
        endpoints = get_authorized_endpoints(Permissions.Location_View, user=self.user_no_perms)
        self.assertNotIn(self.endpoint_1, endpoints)
        self.assertNotIn(self.endpoint_2, endpoints)

    def test_user_product_member_gets_product_endpoints(self):
        """User with product membership should get only that product's endpoints"""
        endpoints = get_authorized_endpoints(Permissions.Location_View, user=self.user_product_member)
        self.assertIn(self.endpoint_1, endpoints)
        self.assertNotIn(self.endpoint_2, endpoints)


# TODO: Delete this after the move to Locations
@skip_unless_v2
class TestGetAuthorizedEndpointStatus(AuthorizationQueriesTestBase):

    """Tests for get_authorized_endpoint_status()"""

    def test_superuser_gets_all_endpoint_statuses(self):
        """Superuser should get all endpoint statuses"""
        endpoint_statuses = get_authorized_endpoint_status(Permissions.Location_View, user=self.superuser)
        self.assertIn(self.endpoint_status_1, endpoint_statuses)
        self.assertIn(self.endpoint_status_2, endpoint_statuses)

    def test_user_no_permissions_gets_empty(self):
        """User with no permissions should not get test endpoint statuses"""
        endpoint_statuses = get_authorized_endpoint_status(Permissions.Location_View, user=self.user_no_perms)
        self.assertNotIn(self.endpoint_status_1, endpoint_statuses)
        self.assertNotIn(self.endpoint_status_2, endpoint_statuses)

    def test_user_product_member_gets_product_endpoint_statuses(self):
        """User with product membership should get only that product's endpoint statuses"""
        endpoint_statuses = get_authorized_endpoint_status(Permissions.Location_View, user=self.user_product_member)
        self.assertIn(self.endpoint_status_1, endpoint_statuses)
        self.assertNotIn(self.endpoint_status_2, endpoint_statuses)


class TestGetAuthorizedGroups(AuthorizationQueriesTestBase):

    """Tests for get_authorized_groups() - uses get_current_user()"""

    @patch("dojo.group.queries.get_current_user")
    def test_superuser_gets_all_groups(self, mock_get_current_user):
        """Superuser should get all groups"""
        mock_get_current_user.return_value = self.superuser
        groups = get_authorized_groups(Permissions.Group_View)
        self.assertIn(self.group_product, groups)
        self.assertIn(self.group_product_type, groups)

    @patch("dojo.group.queries.get_current_user")
    def test_user_group_member_gets_own_groups(self, mock_get_current_user):
        """User who is a group member should get that group"""
        mock_get_current_user.return_value = self.user_group_product_member
        groups = get_authorized_groups(Permissions.Group_View)
        self.assertIn(self.group_product, groups)


class TestGetAuthorizedFindingGroups(AuthorizationQueriesTestBase):

    """Tests for get_authorized_finding_groups()"""

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        # Create finding groups - creator is required
        cls.finding_group_1, _ = Finding_Group.objects.get_or_create(
            name="Auth Test Finding Group 1",
            test=cls.test_1,
            defaults={"creator": cls.superuser},
        )
        cls.finding_group_2, _ = Finding_Group.objects.get_or_create(
            name="Auth Test Finding Group 2",
            test=cls.test_2,
            defaults={"creator": cls.superuser},
        )

    def test_superuser_gets_all_finding_groups(self):
        """Superuser should get all finding groups"""
        finding_groups = get_authorized_finding_groups(Permissions.Finding_Group_View, user=self.superuser)
        self.assertIn(self.finding_group_1, finding_groups)
        self.assertIn(self.finding_group_2, finding_groups)

    def test_user_no_permissions_gets_empty(self):
        """User with no permissions should not get test finding groups"""
        finding_groups = get_authorized_finding_groups(Permissions.Finding_Group_View, user=self.user_no_perms)
        self.assertNotIn(self.finding_group_1, finding_groups)
        self.assertNotIn(self.finding_group_2, finding_groups)

    def test_user_product_member_gets_product_finding_groups(self):
        """User with product membership should get only that product's finding groups"""
        finding_groups = get_authorized_finding_groups(Permissions.Finding_Group_View, user=self.user_product_member)
        self.assertIn(self.finding_group_1, finding_groups)
        self.assertNotIn(self.finding_group_2, finding_groups)


# Note: Tests for get_authorized_risk_acceptances(), get_authorized_jira_projects(),
# and get_authorized_jira_issues() require complex model setups (JIRA_Instance with many
# required fields, Risk_Acceptance with engagement relations). These are covered by
# the existing REST API tests in test_rest_framework.py.
