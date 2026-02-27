"""
Security-focused permission tests for the permissions audit.

Tests verify:
1. Risk Acceptance data is not exposed to users without Risk_Acceptance permission
2. Metadata batch operations enforce permissions on parent objects
3. Note removal verifies note-finding relationship (regression)
4. Benchmark IDOR: update_benchmark rejects bench_id from different product
5. Object/tool_product parent mismatch returns 403
"""
import datetime

from django.test import Client
from django.urls import reverse
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.models import (
    Benchmark_Category,
    Benchmark_Product,
    Benchmark_Product_Summary,
    Benchmark_Requirement,
    Benchmark_Type,
    Dojo_User,
    DojoMeta,
    Engagement,
    Finding,
    Notes,
    Objects_Product,
    Objects_Review,
    Product,
    Product_Member,
    Product_Type,
    Risk_Acceptance,
    Role,
    Test,
    Test_Type,
    Tool_Configuration,
    Tool_Product_Settings,
    Tool_Type,
)

from .dojo_test_case import DojoTestCase


class TestRiskAcceptanceExposure(DojoTestCase):
    """FindingSerializer must not expose accepted_risks to users without Risk_Acceptance permission."""

    @classmethod
    def setUpTestData(cls):
        cls.reader_role = Role.objects.get(name="Reader")
        cls.writer_role = Role.objects.get(name="Writer")

        # Create product type and product
        cls.product_type = Product_Type.objects.create(name="RA Exposure Test PT")
        cls.product = Product.objects.create(
            name="RA Exposure Test Product",
            description="Test",
            prod_type=cls.product_type,
        )

        # Create users
        cls.reader_user = Dojo_User.objects.create_user(
            username="ra_test_reader",
            password="testpass123",
            is_active=True,
        )
        cls.writer_user = Dojo_User.objects.create_user(
            username="ra_test_writer",
            password="testpass123",
            is_active=True,
        )

        # Assign roles
        Product_Member.objects.create(
            product=cls.product,
            user=cls.reader_user,
            role=cls.reader_role,
        )
        Product_Member.objects.create(
            product=cls.product,
            user=cls.writer_user,
            role=cls.writer_role,
        )

        # Create engagement, test, finding
        cls.engagement = Engagement.objects.create(
            name="RA Test Engagement",
            product=cls.product,
            target_start=datetime.date(2024, 1, 1),
            target_end=datetime.date(2024, 12, 31),
        )
        test_type, _ = Test_Type.objects.get_or_create(name="Manual Code Review")
        cls.test = Test.objects.create(
            engagement=cls.engagement,
            test_type=test_type,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        cls.finding = Finding.objects.create(
            title="RA Test Finding",
            test=cls.test,
            severity="High",
            numerical_severity="S1",
            reporter=cls.writer_user,
        )

        # Create risk acceptance linked to the finding
        cls.risk_acceptance = Risk_Acceptance.objects.create(
            name="Test RA",
            owner=cls.writer_user,
        )
        cls.risk_acceptance.accepted_findings.add(cls.finding)
        cls.engagement.risk_acceptance.add(cls.risk_acceptance)

    def _get_finding_as_user(self, user):
        token, _ = Token.objects.get_or_create(user=user)
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        return client.get(reverse("finding-detail", args=(self.finding.id,)))

    def test_reader_cannot_see_accepted_risks(self):
        """Reader role lacks Risk_Acceptance permission — accepted_risks must be empty."""
        response = self._get_finding_as_user(self.reader_user)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["accepted_risks"], [])

    def test_writer_can_see_accepted_risks(self):
        """Writer role has Risk_Acceptance permission — accepted_risks must contain data."""
        response = self._get_finding_as_user(self.writer_user)
        self.assertEqual(response.status_code, 200)
        accepted = response.json()["accepted_risks"]
        self.assertGreater(len(accepted), 0)
        self.assertEqual(accepted[0]["name"], "Test RA")


class TestMetadataBatchPermissions(DojoTestCase):
    """Metadata batch endpoint must enforce permissions on parent objects."""

    @classmethod
    def setUpTestData(cls):
        cls.reader_role = Role.objects.get(name="Reader")
        cls.writer_role = Role.objects.get(name="Writer")

        # Product the user CAN access
        cls.product_type = Product_Type.objects.create(name="Meta Batch Test PT")
        cls.accessible_product = Product.objects.create(
            name="Meta Batch Accessible Product",
            description="Test",
            prod_type=cls.product_type,
        )

        # Product the user CANNOT access
        cls.inaccessible_product = Product.objects.create(
            name="Meta Batch Inaccessible Product",
            description="Test",
            prod_type=cls.product_type,
        )

        # User with Writer on accessible product, no role on inaccessible product
        cls.writer_user = Dojo_User.objects.create_user(
            username="meta_batch_writer",
            password="testpass123",
            is_active=True,
        )
        Product_Member.objects.create(
            product=cls.accessible_product,
            user=cls.writer_user,
            role=cls.writer_role,
        )

        # User with Reader on accessible product (Reader lacks Product_Edit)
        cls.reader_user = Dojo_User.objects.create_user(
            username="meta_batch_reader",
            password="testpass123",
            is_active=True,
        )
        Product_Member.objects.create(
            product=cls.accessible_product,
            user=cls.reader_user,
            role=cls.reader_role,
        )

    def _client_for_user(self, user):
        token, _ = Token.objects.get_or_create(user=user)
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        return client

    def test_batch_post_unauthorized_product(self):
        """Writer should be denied when targeting a product they have no access to."""
        client = self._client_for_user(self.writer_user)
        response = client.post(
            reverse("metadata-batch"),
            data={
                "product": self.inaccessible_product.id,
                "metadata": [{"name": "hack_key", "value": "hack_val"}],
            },
            format="json",
        )
        self.assertIn(response.status_code, [403, 404])
        self.assertFalse(
            DojoMeta.objects.filter(
                product=self.inaccessible_product, name="hack_key",
            ).exists(),
        )

    def test_batch_post_reader_cannot_edit(self):
        """Reader lacks Product_Edit — batch POST should be denied."""
        client = self._client_for_user(self.reader_user)
        response = client.post(
            reverse("metadata-batch"),
            data={
                "product": self.accessible_product.id,
                "metadata": [{"name": "reader_key", "value": "reader_val"}],
            },
            format="json",
        )
        self.assertIn(response.status_code, [403, 404])
        self.assertFalse(
            DojoMeta.objects.filter(
                product=self.accessible_product, name="reader_key",
            ).exists(),
        )


class TestNoteRelationshipVerification(DojoTestCase):
    """Regression: remove_note must verify the note belongs to the finding."""

    @classmethod
    def setUpTestData(cls):
        cls.owner_role = Role.objects.get(name="Owner")

        cls.product_type = Product_Type.objects.create(name="Note Test PT")
        cls.product = Product.objects.create(
            name="Note Test Product",
            description="Test",
            prod_type=cls.product_type,
        )

        cls.user = Dojo_User.objects.create_user(
            username="note_test_owner",
            password="testpass123",
            is_active=True,
        )
        Product_Member.objects.create(
            product=cls.product,
            user=cls.user,
            role=cls.owner_role,
        )

        cls.engagement = Engagement.objects.create(
            name="Note Test Engagement",
            product=cls.product,
            target_start=datetime.date(2024, 1, 1),
            target_end=datetime.date(2024, 12, 31),
        )
        test_type, _ = Test_Type.objects.get_or_create(name="Manual Code Review")
        cls.test = Test.objects.create(
            engagement=cls.engagement,
            test_type=test_type,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )

        # Create two findings
        cls.finding_a = Finding.objects.create(
            title="Note Test Finding A",
            test=cls.test,
            severity="High",
            numerical_severity="S1",
            reporter=cls.user,
        )
        cls.finding_b = Finding.objects.create(
            title="Note Test Finding B",
            test=cls.test,
            severity="Medium",
            numerical_severity="S2",
            reporter=cls.user,
        )

        # Create a note on finding A
        cls.note = Notes.objects.create(
            entry="Test note on finding A",
            author=cls.user,
        )
        cls.finding_a.notes.add(cls.note)

    def test_remove_note_from_wrong_finding(self):
        """Removing a note via a different finding's endpoint must fail."""
        token, _ = Token.objects.get_or_create(user=self.user)
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION="Token " + token.key)

        response = client.patch(
            reverse("finding-remove-note", args=(self.finding_b.id,)),
            data={"note_id": self.note.id},
            format="json",
        )
        self.assertEqual(response.status_code, 400)
        # Note should still exist
        self.assertTrue(Notes.objects.filter(id=self.note.id).exists())

    def test_remove_note_from_correct_finding(self):
        """Removing a note from the correct finding must succeed for the author."""
        # Create a fresh note so we don't affect other tests
        note = Notes.objects.create(
            entry="Disposable test note",
            author=self.user,
        )
        self.finding_a.notes.add(note)

        token, _ = Token.objects.get_or_create(user=self.user)
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION="Token " + token.key)

        response = client.patch(
            reverse("finding-remove-note", args=(self.finding_a.id,)),
            data={"note_id": note.id},
            format="json",
        )
        self.assertEqual(response.status_code, 204)
        self.assertFalse(Notes.objects.filter(id=note.id).exists())


class TestBenchmarkIDOR(DojoTestCase):
    """update_benchmark must reject bench_id belonging to a different product."""

    @classmethod
    def setUpTestData(cls):
        cls.owner_role = Role.objects.get(name="Owner")
        cls.product_type = Product_Type.objects.create(name="Bench IDOR Test PT")

        # Two separate products
        cls.product_a = Product.objects.create(
            name="Bench IDOR Product A",
            description="Test",
            prod_type=cls.product_type,
        )
        cls.product_b = Product.objects.create(
            name="Bench IDOR Product B",
            description="Test",
            prod_type=cls.product_type,
        )

        # User with Owner on both products
        cls.user = Dojo_User.objects.create_user(
            username="bench_idor_owner",
            password="testpass123",
            is_active=True,
        )
        Product_Member.objects.create(
            product=cls.product_a, user=cls.user, role=cls.owner_role,
        )
        Product_Member.objects.create(
            product=cls.product_b, user=cls.user, role=cls.owner_role,
        )

        # Create benchmark type, category, requirement
        cls.bench_type = Benchmark_Type.objects.create(
            name="IDOR Test Type", enabled=True,
        )
        cls.bench_category = Benchmark_Category.objects.create(
            type=cls.bench_type, name="V1: Test Category", enabled=True,
        )
        cls.bench_requirement = Benchmark_Requirement.objects.create(
            category=cls.bench_category,
            objective_number="1.1",
            objective="Test objective",
            enabled=True,
        )

        # Create a benchmark entry for product A
        cls.bench_product_a = Benchmark_Product.objects.create(
            product=cls.product_a,
            control=cls.bench_requirement,
        )

        # Create benchmark summary for product B (needed for URL)
        cls.bench_summary_a = Benchmark_Product_Summary.objects.create(
            product=cls.product_a, benchmark_type=cls.bench_type,
        )
        cls.bench_summary_b = Benchmark_Product_Summary.objects.create(
            product=cls.product_b, benchmark_type=cls.bench_type,
        )

    def test_update_benchmark_cross_product_rejected(self):
        """POSTing a bench_id from product A via product B's URL must be denied."""
        client = Client()
        client.login(username="bench_idor_owner", password="testpass123")

        # Try to update product A's benchmark through product B's endpoint
        url = reverse(
            "update_product_benchmark",
            args=(self.product_b.id, self.bench_type.id),
        )
        response = client.post(url, {
            "bench_id": self.bench_product_a.id,
            "field": "pass_fail",
            "value": "true",
        })
        # Scoped get_object_or_404 returns 404 for cross-product access;
        # PermissionDenied would give 400/403 via custom handler403 (DD bug)
        self.assertIn(response.status_code, [400, 403, 404])

    def test_update_benchmark_summary_cross_product_rejected(self):
        """POSTing a summary from product A via product B's URL must be denied."""
        client = Client()
        client.login(username="bench_idor_owner", password="testpass123")

        url = reverse(
            "update_product_benchmark_summary",
            args=(self.product_b.id, self.bench_type.id, self.bench_summary_a.id),
        )
        response = client.post(url, {
            "field": "publish",
            "value": "true",
        })
        # Scoped get_object_or_404 returns 404 for cross-product access;
        # PermissionDenied would give 400/403 via custom handler403 (DD bug)
        self.assertIn(response.status_code, [400, 403, 404])

    def test_update_benchmark_same_product_allowed(self):
        """POSTing a bench_id for the correct product should succeed."""
        client = Client()
        client.login(username="bench_idor_owner", password="testpass123")

        url = reverse(
            "update_product_benchmark",
            args=(self.product_a.id, self.bench_type.id),
        )
        response = client.post(url, {
            "bench_id": self.bench_product_a.id,
            "field": "enabled",
            "value": "true",
        })
        self.assertEqual(response.status_code, 200)


class TestObjectProductParentCheck(DojoTestCase):
    """edit_object and delete_object must reject objects from different products."""

    @classmethod
    def setUpTestData(cls):
        cls.owner_role = Role.objects.get(name="Owner")
        cls.product_type = Product_Type.objects.create(name="Object Parent Test PT")

        cls.product_a = Product.objects.create(
            name="Object Parent Product A",
            description="Test",
            prod_type=cls.product_type,
        )
        cls.product_b = Product.objects.create(
            name="Object Parent Product B",
            description="Test",
            prod_type=cls.product_type,
        )

        cls.user = Dojo_User.objects.create_user(
            username="object_parent_owner",
            password="testpass123",
            is_active=True,
        )
        Product_Member.objects.create(
            product=cls.product_a, user=cls.user, role=cls.owner_role,
        )
        Product_Member.objects.create(
            product=cls.product_b, user=cls.user, role=cls.owner_role,
        )

        # Object belonging to product A
        cls.review_status = Objects_Review.objects.create(name="In Review")
        cls.tracked_file = Objects_Product.objects.create(
            product=cls.product_a,
            path="/test/path",
            folder="test_folder",
            artifact="test.py",
            review_status=cls.review_status,
        )

    def test_edit_object_cross_product_rejected(self):
        """Editing an object from product A via product B's URL must be denied."""
        client = Client()
        client.login(username="object_parent_owner", password="testpass123")

        url = reverse("edit_object", args=(self.product_b.id, self.tracked_file.id))
        response = client.get(url)
        # PermissionDenied raised; custom handler403 returns 400 (DD bug)
        self.assertIn(response.status_code, [400, 403])

    def test_delete_object_cross_product_rejected(self):
        """Deleting an object from product A via product B's URL must be denied."""
        client = Client()
        client.login(username="object_parent_owner", password="testpass123")

        url = reverse("delete_object", args=(self.product_b.id, self.tracked_file.id))
        response = client.get(url)
        # PermissionDenied raised; custom handler403 returns 400 (DD bug)
        self.assertIn(response.status_code, [400, 403])


class TestToolProductParentCheck(DojoTestCase):
    """edit_tool_product and delete_tool_product must reject tools from different products."""

    @classmethod
    def setUpTestData(cls):
        cls.owner_role = Role.objects.get(name="Owner")
        cls.product_type = Product_Type.objects.create(name="Tool Parent Test PT")

        cls.product_a = Product.objects.create(
            name="Tool Parent Product A",
            description="Test",
            prod_type=cls.product_type,
        )
        cls.product_b = Product.objects.create(
            name="Tool Parent Product B",
            description="Test",
            prod_type=cls.product_type,
        )

        cls.user = Dojo_User.objects.create_user(
            username="tool_parent_owner",
            password="testpass123",
            is_active=True,
        )
        Product_Member.objects.create(
            product=cls.product_a, user=cls.user, role=cls.owner_role,
        )
        Product_Member.objects.create(
            product=cls.product_b, user=cls.user, role=cls.owner_role,
        )

        # Tool type, configuration, and tool setting belonging to product A
        cls.tool_type = Tool_Type.objects.create(name="Test Tool Type Parent Check")
        cls.tool_config = Tool_Configuration.objects.create(
            name="Test Tool Config",
            tool_type=cls.tool_type,
        )
        cls.tool_setting = Tool_Product_Settings.objects.create(
            name="Test Tool Setting",
            product=cls.product_a,
            tool_configuration=cls.tool_config,
        )

    def test_edit_tool_product_cross_product_rejected(self):
        """Editing a tool setting from product A via product B's URL must be denied."""
        client = Client()
        client.login(username="tool_parent_owner", password="testpass123")

        url = reverse("edit_tool_product", args=(self.product_b.id, self.tool_setting.id))
        response = client.get(url)
        # PermissionDenied raised; custom handler403 returns 400 (DD bug)
        self.assertIn(response.status_code, [400, 403])

    def test_delete_tool_product_cross_product_rejected(self):
        """Deleting a tool setting from product A via product B's URL must be denied."""
        client = Client()
        client.login(username="tool_parent_owner", password="testpass123")

        url = reverse("delete_tool_product", args=(self.product_b.id, self.tool_setting.id))
        response = client.get(url)
        # PermissionDenied raised; custom handler403 returns 400 (DD bug)
        self.assertIn(response.status_code, [400, 403])
