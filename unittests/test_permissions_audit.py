"""
Security-focused permission tests for the permissions audit.

Tests verify:
1. Risk Acceptance data is not exposed to users without Risk_Acceptance permission
2. Metadata batch operations enforce permissions on parent objects
3. Note removal verifies note-finding relationship (regression)
4. Benchmark IDOR: update_benchmark rejects bench_id from different product
5. Object/tool_product parent mismatch returns 403
6. Risk Acceptance cross-engagement IDOR (H1 #3577434 / #3569882)
7. Engagement Presets cross-product IDOR (H1 #3577398 / #3570349)
8. Questionnaire cross-engagement IDOR (H1 #3571957)
9. Finding Templates exposure via find_template_to_apply (H1 #3577363)
10. Jira Epic BFLA - Reader cannot trigger update_jira_epic (H1 #3577193)
11. Zip Bomb DoS protection in SonarQube and MS Defender parsers (H1 #3572557)
"""
import datetime
import io
import zipfile

from django.test import Client
from django.urls import reverse
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.models import (
    Answered_Survey,
    Benchmark_Category,
    Benchmark_Product,
    Benchmark_Product_Summary,
    Benchmark_Requirement,
    Benchmark_Type,
    Dojo_User,
    DojoMeta,
    Engagement,
    Engagement_Presets,
    Engagement_Survey,
    Finding,
    Finding_Template,
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


class TestRiskAcceptanceCrossEngagementIDOR(DojoTestCase):
    """H1 #3577434 / #3569882: Risk acceptance endpoints must reject
    a raid belonging to a different engagement than the eid in the URL."""

    @classmethod
    def setUpTestData(cls):
        cls.owner_role = Role.objects.get(name="Owner")
        cls.product_type = Product_Type.objects.create(name="RA IDOR Test PT")
        cls.product = Product.objects.create(
            name="RA IDOR Test Product",
            description="Test",
            prod_type=cls.product_type,
        )
        cls.user = Dojo_User.objects.create_user(
            username="ra_idor_owner",
            password="testpass123",
            is_active=True,
        )
        Product_Member.objects.create(
            product=cls.product, user=cls.user, role=cls.owner_role,
        )

        # Two engagements under the same product
        cls.engagement_a = Engagement.objects.create(
            name="RA IDOR Engagement A",
            product=cls.product,
            target_start=datetime.date(2024, 1, 1),
            target_end=datetime.date(2024, 12, 31),
        )
        cls.engagement_b = Engagement.objects.create(
            name="RA IDOR Engagement B",
            product=cls.product,
            target_start=datetime.date(2024, 1, 1),
            target_end=datetime.date(2024, 12, 31),
        )

        # Create a risk acceptance on engagement A
        test_type, _ = Test_Type.objects.get_or_create(name="Manual Code Review")
        cls.test_a = Test.objects.create(
            engagement=cls.engagement_a,
            test_type=test_type,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        cls.finding_a = Finding.objects.create(
            title="RA IDOR Finding",
            test=cls.test_a,
            severity="High",
            numerical_severity="S1",
            reporter=cls.user,
        )
        cls.risk_acceptance = Risk_Acceptance.objects.create(
            name="RA IDOR Test RA",
            owner=cls.user,
        )
        cls.risk_acceptance.accepted_findings.add(cls.finding_a)
        cls.engagement_a.risk_acceptance.add(cls.risk_acceptance)

    def _login(self):
        client = Client()
        client.login(username="ra_idor_owner", password="testpass123")
        return client

    def test_view_risk_acceptance_cross_engagement(self):
        """Viewing a risk acceptance via a different engagement's URL must be denied."""
        client = self._login()
        url = reverse("view_risk_acceptance", args=(
            self.engagement_b.id, self.risk_acceptance.id,
        ))
        response = client.get(url)
        self.assertIn(response.status_code, [400, 403])

    def test_edit_risk_acceptance_cross_engagement(self):
        """Editing a risk acceptance via a different engagement's URL must be denied."""
        client = self._login()
        url = reverse("edit_risk_acceptance", args=(
            self.engagement_b.id, self.risk_acceptance.id,
        ))
        response = client.get(url)
        self.assertIn(response.status_code, [400, 403])

    def test_expire_risk_acceptance_cross_engagement(self):
        """Expiring a risk acceptance via a different engagement's URL must be denied."""
        client = self._login()
        url = reverse("expire_risk_acceptance", args=(
            self.engagement_b.id, self.risk_acceptance.id,
        ))
        response = client.get(url)
        self.assertIn(response.status_code, [400, 403])

    def test_reinstate_risk_acceptance_cross_engagement(self):
        """Reinstating a risk acceptance via a different engagement's URL must be denied."""
        client = self._login()
        url = reverse("reinstate_risk_acceptance", args=(
            self.engagement_b.id, self.risk_acceptance.id,
        ))
        response = client.get(url)
        self.assertIn(response.status_code, [400, 403])

    def test_delete_risk_acceptance_cross_engagement(self):
        """Deleting a risk acceptance via a different engagement's URL must be denied."""
        client = self._login()
        url = reverse("delete_risk_acceptance", args=(
            self.engagement_b.id, self.risk_acceptance.id,
        ))
        response = client.get(url)
        self.assertIn(response.status_code, [400, 403])

    def test_view_risk_acceptance_same_engagement(self):
        """Viewing a risk acceptance via the correct engagement's URL should work."""
        client = self._login()
        url = reverse("view_risk_acceptance", args=(
            self.engagement_a.id, self.risk_acceptance.id,
        ))
        response = client.get(url)
        self.assertEqual(response.status_code, 200)


class TestEngagementPresetsCrossProductIDOR(DojoTestCase):
    """H1 #3577398 / #3570349: Engagement preset endpoints must reject
    a preset belonging to a different product than the pid in the URL."""

    @classmethod
    def setUpTestData(cls):
        cls.owner_role = Role.objects.get(name="Owner")
        cls.product_type = Product_Type.objects.create(name="Preset IDOR Test PT")

        cls.product_a = Product.objects.create(
            name="Preset IDOR Product A",
            description="Test",
            prod_type=cls.product_type,
        )
        cls.product_b = Product.objects.create(
            name="Preset IDOR Product B",
            description="Test",
            prod_type=cls.product_type,
        )

        cls.user = Dojo_User.objects.create_user(
            username="preset_idor_owner",
            password="testpass123",
            is_active=True,
        )
        Product_Member.objects.create(
            product=cls.product_a, user=cls.user, role=cls.owner_role,
        )
        Product_Member.objects.create(
            product=cls.product_b, user=cls.user, role=cls.owner_role,
        )

        # Preset belonging to product A
        cls.preset = Engagement_Presets.objects.create(
            title="IDOR Test Preset",
            product=cls.product_a,
            scope="Test scope",
        )

    def _login(self):
        client = Client()
        client.login(username="preset_idor_owner", password="testpass123")
        return client

    def test_edit_preset_cross_product(self):
        """Editing a preset from product A via product B's URL must return 404."""
        client = self._login()
        url = reverse("edit_engagement_presets", args=(
            self.product_b.id, self.preset.id,
        ))
        response = client.get(url)
        # Scoped get_object_or_404 returns 404 for cross-product access
        self.assertEqual(response.status_code, 404)

    def test_delete_preset_cross_product(self):
        """Deleting a preset from product A via product B's URL must return 404."""
        client = self._login()
        url = reverse("delete_engagement_presets", args=(
            self.product_b.id, self.preset.id,
        ))
        response = client.get(url)
        self.assertEqual(response.status_code, 404)

    def test_edit_preset_same_product(self):
        """Editing a preset via the correct product's URL should work."""
        client = self._login()
        url = reverse("edit_engagement_presets", args=(
            self.product_a.id, self.preset.id,
        ))
        response = client.get(url)
        self.assertEqual(response.status_code, 200)


class TestQuestionnaireCrossEngagementIDOR(DojoTestCase):
    """H1 #3571957: Survey/questionnaire endpoints must reject
    a survey belonging to a different engagement than the eid in the URL."""

    @classmethod
    def setUpTestData(cls):
        cls.owner_role = Role.objects.get(name="Owner")
        cls.product_type = Product_Type.objects.create(name="Survey IDOR Test PT")
        cls.product = Product.objects.create(
            name="Survey IDOR Test Product",
            description="Test",
            prod_type=cls.product_type,
        )
        cls.user = Dojo_User.objects.create_user(
            username="survey_idor_owner",
            password="testpass123",
            is_active=True,
        )
        Product_Member.objects.create(
            product=cls.product, user=cls.user, role=cls.owner_role,
        )

        cls.engagement_a = Engagement.objects.create(
            name="Survey IDOR Engagement A",
            product=cls.product,
            target_start=datetime.date(2024, 1, 1),
            target_end=datetime.date(2024, 12, 31),
        )
        cls.engagement_b = Engagement.objects.create(
            name="Survey IDOR Engagement B",
            product=cls.product,
            target_start=datetime.date(2024, 1, 1),
            target_end=datetime.date(2024, 12, 31),
        )

        # Create a questionnaire (Engagement_Survey) and an Answered_Survey on engagement A
        cls.survey_template = Engagement_Survey.objects.create(
            name="Test Questionnaire",
            description="Test description",
            active=True,
        )
        cls.answered_survey = Answered_Survey.objects.create(
            engagement=cls.engagement_a,
            survey=cls.survey_template,
            responder=cls.user,
            completed=False,
        )

    def _login(self):
        client = Client()
        client.login(username="survey_idor_owner", password="testpass123")
        return client

    def test_view_questionnaire_cross_engagement(self):
        """Viewing a survey from engagement A via engagement B's URL must return 404."""
        client = self._login()
        url = reverse("view_questionnaire", args=(
            self.engagement_b.id, self.answered_survey.id,
        ))
        response = client.get(url)
        self.assertEqual(response.status_code, 404)

    def test_delete_survey_cross_engagement(self):
        """Deleting a survey from engagement A via engagement B's URL must return 404."""
        client = self._login()
        url = reverse("delete_engagement_survey", args=(
            self.engagement_b.id, self.answered_survey.id,
        ))
        response = client.get(url)
        self.assertEqual(response.status_code, 404)

    def test_answer_questionnaire_cross_engagement(self):
        """Answering a survey from engagement A via engagement B's URL must return 404."""
        client = self._login()
        url = reverse("answer_questionnaire", args=(
            self.engagement_b.id, self.answered_survey.id,
        ))
        response = client.get(url)
        self.assertEqual(response.status_code, 404)

    def test_view_questionnaire_same_engagement(self):
        """Viewing a survey via the correct engagement's URL should work."""
        client = self._login()
        url = reverse("view_questionnaire", args=(
            self.engagement_a.id, self.answered_survey.id,
        ))
        response = client.get(url)
        self.assertEqual(response.status_code, 200)


class TestFindingTemplatesGlobalPermission(DojoTestCase):
    """H1 #3577363: find_template_to_apply must require global Finding_Edit
    permission, not just product-level Finding_Edit."""

    @classmethod
    def setUpTestData(cls):
        cls.writer_role = Role.objects.get(name="Writer")
        cls.product_type = Product_Type.objects.create(name="Template Test PT")
        cls.product = Product.objects.create(
            name="Template Test Product",
            description="Test",
            prod_type=cls.product_type,
        )

        # Product-level writer (no global permission)
        cls.product_writer = Dojo_User.objects.create_user(
            username="template_test_writer",
            password="testpass123",
            is_active=True,
        )
        Product_Member.objects.create(
            product=cls.product, user=cls.product_writer, role=cls.writer_role,
        )

        # Superuser (has global permissions)
        cls.superuser = Dojo_User.objects.create_user(
            username="template_test_super",
            password="testpass123",
            is_active=True,
            is_superuser=True,
        )

        # Create engagement, test, finding
        cls.engagement = Engagement.objects.create(
            name="Template Test Engagement",
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
            title="Template Test Finding",
            test=cls.test,
            severity="High",
            numerical_severity="S1",
            reporter=cls.product_writer,
        )

        # Create a template (should only be visible to global permission holders)
        Finding_Template.objects.create(
            title="Secret Template",
            severity="Critical",
        )

    def test_product_writer_cannot_access_find_template(self):
        """Product-level Writer without global permission should be denied."""
        client = Client()
        client.login(username="template_test_writer", password="testpass123")
        url = reverse("find_template_to_apply", args=(self.finding.id,))
        response = client.get(url)
        # PermissionDenied raised; custom handler403 returns 400 (DD bug)
        self.assertIn(response.status_code, [400, 403])

    def test_superuser_can_access_find_template(self):
        """Superuser (implicit global permission) should be able to access."""
        client = Client()
        client.login(username="template_test_super", password="testpass123")
        url = reverse("find_template_to_apply", args=(self.finding.id,))
        response = client.get(url)
        self.assertEqual(response.status_code, 200)


class TestJiraEpicBFLA(DojoTestCase):
    """H1 #3577193: update_jira_epic must enforce Engagement_Edit permission,
    not just IsAuthenticated. Reader role should be denied."""

    @classmethod
    def setUpTestData(cls):
        cls.reader_role = Role.objects.get(name="Reader")
        cls.writer_role = Role.objects.get(name="Writer")
        cls.product_type = Product_Type.objects.create(name="Jira Epic BFLA Test PT")
        cls.product = Product.objects.create(
            name="Jira Epic BFLA Test Product",
            description="Test",
            prod_type=cls.product_type,
        )

        cls.reader_user = Dojo_User.objects.create_user(
            username="jira_epic_reader",
            password="testpass123",
            is_active=True,
        )
        cls.writer_user = Dojo_User.objects.create_user(
            username="jira_epic_writer",
            password="testpass123",
            is_active=True,
        )

        Product_Member.objects.create(
            product=cls.product, user=cls.reader_user, role=cls.reader_role,
        )
        Product_Member.objects.create(
            product=cls.product, user=cls.writer_user, role=cls.writer_role,
        )

        cls.engagement = Engagement.objects.create(
            name="Jira Epic BFLA Engagement",
            product=cls.product,
            target_start=datetime.date(2024, 1, 1),
            target_end=datetime.date(2024, 12, 31),
        )

    def _client_for_user(self, user):
        token, _ = Token.objects.get_or_create(user=user)
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        return client

    def test_reader_cannot_update_jira_epic(self):
        """Reader role should be denied POST to update_jira_epic."""
        client = self._client_for_user(self.reader_user)
        url = reverse("engagement-update-jira-epic", args=(self.engagement.id,))
        response = client.post(url, data={}, format="json")
        self.assertIn(response.status_code, [403, 404])

    def test_writer_allowed_update_jira_epic(self):
        """Writer role should be allowed to POST to update_jira_epic
        (may fail at Jira level, but not at permission level)."""
        client = self._client_for_user(self.writer_user)
        url = reverse("engagement-update-jira-epic", args=(self.engagement.id,))
        response = client.post(url, data={}, format="json")
        # Writer has Engagement_Edit, so should pass permission check.
        # May get 400/500 from Jira integration, but NOT 403.
        self.assertNotEqual(response.status_code, 403)


class TestZipBombProtection(DojoTestCase):
    """H1 #3572557: SonarQube and MS Defender parsers must reject zip files
    whose uncompressed content exceeds the size limit."""

    def _make_zip(self, inner_name, content=b"small content"):
        """Create a simple zip file."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr(inner_name, content)
        buf.seek(0)
        buf.name = "test.zip"
        return buf

    def test_sonarqube_parser_rejects_oversized_zip(self):
        """SonarQube parser should raise ValueError for oversized zip."""
        from unittest.mock import patch

        from dojo.tools.sonarqube.parser import SonarQubeParser

        test_zip = self._make_zip("sonar-report.html")
        parser = SonarQubeParser()

        # Mock infolist to report a huge file_size (simulating a zip bomb)
        fake_info = zipfile.ZipInfo("sonar-report.html")
        fake_info.file_size = 512 * 1024 * 1024  # 512 MB

        with patch.object(zipfile.ZipFile, "infolist", return_value=[fake_info]):
            with self.assertRaises(ValueError) as ctx:
                parser.get_findings(test_zip, None)
        self.assertIn("exceeds maximum allowed size", str(ctx.exception))

    def test_ms_defender_parser_rejects_oversized_zip(self):
        """MS Defender parser should raise ValueError for oversized zip."""
        from unittest.mock import patch

        from dojo.tools.ms_defender.parser import MSDefenderParser

        test_zip = self._make_zip("vulnerabilities/vuln1.json")
        parser = MSDefenderParser()

        fake_info = zipfile.ZipInfo("vulnerabilities/vuln1.json")
        fake_info.file_size = 512 * 1024 * 1024

        with patch.object(zipfile.ZipFile, "infolist", return_value=[fake_info]):
            with self.assertRaises(ValueError) as ctx:
                parser.get_findings(test_zip, None)
        self.assertIn("exceeds maximum allowed size", str(ctx.exception))

    def test_sonarqube_parser_accepts_normal_zip(self):
        """SonarQube parser should accept a reasonably sized zip."""
        from dojo.tools.sonarqube.parser import SonarQubeParser

        test_zip = self._make_zip(
            "sonar-report.html", b"<html><body>report</body></html>",
        )
        parser = SonarQubeParser()

        # Should not raise ValueError (may raise other errors from parsing)
        try:
            parser.get_findings(test_zip, None)
        except ValueError:
            self.fail("SonarQubeParser raised ValueError on a normal-sized zip")
