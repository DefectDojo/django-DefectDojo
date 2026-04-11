"""
Tests for prepare_duplicates_for_delete() in dojo.finding.helper.

These tests verify that duplicate clusters are properly handled before
Test/Engagement deletion: inside-scope duplicates get their FK cleared,
outside-scope duplicates get a new original chosen.
"""

import logging

from crum import impersonate
from django.test.utils import override_settings
from django.utils import timezone

from dojo.finding.helper import prepare_duplicates_for_delete
from dojo.models import (
    Dojo_User,
    Engagement,
    Finding,
    Finding_Group,
    Product,
    Product_Type,
    Risk_Acceptance,
    Test,
    Test_Type,
    User,
    UserContactInfo,
)

from .dojo_test_case import DojoTestCase

logger = logging.getLogger(__name__)


@override_settings(DUPLICATE_CLUSTER_CASCADE_DELETE=False)
class TestPrepareDuplicatesForDelete(DojoTestCase):

    """Tests for prepare_duplicates_for_delete()."""

    def setUp(self):
        super().setUp()

        self.testuser = User.objects.create(
            username="test_prepare_dupes_user",
            is_staff=True,
            is_superuser=True,
        )
        UserContactInfo.objects.create(user=self.testuser, block_execution=True)

        self.system_settings(enable_deduplication=False)
        self.system_settings(enable_product_grade=False)

        self.product_type = Product_Type.objects.create(name="Test PT for Prepare Dupes")
        self.product = Product.objects.create(
            name="Test Product",
            description="Test",
            prod_type=self.product_type,
        )
        self.test_type = Test_Type.objects.get_or_create(name="Manual Test")[0]

        # Engagement 1 with Test 1 and Test 2
        self.engagement1 = Engagement.objects.create(
            name="Engagement 1",
            product=self.product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        self.test1 = Test.objects.create(
            engagement=self.engagement1,
            test_type=self.test_type,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        self.test2 = Test.objects.create(
            engagement=self.engagement1,
            test_type=self.test_type,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )

        # Engagement 2 with Test 3 (for cross-engagement tests)
        self.engagement2 = Engagement.objects.create(
            name="Engagement 2",
            product=self.product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        self.test3 = Test.objects.create(
            engagement=self.engagement2,
            test_type=self.test_type,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )

    def _create_finding(self, test, title="Finding"):
        return Finding.objects.create(
            test=test,
            title=title,
            severity="High",
            description="Test",
            mitigation="Test",
            impact="Test",
            reporter=self.testuser,
        )

    def _make_duplicate(self, duplicate, original):
        """Set duplicate relationship directly, bypassing set_duplicate safeguards."""
        duplicate.duplicate = True
        duplicate.duplicate_finding = original
        duplicate.active = False
        super(Finding, duplicate).save(skip_validation=True)

    def test_no_duplicates(self):
        """Deleting a test with no duplicate relationships is a no-op."""
        f1 = self._create_finding(self.test1, "F1")
        f2 = self._create_finding(self.test1, "F2")

        with impersonate(self.testuser):
            prepare_duplicates_for_delete(self.test1)

        f1.refresh_from_db()
        f2.refresh_from_db()
        self.assertFalse(f1.duplicate)
        self.assertFalse(f2.duplicate)
        self.assertIsNone(f1.duplicate_finding)
        self.assertIsNone(f2.duplicate_finding)

    def test_inside_scope_duplicates_reset(self):
        """Duplicates inside the deletion scope have their duplicate FK cleared."""
        original = self._create_finding(self.test1, "Original")
        dupe = self._create_finding(self.test1, "Duplicate")
        self._make_duplicate(dupe, original)

        with impersonate(self.testuser):
            prepare_duplicates_for_delete(self.test1)

        dupe.refresh_from_db()
        self.assertIsNone(dupe.duplicate_finding)
        self.assertFalse(dupe.duplicate)

    def test_outside_scope_duplicates_get_new_original(self):
        """Duplicates outside the deletion scope get a new original."""
        original = self._create_finding(self.test1, "Original")
        original.active = True
        original.is_mitigated = False
        super(Finding, original).save(skip_validation=True)

        outside_dupe = self._create_finding(self.test2, "Outside Dupe")
        self._make_duplicate(outside_dupe, original)

        with impersonate(self.testuser):
            prepare_duplicates_for_delete(self.test1)

        outside_dupe.refresh_from_db()
        # Outside dupe becomes the new original
        self.assertFalse(outside_dupe.duplicate)
        self.assertIsNone(outside_dupe.duplicate_finding)
        # Inherits active/mitigated status from old original
        self.assertTrue(outside_dupe.active)
        self.assertFalse(outside_dupe.is_mitigated)

    def test_outside_scope_cluster_repointed(self):
        """Multiple outside-scope duplicates are re-pointed to the new original."""
        original = self._create_finding(self.test1, "Original")
        dupe_b = self._create_finding(self.test2, "Dupe B")
        dupe_c = self._create_finding(self.test2, "Dupe C")
        dupe_d = self._create_finding(self.test2, "Dupe D")
        self._make_duplicate(dupe_b, original)
        self._make_duplicate(dupe_c, original)
        self._make_duplicate(dupe_d, original)

        with impersonate(self.testuser):
            prepare_duplicates_for_delete(self.test1)

        dupe_b.refresh_from_db()
        dupe_c.refresh_from_db()
        dupe_d.refresh_from_db()

        # Lowest ID becomes new original
        new_original = dupe_b
        self.assertFalse(new_original.duplicate)
        self.assertIsNone(new_original.duplicate_finding)

        # Others re-pointed to new original
        self.assertTrue(dupe_c.duplicate)
        self.assertEqual(dupe_c.duplicate_finding_id, new_original.id)
        self.assertTrue(dupe_d.duplicate)
        self.assertEqual(dupe_d.duplicate_finding_id, new_original.id)

    def test_engagement_scope_inside_reset(self):
        """Inside-scope reset works at engagement level."""
        original = self._create_finding(self.test1, "Original")
        dupe = self._create_finding(self.test2, "Dupe in same engagement")
        self._make_duplicate(dupe, original)

        with impersonate(self.testuser):
            prepare_duplicates_for_delete(self.engagement1)

        dupe.refresh_from_db()
        self.assertIsNone(dupe.duplicate_finding)
        self.assertFalse(dupe.duplicate)

    def test_engagement_scope_outside_reconfigure(self):
        """Outside-scope reconfiguration works at engagement level."""
        original = self._create_finding(self.test1, "Original in Eng 1")
        outside_dupe = self._create_finding(self.test3, "Dupe in Eng 2")
        self._make_duplicate(outside_dupe, original)

        with impersonate(self.testuser):
            prepare_duplicates_for_delete(self.engagement1)

        outside_dupe.refresh_from_db()
        self.assertFalse(outside_dupe.duplicate)
        self.assertIsNone(outside_dupe.duplicate_finding)

    def test_mixed_inside_and_outside_duplicates(self):
        """Original with duplicates both inside and outside scope."""
        original = self._create_finding(self.test1, "Original")
        inside_dupe = self._create_finding(self.test1, "Inside Dupe")
        outside_dupe = self._create_finding(self.test2, "Outside Dupe")
        self._make_duplicate(inside_dupe, original)
        self._make_duplicate(outside_dupe, original)

        with impersonate(self.testuser):
            prepare_duplicates_for_delete(self.test1)

        inside_dupe.refresh_from_db()
        outside_dupe.refresh_from_db()

        # Inside dupe: FK cleared
        self.assertIsNone(inside_dupe.duplicate_finding)
        self.assertFalse(inside_dupe.duplicate)

        # Outside dupe: becomes new original
        self.assertFalse(outside_dupe.duplicate)
        self.assertIsNone(outside_dupe.duplicate_finding)

    @override_settings(DUPLICATE_CLUSTER_CASCADE_DELETE=True)
    def test_cascade_delete_skips_outside_reconfigure(self):
        """
        When DUPLICATE_CLUSTER_CASCADE_DELETE=True, outside duplicates are left untouched.

        The caller (async_delete_crawl_task) handles deletion of outside-scope
        duplicates separately via bulk_delete_findings.
        """
        original = self._create_finding(self.test1, "Original")
        outside_dupe = self._create_finding(self.test2, "Outside Dupe")
        self._make_duplicate(outside_dupe, original)

        with impersonate(self.testuser):
            prepare_duplicates_for_delete(self.test1)

        outside_dupe.refresh_from_db()
        # Outside dupe is still a duplicate — not reconfigured or deleted
        self.assertTrue(outside_dupe.duplicate)
        self.assertEqual(outside_dupe.duplicate_finding_id, original.id)

    def test_multiple_originals(self):
        """Multiple originals in the same test each get their clusters handled."""
        original_a = self._create_finding(self.test1, "Original A")
        original_b = self._create_finding(self.test1, "Original B")
        dupe_of_a = self._create_finding(self.test2, "Dupe of A")
        dupe_of_b = self._create_finding(self.test2, "Dupe of B")
        self._make_duplicate(dupe_of_a, original_a)
        self._make_duplicate(dupe_of_b, original_b)

        with impersonate(self.testuser):
            prepare_duplicates_for_delete(self.test1)

        dupe_of_a.refresh_from_db()
        dupe_of_b.refresh_from_db()

        # Both become new originals
        self.assertFalse(dupe_of_a.duplicate)
        self.assertIsNone(dupe_of_a.duplicate_finding)
        self.assertFalse(dupe_of_b.duplicate)
        self.assertIsNone(dupe_of_b.duplicate_finding)

    def test_original_status_copied_to_new_original(self):
        """New original inherits active/is_mitigated status from deleted original."""
        original = self._create_finding(self.test1, "Original")
        original.active = False
        original.is_mitigated = True
        super(Finding, original).save(skip_validation=True)

        outside_dupe = self._create_finding(self.test2, "Outside Dupe")
        self._make_duplicate(outside_dupe, original)

        with impersonate(self.testuser):
            prepare_duplicates_for_delete(self.test1)

        outside_dupe.refresh_from_db()
        self.assertFalse(outside_dupe.duplicate)
        self.assertFalse(outside_dupe.active)
        self.assertTrue(outside_dupe.is_mitigated)

    def test_found_by_copied_to_new_original(self):
        """New original inherits found_by from deleted original."""
        original = self._create_finding(self.test1, "Original")
        test_type_2 = Test_Type.objects.get_or_create(name="ZAP Scan")[0]
        original.found_by.add(self.test_type)
        original.found_by.add(test_type_2)

        outside_dupe = self._create_finding(self.test2, "Outside Dupe")
        self._make_duplicate(outside_dupe, original)

        with impersonate(self.testuser):
            prepare_duplicates_for_delete(self.test1)

        outside_dupe.refresh_from_db()
        found_by_ids = set(outside_dupe.found_by.values_list("id", flat=True))
        self.assertIn(self.test_type.id, found_by_ids)
        self.assertIn(test_type_2.id, found_by_ids)

    def test_delete_finding_reconfigures_cross_engagement_duplicate(self):
        """
        Deleting an original finding makes its cross-engagement duplicate standalone.

        Setup: product with eng A (finding A, original) and eng B (finding B, duplicate of A).
        Action: delete finding A.
        Expected: finding B becomes a standalone finding (not duplicate, active, no duplicate_finding).
        """
        finding_a = self._create_finding(self.test1, "Original A")
        finding_a.active = True
        finding_a.is_mitigated = False
        super(Finding, finding_a).save(skip_validation=True)

        finding_b = self._create_finding(self.test3, "Duplicate B")
        self._make_duplicate(finding_b, finding_a)

        # Verify setup
        finding_b.refresh_from_db()
        self.assertTrue(finding_b.duplicate)
        self.assertEqual(finding_b.duplicate_finding_id, finding_a.id)

        # Delete finding A — triggers finding_delete signal -> reconfigure_duplicate_cluster
        with impersonate(self.testuser):
            finding_a.delete()

        # Finding B should now be standalone
        finding_b.refresh_from_db()
        self.assertFalse(finding_b.duplicate)
        self.assertIsNone(finding_b.duplicate_finding)
        self.assertTrue(finding_b.active)
        self.assertFalse(finding_b.is_mitigated)

    def test_delete_product_with_cross_engagement_duplicates(self):
        """
        Deleting a product with cross-engagement duplicates succeeds without FK violations.

        Setup: product with eng A (finding A, original) and eng B (finding B, duplicate of A).
        Action: delete the entire product via async_delete_crawl_task.
        Expected: product and all findings are deleted without errors.
        """
        from dojo.utils import async_delete  # noqa: PLC0415

        finding_a = self._create_finding(self.test1, "Original A")
        finding_a.active = True
        finding_a.is_mitigated = False
        super(Finding, finding_a).save(skip_validation=True)

        finding_b = self._create_finding(self.test3, "Duplicate B")
        self._make_duplicate(finding_b, finding_a)

        product_id = self.product.id
        finding_a_id = finding_a.id
        finding_b_id = finding_b.id

        with impersonate(self.testuser):
            async_del = async_delete()
            async_del.delete(self.product)

        # Everything should be gone
        self.assertFalse(Product.objects.filter(id=product_id).exists())
        self.assertFalse(Finding.objects.filter(id=finding_a_id).exists())
        self.assertFalse(Finding.objects.filter(id=finding_b_id).exists())

    def test_delete_product_with_tags(self):
        """
        Deleting a product with tags on product and findings succeeds
        and correctly decrements tag counts.
        """
        from dojo.utils import async_delete  # noqa: PLC0415

        # Add tags to product and findings
        self.product.tags = "product-tag, shared-tag"
        self.product.save()

        finding_a = self._create_finding(self.test1, "Tagged Finding A")
        finding_a.tags = "finding-tag, shared-tag"
        super(Finding, finding_a).save(skip_validation=True)

        finding_b = self._create_finding(self.test3, "Tagged Finding B")
        finding_b.tags = "finding-tag"
        super(Finding, finding_b).save(skip_validation=True)

        product_id = self.product.id
        finding_a_id = finding_a.id
        finding_b_id = finding_b.id

        # Get tag models to check counts after deletion
        # Product and Finding have separate tag models in tagulous
        product_tag_model = Product._meta.get_field("tags").related_model
        finding_tag_model = Finding._meta.get_field("tags").related_model
        product_shared_tag = product_tag_model.objects.get(name="shared-tag")
        finding_shared_tag = finding_tag_model.objects.get(name="shared-tag")

        with impersonate(self.testuser):
            async_del = async_delete()
            async_del.delete(self.product)

        # Everything should be gone
        self.assertFalse(Product.objects.filter(id=product_id).exists())
        self.assertFalse(Finding.objects.filter(id=finding_a_id).exists())
        self.assertFalse(Finding.objects.filter(id=finding_b_id).exists())

        # Tag counts should be decremented to 0 (all referencing objects deleted).
        # Tag counts are not used in DefectDojo, but we still verify them to ensure
        # our bulk removal method doesn't break tagulous's internal bookkeeping.
        product_shared_tag.refresh_from_db()
        self.assertEqual(product_shared_tag.count, 0)
        finding_shared_tag.refresh_from_db()
        self.assertEqual(finding_shared_tag.count, 0)

    def test_delete_product_with_reverse_m2m_relations(self):
        """
        Deleting a product with findings that have reverse M2M relations succeeds.

        Reverse M2M through tables (M2M fields on other models pointing to Finding)
        must be cleared before findings are deleted. This tests:
        - Finding_Group.findings (dojo_finding_group_findings)
        - Risk_Acceptance.accepted_findings (dojo_risk_acceptance_accepted_findings)
        """
        from dojo.utils import async_delete  # noqa: PLC0415

        finding_a = self._create_finding(self.test1, "Grouped Finding A")
        finding_b = self._create_finding(self.test1, "Grouped Finding B")
        finding_c = self._create_finding(self.test1, "Risk Accepted Finding")

        # Finding_Group with findings
        creator = Dojo_User.objects.first() or Dojo_User.objects.create(username="testcreator")
        group = Finding_Group.objects.create(
            name="Test Group",
            test=self.test1,
            creator=creator,
        )
        group.findings.add(finding_a, finding_b)

        # Risk_Acceptance with accepted findings
        ra = Risk_Acceptance.objects.create(
            name="Test RA",
            owner=self.testuser,
        )
        ra.accepted_findings.add(finding_c)
        # Link to engagement so we can verify it survives
        self.engagement1.risk_acceptance.add(ra)

        product_id = self.product.id
        group_id = group.id
        ra_id = ra.id

        with impersonate(self.testuser):
            async_del = async_delete()
            async_del.delete(self.product)

        self.assertFalse(Product.objects.filter(id=product_id).exists())
        self.assertFalse(Finding_Group.objects.filter(id=group_id).exists())
        self.assertFalse(Finding.objects.filter(id__in=[finding_a.id, finding_b.id, finding_c.id]).exists())
        # Risk_Acceptance itself survives (no FK to product/engagement),
        # but its accepted_findings M2M entries should be gone
        self.assertTrue(Risk_Acceptance.objects.filter(id=ra_id).exists())
        self.assertEqual(Risk_Acceptance.objects.get(id=ra_id).accepted_findings.count(), 0)
