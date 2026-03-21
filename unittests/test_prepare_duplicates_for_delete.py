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
from dojo.models import Engagement, Finding, Product, Product_Type, Test, Test_Type, User, UserContactInfo

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
            prepare_duplicates_for_delete(test=self.test1)

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
            prepare_duplicates_for_delete(test=self.test1)

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
            prepare_duplicates_for_delete(test=self.test1)

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
            prepare_duplicates_for_delete(test=self.test1)

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
            prepare_duplicates_for_delete(engagement=self.engagement1)

        dupe.refresh_from_db()
        self.assertIsNone(dupe.duplicate_finding)
        self.assertFalse(dupe.duplicate)

    def test_engagement_scope_outside_reconfigure(self):
        """Outside-scope reconfiguration works at engagement level."""
        original = self._create_finding(self.test1, "Original in Eng 1")
        outside_dupe = self._create_finding(self.test3, "Dupe in Eng 2")
        self._make_duplicate(outside_dupe, original)

        with impersonate(self.testuser):
            prepare_duplicates_for_delete(engagement=self.engagement1)

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
            prepare_duplicates_for_delete(test=self.test1)

        inside_dupe.refresh_from_db()
        outside_dupe.refresh_from_db()

        # Inside dupe: FK cleared
        self.assertIsNone(inside_dupe.duplicate_finding)
        self.assertFalse(inside_dupe.duplicate)

        # Outside dupe: becomes new original
        self.assertFalse(outside_dupe.duplicate)
        self.assertIsNone(outside_dupe.duplicate_finding)

    @override_settings(DUPLICATE_CLUSTER_CASCADE_DELETE=True)
    def test_cascade_delete_setting(self):
        """When DUPLICATE_CLUSTER_CASCADE_DELETE=True, outside duplicates are deleted."""
        original = self._create_finding(self.test1, "Original")
        outside_dupe = self._create_finding(self.test2, "Outside Dupe")
        self._make_duplicate(outside_dupe, original)
        outside_dupe_id = outside_dupe.id

        with impersonate(self.testuser):
            prepare_duplicates_for_delete(test=self.test1)

        self.assertFalse(
            Finding.objects.filter(id=outside_dupe_id).exists(),
            "Outside duplicate should be cascade-deleted",
        )

    def test_multiple_originals(self):
        """Multiple originals in the same test each get their clusters handled."""
        original_a = self._create_finding(self.test1, "Original A")
        original_b = self._create_finding(self.test1, "Original B")
        dupe_of_a = self._create_finding(self.test2, "Dupe of A")
        dupe_of_b = self._create_finding(self.test2, "Dupe of B")
        self._make_duplicate(dupe_of_a, original_a)
        self._make_duplicate(dupe_of_b, original_b)

        with impersonate(self.testuser):
            prepare_duplicates_for_delete(test=self.test1)

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
            prepare_duplicates_for_delete(test=self.test1)

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
            prepare_duplicates_for_delete(test=self.test1)

        outside_dupe.refresh_from_db()
        found_by_ids = set(outside_dupe.found_by.values_list("id", flat=True))
        self.assertIn(self.test_type.id, found_by_ids)
        self.assertIn(test_type_2.id, found_by_ids)
