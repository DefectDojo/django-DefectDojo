"""
Unit tests for cascade_delete_related_objects() in dojo.utils_cascade_delete.

Focused on preview mode and the preview_models filter parameter.
"""

import logging
from collections import Counter

from django.utils import timezone

from dojo.models import (
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
    User,
    UserContactInfo,
)
from dojo.utils_cascade_delete import cascade_delete_related_objects

from .dojo_test_case import DojoTestCase

logger = logging.getLogger(__name__)


class TestCascadeDeletePreviewModels(DojoTestCase):
    """Tests for cascade_delete_related_objects(preview=True, preview_models=...)."""

    def setUp(self):
        super().setUp()
        self.testuser = User.objects.create(
            username="cascade_preview_test_user",
            is_staff=True,
            is_superuser=True,
        )
        UserContactInfo.objects.create(user=self.testuser, block_execution=True)
        self.system_settings(enable_deduplication=False)
        self.system_settings(enable_product_grade=False)

        self.product_type = Product_Type.objects.create(name="Cascade Preview PT")
        self.product = Product.objects.create(
            name="Cascade Preview Product",
            description="Test",
            prod_type=self.product_type,
        )
        self.test_type = Test_Type.objects.get_or_create(name="Manual Test")[0]
        self.engagement = Engagement.objects.create(
            name="Cascade Preview Engagement",
            product=self.product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        self.test = Test.objects.create(
            engagement=self.engagement,
            test_type=self.test_type,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )

    def _create_finding(self, title="Finding"):
        return Finding.objects.create(
            test=self.test,
            title=title,
            severity="High",
            description="Test",
            mitigation="Test",
            impact="Test",
            reporter=self.testuser,
        )

    def test_preview_counts_cascade_relations(self):
        """preview=True accumulates counts into counter without deleting."""
        self._create_finding("F1")
        self._create_finding("F2")

        counter = Counter()
        cascade_delete_related_objects(
            Engagement,
            Engagement.objects.filter(pk=self.engagement.pk),
            preview=True,
            counter=counter,
        )

        self.assertGreater(counter["Test"], 0)
        self.assertGreater(counter["Finding"], 0)
        # Nothing deleted
        self.assertTrue(Engagement.objects.filter(pk=self.engagement.pk).exists())
        self.assertTrue(Finding.objects.filter(test=self.test).count() == 2)

    def test_preview_models_skips_count_for_untracked(self):
        """With preview_models set, untracked models are not counted."""
        self._create_finding("F1")

        tracked = {"Test", "Finding"}
        counter = Counter()
        cascade_delete_related_objects(
            Engagement,
            Engagement.objects.filter(pk=self.engagement.pk),
            preview=True,
            counter=counter,
            preview_models=tracked,
        )

        for model_name in counter:
            self.assertIn(model_name, tracked, msg=f"{model_name} should not be counted")

    def test_preview_models_still_counts_tracked(self):
        """With preview_models set, tracked models ARE counted."""
        self._create_finding("F1")
        self._create_finding("F2")

        counter = Counter()
        cascade_delete_related_objects(
            Engagement,
            Engagement.objects.filter(pk=self.engagement.pk),
            preview=True,
            counter=counter,
            preview_models={"Test", "Finding"},
        )

        self.assertEqual(counter["Test"], 1)
        self.assertEqual(counter["Finding"], 2)

    def test_preview_none_preview_models_counts_all(self):
        """preview_models=None (default) counts every CASCADE relation."""
        self._create_finding("F1")

        counter_full = Counter()
        cascade_delete_related_objects(
            Engagement,
            Engagement.objects.filter(pk=self.engagement.pk),
            preview=True,
            counter=counter_full,
            preview_models=None,
        )

        counter_filtered = Counter()
        cascade_delete_related_objects(
            Engagement,
            Engagement.objects.filter(pk=self.engagement.pk),
            preview=True,
            counter=counter_filtered,
            preview_models={"Test", "Finding"},
        )

        # Full walk has at least as many distinct model types as filtered
        self.assertGreaterEqual(len(counter_full), len(counter_filtered))

    def test_preview_does_not_delete(self):
        """preview=True with preview_models never deletes any rows."""
        f = self._create_finding("F1")

        cascade_delete_related_objects(
            Engagement,
            Engagement.objects.filter(pk=self.engagement.pk),
            preview=True,
            counter=Counter(),
            preview_models={"Test", "Finding"},
        )

        self.assertTrue(Finding.objects.filter(pk=f.pk).exists())
        self.assertTrue(Test.objects.filter(pk=self.test.pk).exists())
        self.assertTrue(Engagement.objects.filter(pk=self.engagement.pk).exists())

    def test_preview_empty_scope_returns_empty_counter(self):
        """No matching records → empty counter."""
        counter = Counter()
        cascade_delete_related_objects(
            Engagement,
            Engagement.objects.filter(pk=999999),
            preview=True,
            counter=counter,
            preview_models={"Test", "Finding"},
        )
        self.assertEqual(sum(counter.values()), 0)
