"""
Unit tests for cascade_delete_related_objects() in dojo.utils_cascade_delete.

Focused on preview mode and the preview_models filter parameter.
"""

import logging
from collections import Counter

from django.utils import timezone

from dojo.models import (
    Answered_Survey,
    Engagement,
    Engagement_Survey,
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

    """Tests for cascade_delete_related_objects(preview_only=True, preview_models=...)."""

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
        """preview_only=True accumulates counts into counter without deleting."""
        self._create_finding("F1")
        self._create_finding("F2")

        counter = Counter()
        cascade_delete_related_objects(
            Engagement,
            Engagement.objects.filter(pk=self.engagement.pk),
            preview_only=True,
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
            preview_only=True,
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
            preview_only=True,
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
            preview_only=True,
            counter=counter_full,
            preview_models=None,
        )

        counter_filtered = Counter()
        cascade_delete_related_objects(
            Engagement,
            Engagement.objects.filter(pk=self.engagement.pk),
            preview_only=True,
            counter=counter_filtered,
            preview_models={"Test", "Finding"},
        )

        # Full walk has at least as many distinct model types as filtered
        self.assertGreaterEqual(len(counter_full), len(counter_filtered))

    def test_preview_does_not_delete(self):
        """preview_only=True with preview_models never deletes any rows."""
        f = self._create_finding("F1")

        cascade_delete_related_objects(
            Engagement,
            Engagement.objects.filter(pk=self.engagement.pk),
            preview_only=True,
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
            preview_only=True,
            counter=counter,
            preview_models={"Test", "Finding"},
        )
        self.assertEqual(sum(counter.values()), 0)


class TestCascadeDeleteHiddenRelations(DojoTestCase):

    """
    Cascade deletion must follow reverse relations whose accessor is suppressed
    with ``related_name="...+"``.

    Regression: deleting an engagement (or a product/product_type containing one)
    that had an answered questionnaire raised
    ``IntegrityError: ... still referenced from table "dojo_answered_survey"``,
    because ``Answered_Survey.engagement`` uses ``related_name="engagement+"`` and
    the cascade walker iterated ``_meta.related_objects``, which omits hidden
    relations, so the ``Answered_Survey`` rows were never deleted.
    """

    def setUp(self):
        super().setUp()
        self.testuser = User.objects.create(
            username="cascade_hidden_test_user",
            is_staff=True,
            is_superuser=True,
        )
        UserContactInfo.objects.create(user=self.testuser, block_execution=True)
        self.system_settings(enable_deduplication=False)
        self.system_settings(enable_product_grade=False)

        self.product_type = Product_Type.objects.create(name="Cascade Hidden PT")
        self.product = Product.objects.create(
            name="Cascade Hidden Product",
            description="Test",
            prod_type=self.product_type,
        )
        self.engagement = Engagement.objects.create(
            name="Cascade Hidden Engagement",
            product=self.product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        self.survey = Engagement_Survey.objects.create(name="Cascade Hidden Survey")

    def _answered_survey(self):
        return Answered_Survey.objects.create(
            engagement=self.engagement,
            survey=self.survey,
        )

    def test_cascade_deletes_answered_survey_for_engagement(self):
        """The hidden ``engagement+`` child is deleted along with the engagement's relations."""
        answered = self._answered_survey()

        cascade_delete_related_objects(
            Engagement,
            Engagement.objects.filter(pk=self.engagement.pk),
        )

        self.assertFalse(
            Answered_Survey.objects.filter(pk=answered.pk).exists(),
            msg="Answered_Survey tied via related_name='engagement+' must be cascade-deleted",
        )

    def test_product_delete_with_answered_survey_does_not_violate_fk(self):
        """
        Deleting a product whose nested engagement has an answered survey must not
        raise a foreign-key IntegrityError (the engagement is deleted by raw SQL at a
        deeper recursion level, so the hidden child must be cleared first).
        """
        answered = self._answered_survey()

        # Before the fix this raised IntegrityError on the engagement's raw delete.
        cascade_delete_related_objects(
            Product,
            Product.objects.filter(pk=self.product.pk),
        )
        self.product.delete()

        self.assertFalse(Answered_Survey.objects.filter(pk=answered.pk).exists())
        self.assertFalse(Engagement.objects.filter(pk=self.engagement.pk).exists())
        self.assertFalse(Product.objects.filter(pk=self.product.pk).exists())

    def test_preview_counts_hidden_relation(self):
        """preview_only must also count the hidden ``Answered_Survey`` child."""
        self._answered_survey()

        counter = Counter()
        cascade_delete_related_objects(
            Engagement,
            Engagement.objects.filter(pk=self.engagement.pk),
            preview_only=True,
            counter=counter,
        )

        self.assertEqual(
            counter["Answered_Survey"], 1,
            msg=f"expected Answered_Survey count 1, got counter={dict(counter)}",
        )
