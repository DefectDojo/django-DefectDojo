"""
Unit tests for cascade_delete_related_objects() in dojo.utils_cascade_delete.

Focused on preview mode and the preview_models filter parameter.
"""

import logging
from collections import Counter

from crum import impersonate
from django.db import connection
from django.utils import timezone

from dojo.models import (
    Answer,
    Answered_Survey,
    Choice,
    ChoiceAnswer,
    ChoiceQuestion,
    Engagement,
    Engagement_Survey,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
    TextAnswer,
    TextQuestion,
    User,
    UserContactInfo,
)
from dojo.utils import async_delete
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


class TestCascadeDeleteAnsweredSurveyWithAnswers(DojoTestCase):

    """
    Cascade deletion of an answered questionnaire that actually has answers.

    ``Answer``, ``TextAnswer`` and ``ChoiceAnswer`` are django-polymorphic models, so
    the relations ``Answered_Survey -> Answer`` and ``Answer -> TextAnswer/ChoiceAnswer``
    (``answer_ptr``) carry a ``PolymorphicGuard`` on_delete that wraps CASCADE. The
    walker must unwrap it, otherwise the answers are skipped and deleting the
    ``Answered_Survey`` row by raw SQL leaves ``dojo_answer`` rows pointing at it.

    Postgres foreign keys are ``DEFERRABLE INITIALLY DEFERRED`` and a TestCase never
    commits, so each delete test calls ``connection.check_constraints()`` to surface
    any dangling reference.
    """

    def setUp(self):
        super().setUp()
        self.testuser = User.objects.create(
            username="cascade_answers_test_user",
            is_staff=True,
            is_superuser=True,
        )
        UserContactInfo.objects.create(user=self.testuser, block_execution=True)
        self.system_settings(enable_deduplication=False)
        self.system_settings(enable_product_grade=False)

        self.product_type = Product_Type.objects.create(name="Cascade Answers PT")
        self.product = Product.objects.create(
            name="Cascade Answers Product",
            description="Test",
            prod_type=self.product_type,
        )
        self.engagement = Engagement.objects.create(
            name="Cascade Answers Engagement",
            product=self.product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )

        self.text_question = TextQuestion.objects.create(text="Cascade text question", order=1)
        self.choice_question = ChoiceQuestion.objects.create(
            text="Cascade choice question", order=2, multichoice=True,
        )
        self.choices = [
            Choice.objects.create(label="Cascade choice A", order=1),
            Choice.objects.create(label="Cascade choice B", order=2),
        ]
        self.choice_question.choices.set(self.choices)
        self.survey = Engagement_Survey.objects.create(name="Cascade Answers Survey")
        self.survey.questions.set([self.text_question, self.choice_question])

        self.answered = Answered_Survey.objects.create(
            engagement=self.engagement,
            survey=self.survey,
            completed=True,
        )
        self.text_answer = TextAnswer.objects.create(
            question=self.text_question,
            answered_survey=self.answered,
            answer="Cascade text answer",
        )
        self.choice_answer = ChoiceAnswer.objects.create(
            question=self.choice_question,
            answered_survey=self.answered,
        )
        self.choice_answer.answer.set(self.choices)
        self.choice_through = ChoiceAnswer.answer.through

    def _async_delete(self, obj):
        # block_execution=True plus impersonate runs the delete task synchronously,
        # through the same cascade path the UI/API delete uses.
        with impersonate(self.testuser):
            async_delete().delete(obj)

    def _assert_answers_gone(self):
        # Surfaces deferred FK violations (e.g. dojo_answer -> dojo_answered_survey).
        connection.check_constraints()
        self.assertFalse(Answered_Survey.objects.filter(pk=self.answered.pk).exists())
        self.assertFalse(
            Answer.objects.filter(pk__in=[self.text_answer.pk, self.choice_answer.pk]).exists(),
        )
        self.assertFalse(TextAnswer.objects.filter(pk=self.text_answer.pk).exists())
        self.assertFalse(ChoiceAnswer.objects.filter(pk=self.choice_answer.pk).exists())
        self.assertFalse(
            self.choice_through.objects.filter(choiceanswer_id=self.choice_answer.pk).exists(),
            msg="ChoiceAnswer.answer M2M rows must be cleared",
        )
        # The survey definition, its questions and the choices are not owned by the
        # engagement and must survive.
        self.assertTrue(Engagement_Survey.objects.filter(pk=self.survey.pk).exists())
        self.assertEqual(
            Choice.objects.filter(pk__in=[c.pk for c in self.choices]).count(), 2,
        )
        self.assertTrue(TextQuestion.objects.filter(pk=self.text_question.pk).exists())
        self.assertTrue(ChoiceQuestion.objects.filter(pk=self.choice_question.pk).exists())

    def test_engagement_delete_removes_answers(self):
        self._async_delete(self.engagement)

        self.assertFalse(Engagement.objects.filter(pk=self.engagement.pk).exists())
        self._assert_answers_gone()

    def test_product_delete_removes_answers(self):
        self._async_delete(self.product)

        self.assertFalse(Product.objects.filter(pk=self.product.pk).exists())
        self.assertFalse(Engagement.objects.filter(pk=self.engagement.pk).exists())
        self._assert_answers_gone()

    def test_product_type_delete_removes_answers(self):
        self._async_delete(self.product_type)

        self.assertFalse(Product_Type.objects.filter(pk=self.product_type.pk).exists())
        self.assertFalse(Product.objects.filter(pk=self.product.pk).exists())
        self.assertFalse(Engagement.objects.filter(pk=self.engagement.pk).exists())
        self._assert_answers_gone()

    def test_preview_counts_answers(self):
        counter = Counter()
        cascade_delete_related_objects(
            Engagement,
            Engagement.objects.filter(pk=self.engagement.pk),
            preview_only=True,
            counter=counter,
        )

        self.assertEqual(counter["Answered_Survey"], 1, msg=f"counter={dict(counter)}")
        self.assertEqual(counter["Answer"], 2, msg=f"counter={dict(counter)}")
        self.assertEqual(counter["TextAnswer"], 1, msg=f"counter={dict(counter)}")
        self.assertEqual(counter["ChoiceAnswer"], 1, msg=f"counter={dict(counter)}")
        # Preview must not delete anything.
        self.assertTrue(Answer.objects.filter(pk=self.text_answer.pk).exists())
