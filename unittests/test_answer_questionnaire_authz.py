"""
Regression tests for authorization on ``answer_questionnaire``
(``dojo/survey/ui/views.py``), the engagement-scoped route that reads and
overwrites the answers of an ``Answered_Survey``.

The object-level ``edit`` check on this route used to be nested under
``if not allow_anonymous_survey_repsonse``, so enabling that instance-wide
setting removed the check as a side effect. The setting exists for the separate,
login-exempt empty-survey route, not this one. With it enabled, any
authenticated user could read and overwrite another tenant's answered
questionnaire by enumerating ``(eid, sid)``.

These tests pin the contract: the ``edit`` check runs regardless of the
anonymous-response setting.
"""
from django.urls import reverse
from django.utils import timezone

from dojo.models import (
    Answered_Survey,
    Dojo_User,
    Engagement,
    Engagement_Survey,
    Product,
    Product_Type,
    System_Settings,
    TextAnswer,
    TextQuestion,
)
from unittests.dojo_test_case import DojoTestCase

VICTIM_ANSWER = "victim-secret-questionnaire-answer"


class AnswerQuestionnaireAuthorizationTests(DojoTestCase):

    @classmethod
    def setUpTestData(cls):
        cls.prod_type = Product_Type.objects.create(name="answer_authz_pt")
        cls.victim_product = Product.objects.create(
            name="answer_authz_victim", description="v", prod_type=cls.prod_type,
        )
        cls.attacker_product = Product.objects.create(
            name="answer_authz_attacker", description="a", prod_type=cls.prod_type,
        )

        # Attacker: authenticated, member of only the attacker product, with no
        # access to the victim tenant.
        cls.attacker = Dojo_User.objects.create(username="answer_authz_attacker_user", is_active=True)
        cls.attacker_product.authorized_users.add(cls.attacker)

        # Legitimate member of the victim product (positive control).
        cls.member = Dojo_User.objects.create(username="answer_authz_member_user", is_active=True)
        cls.victim_product.authorized_users.add(cls.member)

        cls.template = Engagement_Survey.objects.create(name="answer_authz_template", description="t")
        cls.question = TextQuestion.objects.create(text="answer_authz_question", order=1)
        cls.template.questions.add(cls.question)

        cls.victim_engagement = Engagement.objects.create(
            name="answer_authz_victim_eng",
            product=cls.victim_product,
            target_start=timezone.now().date(),
            target_end=timezone.now().date(),
        )
        cls.victim_survey = Answered_Survey.objects.create(
            survey=cls.template, engagement=cls.victim_engagement,
        )
        cls.victim_answer = TextAnswer.objects.create(
            answered_survey=cls.victim_survey, question=cls.question, answer=VICTIM_ANSWER,
        )

    def setUp(self):
        super().setUp()
        # The setting whose enablement used to strip the check.
        System_Settings.objects.get_or_create(id=1)
        System_Settings.objects.update(allow_anonymous_survey_repsonse=True)

    def _answer_url(self):
        return reverse("answer_questionnaire", args=(self.victim_engagement.id, self.victim_survey.id))

    def test_answer_get_denied_for_unauthorized_user(self):
        self.client.force_login(self.attacker)
        response = self.client.get(self._answer_url())
        self.assertNotContains(response, VICTIM_ANSWER, status_code=400)

    def test_answer_post_denied_for_unauthorized_user(self):
        self.client.force_login(self.attacker)
        response = self.client.post(
            self._answer_url(),
            data={f"{self.question.id}-answer": "overwritten-by-attacker"},
        )
        self.assertEqual(response.status_code, 400)
        self.victim_answer.refresh_from_db()
        self.victim_survey.refresh_from_db()
        self.assertEqual(self.victim_answer.answer, VICTIM_ANSWER)
        self.assertIsNone(self.victim_survey.responder_id)
        self.assertFalse(self.victim_survey.completed)

    def test_authorized_member_can_reach_answer_page(self):
        self.client.force_login(self.member)
        response = self.client.get(self._answer_url())
        self.assertEqual(response.status_code, 200)
