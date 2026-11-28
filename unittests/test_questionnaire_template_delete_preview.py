from django.contrib.auth.models import Permission
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone

from dojo.models import (
    Answered_Survey,
    Dojo_User,
    Engagement,
    Engagement_Survey,
    Product,
    Product_Type,
    TextAnswer,
    TextQuestion,
)
from unittests.dojo_test_case import DojoTestCase

HIDDEN_ANSWER = "qn_tpl_preview_other_product_answer"
OWN_ANSWER = "qn_tpl_preview_own_product_answer"


@override_settings(DELETE_PREVIEW=True)
class QuestionnaireTemplateDeletePreviewTests(DojoTestCase):

    @classmethod
    def setUpTestData(cls):
        prod_type = Product_Type.objects.create(name="qn_tpl_preview_pt")
        other_product = Product.objects.create(name="qn_tpl_preview_other", description="o", prod_type=prod_type)
        own_product = Product.objects.create(name="qn_tpl_preview_own", description="m", prod_type=prod_type)

        cls.manager = Dojo_User.objects.create(username="qn_tpl_preview_manager", is_active=True)
        own_product.authorized_users.add(cls.manager)
        cls.manager.user_permissions.add(
            Permission.objects.get(content_type__app_label="dojo", codename="delete_engagement_survey"),
        )

        cls.question = TextQuestion.objects.create(text="qn_tpl_preview_question", order=1)
        cls.template = Engagement_Survey.objects.create(name="qn_tpl_preview_template", description="t")
        cls.template.questions.add(cls.question)
        cls.other_engagement = cls.answer(other_product, HIDDEN_ANSWER)
        cls.own_engagement = cls.answer(own_product, OWN_ANSWER)

    @classmethod
    def answer(cls, product, text):
        today = timezone.now().date()
        engagement = Engagement.objects.create(name=f"{product.name}_eng", product=product, target_start=today, target_end=today)
        answered = Answered_Survey.objects.create(survey=cls.template, engagement=engagement)
        TextAnswer.objects.create(question=cls.question, answered_survey=answered, answer=text)
        return engagement

    def preview(self, user):
        self.client.force_login(user)
        response = self.client.get(reverse("delete_questionnaire", args=(self.template.id,)))
        self.assertEqual(response.status_code, 200)
        return response.content.decode()

    def test_preview_hides_answers_of_engagements_the_user_cannot_view(self):
        page = self.preview(self.manager)
        self.assertNotIn(HIDDEN_ANSWER, page)
        self.assertNotIn(OWN_ANSWER, page)

    def test_preview_lists_answers_when_the_user_can_view_every_engagement(self):
        self.other_engagement.product.authorized_users.add(self.manager)
        page = self.preview(self.manager)
        self.assertIn(HIDDEN_ANSWER, page)
        self.assertIn(OWN_ANSWER, page)

    def test_superuser_sees_the_full_preview(self):
        page = self.preview(Dojo_User.objects.create(username="qn_tpl_preview_admin", is_superuser=True, is_active=True))
        self.assertIn(HIDDEN_ANSWER, page)

    def test_delete_still_works_for_the_permission_holder(self):
        self.client.force_login(self.manager)
        response = self.client.post(
            reverse("delete_questionnaire", args=(self.template.id,)),
            data={"id": self.template.id},
        )
        self.assertEqual(response.status_code, 302)
        self.assertFalse(Engagement_Survey.objects.filter(id=self.template.id).exists())
