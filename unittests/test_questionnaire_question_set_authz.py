"""
Regression tests for authorization on ``edit_questionnaire_questions``
(``dojo/survey/ui/views.py``), the route that replaces the question set of an
existing questionnaire and resets every answered instance of it to uncompleted.

The route used to accept ``dojo.add_engagement_survey`` OR
``dojo.change_engagement_survey``, so a user holding only the create permission
could rewrite any questionnaire in the instance. The sibling routes each carry
one verb and one permission, and the permission chart documents editing an
existing questionnaire as the change permission.

These tests pin the contract: only the change permission reaches this route.
"""
from django.contrib.auth.models import Permission
from django.urls import reverse
from django.utils import timezone

from dojo.models import (
    Answered_Survey,
    Dojo_User,
    Engagement,
    Engagement_Survey,
    Product,
    Product_Type,
    TextQuestion,
)
from unittests.dojo_test_case import DojoTestCase


def _config_permission(codename):
    return Permission.objects.get(codename=codename, content_type__app_label="dojo")


class EditQuestionnaireQuestionsAuthorizationTests(DojoTestCase):

    @classmethod
    def setUpTestData(cls):
        cls.prod_type = Product_Type.objects.create(name="qset_authz_pt")
        cls.victim_product = Product.objects.create(
            name="qset_authz_victim", description="v", prod_type=cls.prod_type,
        )
        cls.victim_engagement = Engagement.objects.create(
            name="qset_authz_victim_eng",
            product=cls.victim_product,
            target_start=timezone.now().date(),
            target_end=timezone.now().date(),
        )

        cls.original_question = TextQuestion.objects.create(text="qset_authz_original", order=1)
        cls.substitute_question = TextQuestion.objects.create(text="qset_authz_substitute", order=2)

        cls.questionnaire = Engagement_Survey.objects.create(name="qset_authz_template", description="t")
        cls.questionnaire.questions.add(cls.original_question)

        cls.answered = Answered_Survey.objects.create(
            survey=cls.questionnaire,
            engagement=cls.victim_engagement,
            completed=True,
            answered_on=timezone.now().date(),
        )

        # Holds only the create permission, and no membership on the victim tenant.
        cls.creator = Dojo_User.objects.create(username="qset_authz_creator", is_active=True)
        cls.creator.user_permissions.add(_config_permission("add_engagement_survey"))

        # Holds neither questionnaire permission.
        cls.outsider = Dojo_User.objects.create(username="qset_authz_outsider", is_active=True)

        # Holds the change permission (positive control).
        cls.editor = Dojo_User.objects.create(username="qset_authz_editor", is_active=True)
        cls.editor.user_permissions.add(_config_permission("change_engagement_survey"))

    def _url(self):
        return reverse("edit_questionnaire_questions", args=(self.questionnaire.id,))

    def _assert_questionnaire_untouched(self):
        self.answered.refresh_from_db()
        self.assertEqual(
            [self.original_question.id],
            list(self.questionnaire.questions.values_list("id", flat=True)),
        )
        self.assertTrue(self.answered.completed)
        self.assertIsNotNone(self.answered.answered_on)

    def test_get_denied_for_create_only_user(self):
        self.client.force_login(self.creator)
        response = self.client.get(self._url())
        self.assertEqual(response.status_code, 400)

    def test_post_denied_for_create_only_user(self):
        self.client.force_login(self.creator)
        response = self.client.post(self._url(), data={"questions": [self.substitute_question.id]})
        self.assertEqual(response.status_code, 400)
        self._assert_questionnaire_untouched()

    def test_post_denied_for_user_without_questionnaire_permissions(self):
        self.client.force_login(self.outsider)
        response = self.client.post(self._url(), data={"questions": [self.substitute_question.id]})
        self.assertEqual(response.status_code, 400)
        self._assert_questionnaire_untouched()

    def test_user_with_change_permission_can_edit_the_question_set(self):
        self.client.force_login(self.editor)
        self.assertEqual(self.client.get(self._url()).status_code, 200)
        response = self.client.post(self._url(), data={"questions": [self.substitute_question.id]})
        self.assertEqual(response.status_code, 302)
        self.answered.refresh_from_db()
        self.assertEqual(
            [self.substitute_question.id],
            list(self.questionnaire.questions.values_list("id", flat=True)),
        )
        self.assertFalse(self.answered.completed)

    def test_create_only_user_is_not_redirected_into_the_question_set_editor(self):
        self.client.force_login(self.creator)
        response = self.client.post(
            reverse("create_questionnaire"),
            data={"name": "qset_authz_new", "description": "d", "active": True, "add_questions": ""},
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(reverse("questionnaire"), response["Location"])
