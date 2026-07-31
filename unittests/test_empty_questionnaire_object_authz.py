"""
Regression tests for authorization on the esid-keyed "empty questionnaire"
read and delete routes (``dojo/survey/ui/views.py``).

``view_empty_survey`` and ``delete_empty_questionnaire`` are mapped in
``URL_PERMISSIONS`` to a bare configuration permission, which the
``AuthorizationMiddleware`` treats as a complete gate: it never loads the
object. Both views then fetched the ``Answered_Survey`` by primary key with no
further check, so a user holding the questionnaire configuration permission
could read and delete any answered questionnaire in the instance -- including
ones linked to engagements in products they have no access to -- by enumerating
primary keys.

The engagement-keyed route for the same data (``view_questionnaire``) is
authorized against its engagement, so the object-scoped model is the intended
one. These tests fix that contract for the esid-keyed routes:

* an engagement-linked questionnaire requires view/edit on that engagement,
  even with the configuration permission;
* an unlinked ("empty") questionnaire still works off the configuration
  permission alone, which is the route's actual purpose.
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
)
from unittests.dojo_test_case import DojoTestCase


class EmptyQuestionnaireObjectAuthorizationTests(DojoTestCase):

    """
    A questionnaire manager who holds the view and delete configuration
    permissions but is not a member of the victim product.
    """

    @classmethod
    def setUpTestData(cls):
        cls.prod_type = Product_Type.objects.create(name="qn_obj_authz_pt")
        cls.victim_product = Product.objects.create(
            name="qn_obj_authz_victim", description="v", prod_type=cls.prod_type,
        )
        cls.manager_product = Product.objects.create(
            name="qn_obj_authz_manager", description="m", prod_type=cls.prod_type,
        )

        cls.manager = Dojo_User.objects.create(username="qn_obj_authz_manager_user", is_active=True)
        cls.manager_product.authorized_users.add(cls.manager)
        for codename in ("view_engagement_survey", "delete_engagement_survey"):
            cls.manager.user_permissions.add(
                Permission.objects.get(content_type__app_label="dojo", codename=codename),
            )

        cls.template = Engagement_Survey.objects.create(name="qn_obj_authz_template", description="t")

        cls.victim_engagement = Engagement.objects.create(
            name="qn_obj_authz_victim_eng",
            product=cls.victim_product,
            target_start=timezone.now().date(),
            target_end=timezone.now().date(),
        )
        cls.victim_survey = Answered_Survey.objects.create(
            survey=cls.template, engagement=cls.victim_engagement,
        )

        cls.manager_engagement = Engagement.objects.create(
            name="qn_obj_authz_manager_eng",
            product=cls.manager_product,
            target_start=timezone.now().date(),
            target_end=timezone.now().date(),
        )
        cls.manager_survey = Answered_Survey.objects.create(
            survey=cls.template, engagement=cls.manager_engagement,
        )

        cls.unlinked_survey = Answered_Survey.objects.create(survey=cls.template, engagement=None)

    # ------------------------------------------------------------------
    # Read: the configuration permission is not enough for a questionnaire
    # linked to an engagement the user cannot view.
    # ------------------------------------------------------------------
    def test_view_denied_for_unauthorized_engagement(self):
        self.client.force_login(self.manager)
        response = self.client.get(reverse("view_empty_survey", args=(self.victim_survey.id,)))
        self.assertEqual(response.status_code, 400)

    def test_view_allowed_for_own_engagement(self):
        self.client.force_login(self.manager)
        response = self.client.get(reverse("view_empty_survey", args=(self.manager_survey.id,)))
        self.assertEqual(response.status_code, 200)

    def test_view_allowed_for_unlinked_questionnaire(self):
        self.client.force_login(self.manager)
        response = self.client.get(reverse("view_empty_survey", args=(self.unlinked_survey.id,)))
        self.assertEqual(response.status_code, 200)

    # ------------------------------------------------------------------
    # Delete: same contract, and the object must survive a denied attempt.
    # ------------------------------------------------------------------
    def test_delete_page_denied_for_unauthorized_engagement(self):
        self.client.force_login(self.manager)
        response = self.client.get(reverse("delete_empty_questionnaire", args=(self.victim_survey.id,)))
        self.assertEqual(response.status_code, 400)

    def test_delete_post_denied_for_unauthorized_engagement(self):
        self.client.force_login(self.manager)
        response = self.client.post(
            reverse("delete_empty_questionnaire", args=(self.victim_survey.id,)),
            data={"id": self.victim_survey.id},
        )
        self.assertEqual(response.status_code, 400)
        self.assertTrue(Answered_Survey.objects.filter(id=self.victim_survey.id).exists())

    def test_delete_post_allowed_for_unlinked_questionnaire(self):
        self.client.force_login(self.manager)
        response = self.client.post(
            reverse("delete_empty_questionnaire", args=(self.unlinked_survey.id,)),
            data={"id": self.unlinked_survey.id},
        )
        self.assertEqual(response.status_code, 302)
        self.assertFalse(Answered_Survey.objects.filter(id=self.unlinked_survey.id).exists())
