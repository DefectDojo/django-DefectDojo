"""
Regression tests for authorization on the "empty questionnaire" relink routes
(``dojo/survey/ui/views.py``).

``engagement_empty_survey`` and ``existing_engagement_empty_survey`` relink an
``Answered_Survey`` to an engagement. They were missing from
``URL_PERMISSIONS``, so the ``AuthorizationMiddleware`` applied no check: any
authenticated user could relink -- and thereby read -- another tenant's
answered questionnaire by enumerating ``Answered_Survey`` primary keys, since
only the attacker-chosen destination product was authorized.

These tests fix the contract:

* the relink routes require the questionnaire-change configuration permission;
* even with that permission, a user cannot move a questionnaire out of a source
  engagement they are not allowed to edit;
* the legitimate flow (claiming an unlinked questionnaire into a product you
  own) still works.
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


class EmptyQuestionnaireRelinkAuthorizationTests(DojoTestCase):

    """
    Two products and an attacker with no access to the victim tenant, plus a
    questionnaire manager who holds the configuration permission but is not a
    member of the victim product.
    """

    @classmethod
    def setUpTestData(cls):
        cls.prod_type = Product_Type.objects.create(name="qn_authz_pt")
        cls.victim_product = Product.objects.create(
            name="qn_authz_victim", description="v", prod_type=cls.prod_type,
        )
        cls.attacker_product = Product.objects.create(
            name="qn_authz_attacker", description="a", prod_type=cls.prod_type,
        )
        cls.manager_product = Product.objects.create(
            name="qn_authz_manager", description="m", prod_type=cls.prod_type,
        )

        # Attacker: authenticated, member of only the attacker product, without
        # the questionnaire-change configuration permission.
        cls.attacker = Dojo_User.objects.create(username="qn_authz_attacker_user", is_active=True)
        cls.attacker_product.authorized_users.add(cls.attacker)

        # Manager: holds the questionnaire-change configuration permission and
        # can add engagements to their own product, but has no access to the
        # victim product.
        cls.manager = Dojo_User.objects.create(username="qn_authz_manager_user", is_active=True)
        cls.manager_product.authorized_users.add(cls.manager)
        cls.manager.user_permissions.add(
            Permission.objects.get(
                content_type__app_label="dojo",
                codename="change_engagement_survey",
            ),
        )

        cls.template = Engagement_Survey.objects.create(name="qn_authz_template", description="t")

        # Victim's answered questionnaire, linked to an engagement in the victim
        # product neither the attacker nor the manager can access.
        cls.victim_engagement = Engagement.objects.create(
            name="qn_authz_victim_eng",
            product=cls.victim_product,
            target_start=timezone.now().date(),
            target_end=timezone.now().date(),
        )
        cls.victim_survey = Answered_Survey.objects.create(
            survey=cls.template, engagement=cls.victim_engagement,
        )

        # An unlinked ("empty") questionnaire response -- the legitimate object
        # of the relink workflow.
        cls.unlinked_survey = Answered_Survey.objects.create(survey=cls.template, engagement=None)

    # ------------------------------------------------------------------
    # Middleware configuration gate: an authenticated user without the
    # questionnaire-change permission is rejected before the view runs.
    # ------------------------------------------------------------------
    def test_new_engagement_relink_get_denied_without_config_perm(self):
        self.client.force_login(self.attacker)
        response = self.client.get(reverse("engagement_empty_survey", args=(self.victim_survey.id,)))
        self.assertEqual(response.status_code, 400)

    def test_new_engagement_relink_post_denied_without_config_perm(self):
        self.client.force_login(self.attacker)
        response = self.client.post(
            reverse("engagement_empty_survey", args=(self.victim_survey.id,)),
            data={"product": self.attacker_product.id},
        )
        self.assertEqual(response.status_code, 400)
        self.victim_survey.refresh_from_db()
        self.assertEqual(self.victim_survey.engagement_id, self.victim_engagement.id)

    def test_existing_engagement_relink_get_denied_without_config_perm(self):
        self.client.force_login(self.attacker)
        response = self.client.get(reverse("existing_engagement_empty_survey", args=(self.victim_survey.id,)))
        self.assertEqual(response.status_code, 400)

    # ------------------------------------------------------------------
    # View-level source check: even with the configuration permission, a user
    # cannot relink a questionnaire out of a source engagement they cannot edit.
    # ------------------------------------------------------------------
    def test_manager_cannot_relink_from_unauthorized_source_engagement(self):
        self.client.force_login(self.manager)
        response = self.client.post(
            reverse("engagement_empty_survey", args=(self.victim_survey.id,)),
            data={"product": self.manager_product.id},
        )
        self.assertEqual(response.status_code, 400)
        self.victim_survey.refresh_from_db()
        self.assertEqual(self.victim_survey.engagement_id, self.victim_engagement.id)

    # ------------------------------------------------------------------
    # Positive control: the legitimate claim-an-unlinked-questionnaire flow
    # still works for a permitted user.
    # ------------------------------------------------------------------
    def test_manager_can_relink_unlinked_questionnaire_into_own_product(self):
        self.client.force_login(self.manager)
        response = self.client.post(
            reverse("engagement_empty_survey", args=(self.unlinked_survey.id,)),
            data={"product": self.manager_product.id},
        )
        self.assertEqual(response.status_code, 302)
        self.unlinked_survey.refresh_from_db()
        self.assertIsNotNone(self.unlinked_survey.engagement_id)
        self.assertEqual(self.unlinked_survey.engagement.product_id, self.manager_product.id)
