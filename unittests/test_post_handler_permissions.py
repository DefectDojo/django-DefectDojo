import datetime
from unittest.mock import patch

from django.core.exceptions import PermissionDenied
from django.urls import reverse

from dojo.models import Engagement, Finding_Group, Risk_Acceptance, Test
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures


def _view_only(user, obj, permission):
    if permission != "view":
        raise PermissionDenied


@versioned_fixtures
class PostHandlerPermissionTest(DojoTestCase):

    """Pages reachable with view access only accept POSTed changes from users with edit access."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.admin = self.get_test_admin()
        self.client.force_login(self.admin)

    def test_risk_acceptance_page(self):
        engagement = Engagement.objects.get(id=1)
        risk_acceptance = Risk_Acceptance.objects.create(
            name="post handler ra", owner=self.admin, decision="A", recommendation="A",
            expiration_date=datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=30),
        )
        engagement.risk_acceptance.add(risk_acceptance)
        url = reverse("view_risk_acceptance", args=(engagement.id, risk_acceptance.id))

        with patch("dojo.engagement.ui.views.user_has_permission_or_403", side_effect=_view_only):
            self.assertEqual(200, self.client.get(url).status_code)
            response = self.client.post(url, {"decision": "V", "recommendation": "A", "name": "renamed"})
        self.assertTemplateUsed(response, "403.html")
        risk_acceptance.refresh_from_db()
        self.assertEqual("post handler ra", risk_acceptance.name)
        self.assertEqual("A", risk_acceptance.decision)

    def test_finding_group_page(self):
        finding_group = Finding_Group.objects.create(name="post handler group", test=Test.objects.get(id=3), creator=self.admin)
        url = reverse("view_finding_group", args=(finding_group.id,))

        with patch("dojo.finding_group.views.user_has_permission_or_403", side_effect=_view_only):
            self.assertEqual(200, self.client.get(url).status_code)
            response = self.client.post(url, {"name": "renamed"})
        self.assertTemplateUsed(response, "403.html")
        finding_group.refresh_from_db()
        self.assertEqual("post handler group", finding_group.name)

    def test_edit_access_can_still_post(self):
        finding_group = Finding_Group.objects.create(name="post handler group", test=Test.objects.get(id=3), creator=self.admin)
        response = self.client.post(reverse("view_finding_group", args=(finding_group.id,)), {"name": "renamed"})
        self.assertEqual(302, response.status_code)
        finding_group.refresh_from_db()
        self.assertEqual("renamed", finding_group.name)
