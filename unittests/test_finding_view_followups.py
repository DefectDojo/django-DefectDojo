import datetime
from unittest.mock import patch

from django.core.exceptions import PermissionDenied
from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.file_uploads.models import FileAccessToken, FileUpload
from dojo.models import Dojo_User, Engagement, Finding, Product, Product_Type, Test, Test_Type
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures


def _view_only(user, obj, permission):
    if permission != "view":
        raise PermissionDenied


@versioned_fixtures
class FindingViewFollowupsTest(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.admin = self.get_test_admin()
        # A finding in a product of its own, so cross-product cases have something to point at.
        product_type = Product_Type.objects.create(name="followups other org")
        self.other_product = Product.objects.create(name="followups other product", prod_type=product_type, description="x")
        engagement = Engagement.objects.create(
            name="followups other engagement", product=self.other_product,
            target_start=datetime.date(2026, 1, 1), target_end=datetime.date(2026, 2, 1),
        )
        test = Test.objects.create(
            engagement=engagement,
            test_type=Test_Type.objects.get_or_create(name="ZAP Scan")[0],
            target_start=datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC),
            target_end=datetime.datetime(2026, 2, 1, tzinfo=datetime.UTC),
        )
        self.other_finding = Finding.objects.create(
            title="followups other finding", test=test, severity="High", reporter=self.admin, active=True, verified=False,
        )
        # A member of product 2 only (the fixture product that owns finding 2).
        self.member = Dojo_User.objects.create(username="followups_member", is_active=True)
        Finding.objects.get(id=2).test.engagement.product.authorized_users.add(self.member)

    # --- request review -----------------------------------------------------------------------

    def _request_review(self, finding):
        return self.client.post(
            reverse("request_finding_review", args=(finding.id,)),
            {"entry": "please check", "reviewers": [self.admin.id]},
        )

    def test_review_request_on_an_active_finding_needs_view_only(self):
        self.client.force_login(self.admin)
        finding = Finding.objects.get(id=2)
        finding.active = True
        finding.is_mitigated = False
        finding.under_review = False
        finding.save()
        with patch("dojo.finding.ui.views.user_has_permission_or_403", side_effect=_view_only):
            response = self._request_review(finding)
        self.assertEqual(302, response.status_code)
        finding.refresh_from_db()
        self.assertTrue(finding.under_review)

    def test_review_request_that_reopens_a_finding_needs_edit(self):
        self.client.force_login(self.admin)
        finding = Finding.objects.get(id=2)
        finding.active = False
        finding.is_mitigated = True
        finding.under_review = False
        finding.save()
        with patch("dojo.finding.ui.views.user_has_permission_or_403", side_effect=_view_only):
            response = self._request_review(finding)
        self.assertTemplateUsed(response, "403.html")
        finding.refresh_from_db()
        self.assertFalse(finding.active)
        self.assertTrue(finding.is_mitigated)
        self.assertFalse(finding.under_review)

    def test_review_request_does_not_replace_an_open_review(self):
        self.client.force_login(self.admin)
        finding = Finding.objects.get(id=2)
        finding.under_review = True
        finding.save()
        finding.reviewers.set([self.member])
        response = self._request_review(finding)
        self.assertEqual(302, response.status_code)
        self.assertEqual([self.member.id], list(finding.reviewers.values_list("id", flat=True)))

    # --- bulk edit ----------------------------------------------------------------------------

    def test_bulk_edit_recomputes_grades_for_authorized_products_only(self):
        self.client.force_login(self.member)
        with patch("dojo.finding.ui.views.calculate_grade") as calculate_grade:
            response = self.client.post(reverse("finding_bulk_update_all"), {
                "finding_to_update": [2, self.other_finding.id],
                "severity": "Low",
            })
        self.assertEqual(302, response.status_code, response.content[:500])
        graded = {call.args[0] for call in calculate_grade.call_args_list}
        self.assertNotIn(self.other_product.id, graded)
        self.other_finding.refresh_from_db()
        self.assertEqual("High", self.other_finding.severity)
        self.assertEqual("Low", Finding.objects.get(id=2).severity)

    # --- report images ------------------------------------------------------------------------

    def test_image_token_is_only_valid_for_its_user(self):
        upload = FileUpload.objects.create(title="picture.png")
        token = FileAccessToken.objects.create(user=self.admin, file=upload, size="original")

        self.client.force_login(self.member)
        response = self.client.get(reverse("download_finding_pic", args=(token.token,)))
        self.assertTemplateUsed(response, "403.html")
        self.assertFalse(FileAccessToken.objects.filter(pk=token.pk).exists())

    # --- duplicate cluster --------------------------------------------------------------------

    def _link_as_duplicate(self):
        finding = Finding.objects.get(id=2)
        self.other_finding.duplicate = True
        self.other_finding.duplicate_finding = finding
        self.other_finding.active = False
        self.other_finding.save(dedupe_option=False)
        return finding

    def test_duplicate_cluster_shows_only_findings_the_user_may_view(self):
        finding = self._link_as_duplicate()
        self.client.force_login(self.member)
        response = self.client.get(reverse("view_finding", args=(finding.id,)))
        self.assertEqual(200, response.status_code)
        self.assertNotIn(self.other_finding.id, [member.id for member in response.context["duplicate_cluster"]])

        self.client.force_login(self.admin)
        response = self.client.get(reverse("view_finding", args=(finding.id,)))
        self.assertIn(self.other_finding.id, [member.id for member in response.context["duplicate_cluster"]])

    def test_duplicate_cluster_api_shows_only_findings_the_user_may_view(self):
        finding = self._link_as_duplicate()
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION="Token " + Token.objects.get_or_create(user=self.member)[0].key)
        response = client.get(reverse("finding-get-duplicate-cluster", args=(finding.id,)))
        self.assertEqual(200, response.status_code, response.content[:500])
        ids = [row["id"] for row in response.json()]
        self.assertNotIn(self.other_finding.id, ids)
        # The fixture's own-product duplicates of finding 2 are still listed.
        self.assertIn(3, ids)
