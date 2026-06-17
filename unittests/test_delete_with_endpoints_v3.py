"""
Regression tests for the V3_FEATURE_LOCATIONS delete-cascade crash.

When ``V3_FEATURE_LOCATIONS`` is enabled the legacy ``Endpoint`` model is deprecated and
``Endpoint.__init__`` raises ``NotImplementedError``. Django's delete machinery hydrates
related ``Endpoint`` rows via ``Model.from_db()`` -- both ``NestedObjects.collect()`` (the
delete preview) and the real cascade delete -- which previously produced a 500 when deleting
an organization/product that still has endpoints (see Slack #possible-bugs, 2026-06-16).

The fix wraps those delete paths in ``Endpoint.allow_endpoint_init()``. These tests cover
deletion of every object in the endpoint relation graph (Product_Type, Product, Engagement,
Test, Finding) via both the UI and the API, plus the delete-preview path for each.
"""
import logging
from types import SimpleNamespace

from django.contrib.auth.models import User
from django.test import Client, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.models import (
    Endpoint,
    Endpoint_Status,
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
    UserContactInfo,
)

from .dojo_test_case import DojoTestCase

logger = logging.getLogger(__name__)


@override_settings(
    V3_FEATURE_LOCATIONS=True,
    DELETE_PREVIEW=True,
    ASYNC_OBJECT_DELETE=False,
)
class TestDeleteWithEndpointsV3(DojoTestCase):

    """
    Deleting endpoint-related objects must not 500 when ``V3_FEATURE_LOCATIONS`` is enabled,
    even though the legacy ``Endpoint`` model is deprecated. ``ASYNC_OBJECT_DELETE=False``
    forces the synchronous Collector path -- the one that hits the deprecated model.
    """

    def setUp(self):
        super().setUp()

        self.admin = User.objects.create(
            username="test_delete_endpoints_v3_admin",
            is_staff=True,
            is_superuser=True,
        )
        UserContactInfo.objects.create(user=self.admin, block_execution=True)

        # UI client: session auth (the Django test client does not enforce CSRF).
        self.ui_client = Client()
        self.ui_client.force_login(self.admin)

        # API client: token auth, to avoid SessionAuthentication CSRF enforcement on DELETE.
        token, _ = Token.objects.get_or_create(user=self.admin)
        self.api_client = APIClient()
        self.api_client.credentials(HTTP_AUTHORIZATION="Token " + token.key)

        # Disable features that add noise/extra work during deletes.
        self.system_settings(enable_product_grade=False)
        self.system_settings(enable_github=False)
        self.system_settings(enable_jira=False)

        self.test_type = Test_Type.objects.get_or_create(name="Manual Test")[0]

    def _build_tree(self, suffix):
        """Create Product_Type -> Product -> Engagement -> Test -> Finding, plus a legacy
        Endpoint on the product and an Endpoint_Status linking it to the finding."""
        product_type = Product_Type.objects.create(name=f"Org with endpoints {suffix}")
        product = Product.objects.create(
            name=f"Product with endpoints {suffix}",
            description="regression fixture",
            prod_type=product_type,
        )
        engagement = Engagement.objects.create(
            name=f"Engagement {suffix}",
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        test = Test.objects.create(
            engagement=engagement,
            test_type=self.test_type,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        finding = Finding.objects.create(
            test=test,
            title=f"Finding {suffix}",
            severity="High",
            description="regression fixture",
            mitigation="n/a",
            impact="n/a",
            reporter=self.admin,
        )
        # The Endpoint model is deprecated under V3; constructing/saving it (and walking it
        # during a cascade delete) requires the escape hatch.
        with Endpoint.allow_endpoint_init():
            endpoint = Endpoint(
                product=product,
                protocol="https",
                host=f"host-{suffix}.example.com",
            )
            endpoint.save()
            endpoint_status = Endpoint_Status(endpoint=endpoint, finding=finding)
            endpoint_status.save()

        return SimpleNamespace(
            product_type=product_type,
            product=product,
            engagement=engagement,
            test=test,
            finding=finding,
            endpoint=endpoint,
            endpoint_status=endpoint_status,
        )

    # ------------------------------------------------------------------ delete preview

    def test_ui_delete_pages_render_without_crashing(self):
        """The UI delete page runs NestedObjects.collect for its preview; it must not crash
        for any object whose cascade can reach the deprecated Endpoint. (Finding deletion is
        a POST-only view with no preview page, so it is covered by the API action below.)"""
        tree = self._build_tree("ui-preview")
        cases = [
            ("delete_product_type", "ptid", tree.product_type.id),
            ("delete_product", "pid", tree.product.id),
            ("delete_engagement", "eid", tree.engagement.id),
            ("delete_test", "tid", tree.test.id),
        ]
        for ui_name, ui_kwarg, obj_id in cases:
            with self.subTest(view=ui_name):
                response = self.ui_client.get(reverse(ui_name, kwargs={ui_kwarg: obj_id}))
                self.assertEqual(
                    response.status_code, 200,
                    f"UI delete page {ui_name} crashed: {response.status_code}",
                )

    def test_api_delete_preview_without_crashing(self):
        """The API delete_preview action (shared DeletePreviewModelMixin) runs the same
        NestedObjects.collect and must not crash for any endpoint-related object."""
        tree = self._build_tree("api-preview")
        cases = [
            ("product_type", tree.product_type.id),
            ("product", tree.product.id),
            ("engagement", tree.engagement.id),
            ("test", tree.test.id),
            ("finding", tree.finding.id),
        ]
        for basename, obj_id in cases:
            with self.subTest(basename=basename):
                response = self.api_client.get(
                    reverse(f"{basename}-delete-preview", kwargs={"pk": obj_id}),
                )
                self.assertEqual(
                    response.status_code, 200,
                    f"API delete_preview for {basename} crashed: {response.status_code}",
                )

    # ------------------------------------------------------------------ Product_Type

    def test_delete_product_type_ui(self):
        tree = self._build_tree("ui-pt")
        response = self.ui_client.post(
            reverse("delete_product_type", kwargs={"ptid": tree.product_type.id}),
            {"id": tree.product_type.id},
        )
        self.assertEqual(response.status_code, 302)
        self.assertFalse(Product_Type.objects.filter(pk=tree.product_type.id).exists())

    def test_delete_product_type_api(self):
        tree = self._build_tree("api-pt")
        response = self.api_client.delete(
            reverse("product_type-detail", kwargs={"pk": tree.product_type.id}),
        )
        self.assertEqual(response.status_code, 204)
        self.assertFalse(Product_Type.objects.filter(pk=tree.product_type.id).exists())

    # ------------------------------------------------------------------ Product

    def test_delete_product_ui(self):
        tree = self._build_tree("ui-prod")
        response = self.ui_client.post(
            reverse("delete_product", kwargs={"pid": tree.product.id}),
            {"id": tree.product.id},
        )
        self.assertEqual(response.status_code, 302)
        self.assertFalse(Product.objects.filter(pk=tree.product.id).exists())

    def test_delete_product_api(self):
        tree = self._build_tree("api-prod")
        response = self.api_client.delete(
            reverse("product-detail", kwargs={"pk": tree.product.id}),
        )
        self.assertEqual(response.status_code, 204)
        self.assertFalse(Product.objects.filter(pk=tree.product.id).exists())

    # ------------------------------------------------------------------ Engagement

    def test_delete_engagement_ui(self):
        tree = self._build_tree("ui-eng")
        response = self.ui_client.post(
            reverse("delete_engagement", kwargs={"eid": tree.engagement.id}),
            {"id": tree.engagement.id},
        )
        self.assertEqual(response.status_code, 302)
        self.assertFalse(Engagement.objects.filter(pk=tree.engagement.id).exists())

    def test_delete_engagement_api(self):
        tree = self._build_tree("api-eng")
        response = self.api_client.delete(
            reverse("engagement-detail", kwargs={"pk": tree.engagement.id}),
        )
        self.assertEqual(response.status_code, 204)
        self.assertFalse(Engagement.objects.filter(pk=tree.engagement.id).exists())

    # ------------------------------------------------------------------ Test

    def test_delete_test_ui(self):
        tree = self._build_tree("ui-test")
        response = self.ui_client.post(
            reverse("delete_test", kwargs={"tid": tree.test.id}),
            {"id": tree.test.id},
        )
        self.assertEqual(response.status_code, 302)
        self.assertFalse(Test.objects.filter(pk=tree.test.id).exists())

    def test_delete_test_api(self):
        tree = self._build_tree("api-test")
        response = self.api_client.delete(
            reverse("test-detail", kwargs={"pk": tree.test.id}),
        )
        self.assertEqual(response.status_code, 204)
        self.assertFalse(Test.objects.filter(pk=tree.test.id).exists())

    # ------------------------------------------------------------------ Finding

    def test_delete_finding_ui(self):
        tree = self._build_tree("ui-find")
        response = self.ui_client.post(
            reverse("delete_finding", kwargs={"finding_id": tree.finding.id}),
            {"id": tree.finding.id},
        )
        self.assertEqual(response.status_code, 302)
        self.assertFalse(Finding.objects.filter(pk=tree.finding.id).exists())

    def test_delete_finding_api(self):
        tree = self._build_tree("api-find")
        response = self.api_client.delete(
            reverse("finding-detail", kwargs={"pk": tree.finding.id}),
        )
        self.assertEqual(response.status_code, 204)
        self.assertFalse(Finding.objects.filter(pk=tree.finding.id).exists())
