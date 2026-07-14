"""
Regression tests for issue #15123: the V3_FEATURE_LOCATIONS crash when creating a
Finding Template from a finding or merging findings.

When ``V3_FEATURE_LOCATIONS`` is enabled the legacy ``Endpoint`` model is deprecated and
``Endpoint.__init__`` raises ``NotImplementedError``. Findings created before the V3
migration still carry legacy endpoint rows (the migration keeps them as backup), so any
un-guarded iteration of ``finding.endpoints.all()`` hydrates ``Endpoint`` instances via
``Model.from_db()`` and produces a 500. Two such sites live in ``dojo/finding/views.py``:
``mktemplate`` (copying endpoint URLs onto the template) and ``merge_finding_product``
(adding the merged findings' endpoints onto the target finding).

The fix wraps both sites in ``Endpoint.allow_endpoint_init()``.
"""
import logging
from types import SimpleNamespace

from django.contrib.auth.models import User
from django.test import Client, override_settings
from django.urls import reverse
from django.utils import timezone

from dojo.models import (
    Endpoint,
    Endpoint_Status,
    Engagement,
    Finding,
    Finding_Template,
    Product,
    Product_Type,
    Test,
    Test_Type,
    UserContactInfo,
)

from .dojo_test_case import DojoTestCase

logger = logging.getLogger(__name__)


@override_settings(V3_FEATURE_LOCATIONS=True)
class TestFindingTemplateAndMergeWithEndpointsV3(DojoTestCase):

    """
    Creating a finding template and merging findings must not 500 when
    ``V3_FEATURE_LOCATIONS`` is enabled and the findings still carry legacy
    ``Endpoint`` rows.
    """

    def setUp(self):
        super().setUp()

        self.admin = User.objects.create(
            username="test_template_merge_endpoints_v3_admin",
            is_staff=True,
            is_superuser=True,
        )
        UserContactInfo.objects.create(user=self.admin, block_execution=True)

        self.ui_client = Client()
        self.ui_client.force_login(self.admin)

        self.system_settings(enable_jira=False)
        self.system_settings(enable_github=False)

        self.test_type = Test_Type.objects.get_or_create(name="Manual Test")[0]

        product_type = Product_Type.objects.create(name="Org for template/merge endpoints")
        self.product = Product.objects.create(
            name="Product for template/merge endpoints",
            description="regression fixture",
            prod_type=product_type,
        )
        engagement = Engagement.objects.create(
            name="Engagement for template/merge endpoints",
            product=self.product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        self.test = Test.objects.create(
            engagement=engagement,
            test_type=self.test_type,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )

    def _create_finding_with_legacy_endpoint(self, suffix):
        """Create a finding carrying a legacy Endpoint row, as pre-V3 findings do."""
        finding = Finding.objects.create(
            test=self.test,
            title=f"Finding with legacy endpoint {suffix}",
            severity="High",
            description="regression fixture",
            mitigation="n/a",
            impact="n/a",
            reporter=self.admin,
        )
        # The Endpoint model is deprecated under V3; constructing/saving it in the
        # fixture requires the escape hatch. Linking it through Endpoint_Status
        # populates the legacy finding.endpoints m2m.
        with Endpoint.allow_endpoint_init():
            endpoint = Endpoint(
                product=self.product,
                protocol="https",
                host=f"host-{suffix}.example.com",
            )
            endpoint.save()
            endpoint_status = Endpoint_Status(endpoint=endpoint, finding=finding)
            endpoint_status.save()

        return SimpleNamespace(finding=finding, endpoint=endpoint)

    def test_mktemplate_with_legacy_endpoints(self):
        """Creating a finding template from a finding with legacy endpoints must not crash."""
        fixture = self._create_finding_with_legacy_endpoint("mktemplate")
        response = self.ui_client.get(
            reverse("mktemplate", kwargs={"fid": fixture.finding.id}),
        )
        self.assertEqual(response.status_code, 302)
        template = Finding_Template.objects.get(title=fixture.finding.title)
        self.assertIn("host-mktemplate.example.com", template.endpoints_text)

    def test_merge_findings_with_legacy_endpoints(self):
        """Merging a finding that carries legacy endpoints must not crash."""
        target = self._create_finding_with_legacy_endpoint("merge-target")
        source = self._create_finding_with_legacy_endpoint("merge-source")
        url = reverse("merge_finding_product", kwargs={"pid": self.product.id})
        response = self.ui_client.post(
            f"{url}?finding_to_update={target.finding.id}&finding_to_update={source.finding.id}",
            {
                "finding_to_merge_into": target.finding.id,
                "findings_to_merge": [source.finding.id],
                "append_description": "on",
                "add_endpoints": "on",
                "finding_action": "inactive",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(target.finding.endpoints.count(), 2)
        self.assertTrue(
            target.finding.endpoints.filter(pk=source.endpoint.pk).exists(),
        )
