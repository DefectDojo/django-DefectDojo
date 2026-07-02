"""
Regression tests for the V3_FEATURE_LOCATIONS ``Endpoint.__init__`` crash class (issue #15123
and siblings).

When ``V3_FEATURE_LOCATIONS`` is enabled the legacy ``Endpoint`` model is deprecated and
``Endpoint.__init__`` raises ``NotImplementedError``. Findings created/migrated from V2 still
carry legacy ``Endpoint``/``Endpoint_Status`` rows (the migration keeps them as backup), so any
code path that hydrates an ``Endpoint`` under V3 -- directly, via a queryset, or via the
``finding.endpoints`` m2m / ``.endpoint`` FK -- produces a 500.

These tests cover the sites that were guarded/repaired for that:

* JIRA + GitHub issue descriptions -- now render ``finding.locations`` under V3 (the legacy
  ``finding.endpoints`` block is gated out), so a push of a finding that still carries legacy
  endpoint rows must not crash and must show location info.
* CSV + Excel finding exports -- iterate ``finding.endpoints.all()`` guarded by
  ``Endpoint.allow_endpoint_init()``.
* API ``report_generate`` (Product/Engagement) -- ``get_endpoint_ids(Endpoint.objects...)``.
* API ``metadata/batch`` -- the ``endpoint`` parent fetch.
"""
import logging
from io import BytesIO
from types import SimpleNamespace

from django.contrib.auth.models import User
from django.test import Client
from django.urls import reverse
from django.utils import timezone
from openpyxl import load_workbook
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.github.services import github_body
from dojo.jira.helper import jira_description
from dojo.location.models import LocationFindingReference, LocationProductReference
from dojo.location.status import FindingLocationStatus, ProductLocationStatus
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
from dojo.url.models import URL

from .dojo_test_case import DojoTestCase, skip_unless_v3

logger = logging.getLogger(__name__)


@skip_unless_v3
class TestEndpointInitV3(DojoTestCase):

    """
    None of these paths may raise ``NotImplementedError`` when ``V3_FEATURE_LOCATIONS`` is
    enabled and the finding still carries legacy ``Endpoint`` rows.
    """

    def setUp(self):
        super().setUp()

        self.admin = User.objects.create(
            username="test_endpoint_init_v3_admin",
            is_staff=True,
            is_superuser=True,
        )
        UserContactInfo.objects.create(user=self.admin, block_execution=True)

        self.ui_client = Client()
        self.ui_client.force_login(self.admin)

        token, _ = Token.objects.get_or_create(user=self.admin)
        self.api_client = APIClient()
        self.api_client.credentials(HTTP_AUTHORIZATION="Token " + token.key)

        self.system_settings(enable_jira=False)
        self.system_settings(enable_github=False)
        self.system_settings(enable_product_grade=False)

        self.test_type = Test_Type.objects.get_or_create(name="Manual Test")[0]

    # ------------------------------------------------------------------
    # fixtures
    # ------------------------------------------------------------------
    def _make_tree(self, suffix):
        """Product_Type -> Product -> Engagement -> Test -> (active) Finding."""
        product_type = Product_Type.objects.create(name=f"Org {suffix}")
        product = Product.objects.create(
            name=f"Product {suffix}", description="regression fixture", prod_type=product_type,
        )
        engagement = Engagement.objects.create(
            name=f"Eng {suffix}", product=product,
            target_start=timezone.now(), target_end=timezone.now(),
        )
        test = Test.objects.create(
            engagement=engagement, test_type=self.test_type,
            target_start=timezone.now(), target_end=timezone.now(),
        )
        finding = Finding.objects.create(
            test=test, title=f"Finding {suffix}", severity="High", cwe=79,
            description="regression fixture", mitigation="n/a", impact="n/a",
            reporter=self.admin, active=True, verified=True,
        )
        return SimpleNamespace(
            product_type=product_type, product=product,
            engagement=engagement, test=test, finding=finding,
        )

    def _add_legacy_endpoint(self, tree, host):
        """Attach a legacy Endpoint + Endpoint_Status to the finding (as a pre-V3 finding has)."""
        with Endpoint.allow_endpoint_init():
            endpoint = Endpoint(product=tree.product, protocol="https", host=host)
            endpoint.save()
            Endpoint_Status(endpoint=endpoint, finding=tree.finding).save()
        return endpoint

    def _add_location(self, tree, host, status=FindingLocationStatus.Active):
        """Attach a V3 Location to the finding via a LocationFindingReference."""
        url = URL(protocol="https", host=host)
        url.clean()
        saved = URL.bulk_get_or_create([url])
        return LocationFindingReference.objects.create(
            location=saved[0].location, finding=tree.finding, status=status,
        )

    def _add_product_location(self, product, host):
        """Attach a V3 URL Location to the product via a LocationProductReference."""
        url = URL(protocol="https", host=host)
        url.clean()
        saved = URL.bulk_get_or_create([url])
        return LocationProductReference.objects.create(
            location=saved[0].location, product=product, status=ProductLocationStatus.Active,
        )

    # ------------------------------------------------------------------
    # JIRA / GitHub descriptions
    # ------------------------------------------------------------------
    def test_jira_description_renders_locations_under_v3(self):
        """jira_description must render locations (not legacy endpoints) and must not crash."""
        tree = self._make_tree("jira")
        self._add_legacy_endpoint(tree, "legacy-jira.example.com")  # crash trigger under old code
        self._add_location(tree, "loc-jira.example.com")

        description = jira_description(tree.finding)

        self.assertIn("loc-jira.example.com", description)
        # The legacy endpoint block must NOT be rendered under V3.
        self.assertNotIn("legacy-jira.example.com", description)

    def test_github_body_renders_locations_under_v3(self):
        """github_body renders the same template and must not crash under V3."""
        tree = self._make_tree("gh")
        self._add_legacy_endpoint(tree, "legacy-gh.example.com")
        self._add_location(tree, "loc-gh.example.com")

        body = github_body(tree.finding)

        self.assertIn("loc-gh.example.com", body)
        self.assertNotIn("legacy-gh.example.com", body)

    # ------------------------------------------------------------------
    # CSV / Excel exports
    # ------------------------------------------------------------------
    def test_csv_export_renders_locations_under_v3(self):
        """CSV export must render locations (not legacy endpoints) under V3 without crashing."""
        tree = self._make_tree("csv")
        self._add_legacy_endpoint(tree, "legacy-csv.example.com")  # must be ignored under V3
        self._add_location(tree, "loc-csv.example.com")

        response = self.ui_client.get(reverse("csv_export") + f"?url=test/{tree.test.id}")

        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        self.assertIn("loc-csv.example.com", content)
        self.assertNotIn("legacy-csv.example.com", content)

    def test_excel_export_renders_locations_under_v3(self):
        """Excel export must render locations (not legacy endpoints) under V3 without crashing."""
        tree = self._make_tree("xlsx")
        self._add_legacy_endpoint(tree, "legacy-xlsx.example.com")  # must be ignored under V3
        self._add_location(tree, "loc-xlsx.example.com")

        response = self.ui_client.get(reverse("excel_export") + f"?url=test/{tree.test.id}")

        self.assertEqual(response.status_code, 200)
        cells = [
            str(cell.value)
            for row in load_workbook(BytesIO(response.content)).active.iter_rows()
            for cell in row
        ]
        self.assertTrue(any("loc-xlsx.example.com" in c for c in cells), cells)
        self.assertFalse(any("legacy-xlsx.example.com" in c for c in cells), cells)

    # ------------------------------------------------------------------
    # API report_generate (Product / Engagement)
    # ------------------------------------------------------------------
    def test_api_product_report_generate_renders_locations_under_v3(self):
        """POST /products/{id}/generate_report returns URL locations (compat shape) under V3."""
        tree = self._make_tree("prod-rpt")
        self._add_legacy_endpoint(tree, "legacy-prodrpt.example.com")  # must be ignored under V3
        self._add_product_location(tree.product, "loc-prodrpt.example.com")

        response = self.api_client.post(
            reverse("product-generate-report", args=(tree.product.id,)),
            {}, format="json", HTTP_HOST="testserver",
        )

        self.assertEqual(response.status_code, 200)
        hosts = [ep.get("host") for ep in response.json()["endpoints"]]
        self.assertIn("loc-prodrpt.example.com", hosts)
        self.assertNotIn("legacy-prodrpt.example.com", hosts)

    def test_api_engagement_report_generate_renders_locations_under_v3(self):
        """POST /engagements/{id}/generate_report returns URL locations (compat shape) under V3."""
        tree = self._make_tree("eng-rpt")
        self._add_legacy_endpoint(tree, "legacy-engrpt.example.com")  # must be ignored under V3
        self._add_product_location(tree.product, "loc-engrpt.example.com")

        response = self.api_client.post(
            reverse("engagement-generate-report", args=(tree.engagement.id,)),
            {}, format="json", HTTP_HOST="testserver",
        )

        self.assertEqual(response.status_code, 200)
        hosts = [ep.get("host") for ep in response.json()["endpoints"]]
        self.assertIn("loc-engrpt.example.com", hosts)

    # ------------------------------------------------------------------
    # API metadata batch
    # ------------------------------------------------------------------
    def test_api_metadata_batch_with_endpoint_under_v3(self):
        """POST /metadata/batch referencing a legacy endpoint must not 500 under V3."""
        tree = self._make_tree("meta")
        endpoint = self._add_legacy_endpoint(tree, "legacy-meta.example.com")

        response = self.api_client.post(
            reverse("metadata-batch"),
            {
                "product": tree.product.id,
                "endpoint": endpoint.id,
                "metadata": [{"name": "k", "value": "v"}],
            },
            format="json",
        )

        self.assertNotEqual(response.status_code, 500)
