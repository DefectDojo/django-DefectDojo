from django.contrib.auth.models import User
from django.test import override_settings
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient
from watson import search as watson

from dojo.models import Development_Environment, Engagement, Finding, Product, Product_Type, UserContactInfo

from .dojo_test_case import DojoAPITestCase


class TestWatsonAsyncSearchIndex(DojoAPITestCase):

    """Test Watson search indexing works correctly for both sync and async updates."""

    def setUp(self):
        """Set up test data and API client."""
        super().setUp()

        self.testuser = User.objects.create(username="admin", is_staff=True, is_superuser=True)
        UserContactInfo.objects.create(user=self.testuser, block_execution=True)

        self.system_settings(enable_product_grade=False)
        self.system_settings(enable_github=False)

        # Create API client with authentication
        self.token = Token.objects.create(user=self.testuser)
        self.client = APIClient()
        self.client.force_login(self.testuser)

        # Create test product type and product
        self.product_type = Product_Type.objects.create(name="Test Product Type")
        self.product = Product.objects.create(
            name="Test Product",
            description="Test product for Watson indexing",
            prod_type=self.product_type,
        )
        self.engagement = Engagement.objects.create(
            name="Test Engagement",
            product=self.product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )

        # Create Development Environment
        Development_Environment.objects.get_or_create(name="Development")

    def _import_acunetix_scan(self):
        """Import an Acunetix scan and return the response."""
        return self.import_scan_with_params(
            filename="scans/acunetix/watson_test_unique.xml",
            scan_type="Acunetix Scan",
            engagement=self.engagement.id,
        )

    def _search_watson_for_finding(self, search_term):
        """Search Watson index for findings containing the search term."""
        # Search the Watson index
        return watson.search(search_term, models=(Finding,))

    def _import_and_check_watson_index(self, expected_message):
        """Common test logic for importing scan and verifying Watson indexing works."""
        # Verify no findings exist before import
        search_results = self._search_watson_for_finding("WatsonUniqueReportItem2025")
        found_finding_ids_before = [result.pk for result in search_results]
        self.assertEqual(len(found_finding_ids_before), 0, "Should have no findings before import")

        # Import the scan
        response_data = self._import_acunetix_scan()

        # Get test ID from response
        test_id = response_data["test_id"]

        # Verify finding was created
        findings = Finding.objects.filter(test_id=test_id)
        self.assertEqual(findings.count(), 1, "Should have created exactly one finding")
        finding = findings.first()

        self.assertIn("WatsonUniqueReportItem2025", finding.title, "Finding should contain 'WatsonUniqueReportItem2025' in title")

        # Search Watson index for the finding
        search_results = self._search_watson_for_finding("WatsonUniqueReportItem2025")

        # Verify finding is in search index
        found_finding_ids = [result.object.pk for result in search_results]

        self.assertIn(finding.pk, found_finding_ids, expected_message.format(finding_id=finding.pk))

        return finding

    def test_sync_watson_indexing_single_finding(self):
        """Test that single finding import uses sync indexing and finding is searchable."""
        # Default threshold is 100, so single finding should use sync indexing
        self._import_and_check_watson_index(
            "Finding {finding_id} should be found in Watson search index",
        )

    @override_settings(WATSON_ASYNC_INDEX_UPDATE_THRESHOLD=0)
    def test_async_watson_indexing_single_finding(self):
        """Test that with threshold=0, single finding uses async indexing and is searchable."""
        # With threshold=0, even single finding should trigger async indexing
        self._import_and_check_watson_index(
            "Finding {finding_id} should be found in Watson search index after async update",
        )

    @override_settings(WATSON_ASYNC_INDEX_UPDATE_THRESHOLD=-1)
    def test_disabled_async_watson_indexing(self):
        """Test that with threshold=-1, async is disabled and sync indexing works."""
        # With threshold=-1, async should be completely disabled
        self._import_and_check_watson_index(
            "Finding {finding_id} should be found in Watson search index with sync update",
        )
