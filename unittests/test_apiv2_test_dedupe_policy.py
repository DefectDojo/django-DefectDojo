import logging

from django.conf import settings
from django.utils import timezone
from rest_framework.authtoken.models import Token

from dojo.importers.default_importer import DefaultImporter
from dojo.models import Development_Environment, Engagement, Product, Product_Type, User

from .dojo_test_case import DojoAPITestCase, get_unit_tests_scans_path

logger = logging.getLogger(__name__)


class TestDedupePolicyOnTestAPI(DojoAPITestCase):

    """
    The Test API exposes the effective finding-matching policy
    (deduplication_algorithm + hash_code_fields) so users can see which
    algorithm and fields matching uses without reading settings.dist.py.
    """

    scan_type = "Acunetix Scan"

    def setUp(self):
        user, _ = User.objects.get_or_create(username="admin", defaults={"is_superuser": True, "is_staff": True})
        token, _ = Token.objects.get_or_create(user=user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")

        product_type, _ = Product_Type.objects.get_or_create(name="dedupe-policy-api")
        environment, _ = Development_Environment.objects.get_or_create(name="Development")
        product, _ = Product.objects.get_or_create(
            name="TestDedupePolicyAPI",
            description="Test",
            prod_type=product_type,
        )
        engagement, _ = Engagement.objects.get_or_create(
            name="dedupe policy api",
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        import_options = {
            "user": user,
            "lead": user,
            "scan_date": None,
            "environment": environment,
            "active": True,
            "verified": False,
            "engagement": engagement,
            "scan_type": self.scan_type,
        }
        with (get_unit_tests_scans_path("acunetix") / "one_finding.xml").open(encoding="utf-8") as scan:
            importer = DefaultImporter(close_old_findings=False, **import_options)
            self.test, _, _, _, _, _, _ = importer.process_scan(scan, force_sync=True)

    def test_matching_policy_is_exposed_read_only(self):
        response = self.client.get(f"/api/v2/tests/{self.test.id}/", format="json")
        self.assertEqual(200, response.status_code, response.content)
        data = response.json()

        # values mirror the per-scanner settings, so assert against them
        # dynamically rather than hardcoding the current config
        expected_algorithm = settings.DEDUPLICATION_ALGORITHM_PER_PARSER.get(
            self.scan_type, settings.DEDUPE_ALGO_LEGACY)
        expected_fields = settings.HASHCODE_FIELDS_PER_SCANNER.get(self.scan_type)

        self.assertIn("deduplication_algorithm", data)
        self.assertIn("hash_code_fields", data)
        self.assertEqual(expected_algorithm, data["deduplication_algorithm"])
        self.assertEqual(expected_fields, data["hash_code_fields"])

    def test_matching_policy_ignored_on_write(self):
        response = self.client.patch(
            f"/api/v2/tests/{self.test.id}/",
            {"deduplication_algorithm": "hash_code", "hash_code_fields": ["title"], "description": "updated"},
            format="json",
        )
        self.assertEqual(200, response.status_code, response.content)
        # read-only fields are silently ignored; effective policy still mirrors settings
        data = self.client.get(f"/api/v2/tests/{self.test.id}/", format="json").json()
        expected_algorithm = settings.DEDUPLICATION_ALGORITHM_PER_PARSER.get(
            self.scan_type, settings.DEDUPE_ALGO_LEGACY)
        self.assertEqual(expected_algorithm, data["deduplication_algorithm"])
        self.assertEqual("updated", data["description"])
