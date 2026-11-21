"""
The importer, not the parser, drops tool ids that repeat inside one report.

SARIF reports a result's single fingerprint at each of its locations, and the Generic JSON format
can carry one id on several findings. Those parsers used to blank a repeated id themselves; they
now report every id they read and declare that a repeat is ambiguous, and the importer applies the
drop after its ``group_parsed_findings`` seam. With no override, what the importer stores is the
same as before.
"""

from django.test import override_settings
from django.utils import timezone

from dojo.importers.default_importer import DefaultImporter
from dojo.models import (
    Development_Environment,
    Dojo_User,
    Engagement,
    Finding,
    Product,
    Product_Type,
)
from dojo.tools.factory import PARSERS, is_splittable_per_location

from .dojo_test_case import DojoTestCase, get_unit_tests_scans_path

SENTINEL_SARIF = get_unit_tests_scans_path("sarif") / "sentinel_fingerprints.sarif"
REPEATED_GENERIC = get_unit_tests_scans_path("generic") / "generic_repeated_unique_ids.json"
SENTINEL_KEPT_ID = "5c1f36e0a9de13c3c96c26fa9a1a02a5d5be0c4a3ad9d0f27b3c4d2f8f4a91aa"


class RecordingImporter(DefaultImporter):

    """Records the tool ids the grouping seam sees, to prove it runs before the drop."""

    def group_parsed_findings(self, findings):
        self.seen_unique_ids = [finding.unique_id_from_tool for finding in findings]
        return super().group_parsed_findings(findings)


@override_settings(V3_FEATURE_LOCATIONS=True)
class TestImporterUniqueIdRules(DojoTestCase):

    def setUp(self):
        super().setUp()
        self.system_settings(enable_jira=False)
        user, _ = Dojo_User.objects.get_or_create(username="unique-id-rules", defaults={"is_superuser": True})
        product_type = Product_Type.objects.create(name="Unique id rules")
        product = Product.objects.create(name="Unique id rules", description="test", prod_type=product_type)
        self.engagement = Engagement.objects.create(
            name="Unique id rules", product=product, target_start=timezone.now(), target_end=timezone.now(),
        )
        self.user = user
        self.environment, _ = Development_Environment.objects.get_or_create(name="Development")

    def _options(self, scan_type):
        return {
            "user": self.user,
            "lead": self.user,
            "scan_date": None,
            "environment": self.environment,
            "minimum_severity": "Info",
            "active": True,
            "verified": True,
            "scan_type": scan_type,
            "engagement": self.engagement,
            "close_old_findings": False,
        }

    def _import(self, importer_class, path, scan_type):
        importer = importer_class(**self._options(scan_type))
        with path.open(encoding="utf-8") as scan:
            test, *_ = importer.process_scan(scan)
        return importer, test

    def test_sarif_repeated_fingerprints_are_dropped_by_the_importer(self):
        """Three findings share a sentinel fingerprint and lose it; the unique one keeps its id."""
        _, test = self._import(DefaultImporter, SENTINEL_SARIF, "SARIF")
        ids = list(Finding.objects.filter(test=test).values_list("unique_id_from_tool", flat=True))
        self.assertEqual(4, len(ids))
        self.assertEqual(3, ids.count(None))
        self.assertEqual([SENTINEL_KEPT_ID], [value for value in ids if value is not None])

    def test_generic_json_repeated_ids_are_dropped_by_the_importer(self):
        _, test = self._import(DefaultImporter, REPEATED_GENERIC, "Generic Findings Import")
        ids = list(Finding.objects.filter(test=test).values_list("unique_id_from_tool", flat=True))
        self.assertEqual(4, len(ids))
        self.assertEqual(3, ids.count(None))
        self.assertEqual(["dep-lodash-4.17.20"], [value for value in ids if value is not None])

    def test_grouping_seam_runs_before_the_drop(self):
        """An override sees the repeated ids, so it can fold on them before they are cleared."""
        importer, test = self._import(RecordingImporter, SENTINEL_SARIF, "SARIF")
        self.assertEqual(4, len(importer.seen_unique_ids))
        self.assertTrue(all(importer.seen_unique_ids))
        self.assertEqual(3, Finding.objects.filter(test=test, unique_id_from_tool__isnull=True).count())


class TestSplittablePerLocation(DojoTestCase):

    """Only parsers whose merge keeps every location declare that their output can be split."""

    # Each merges a repeated entry by adding its locations to the first finding. Invicti is
    # Netsparker under its new name and inherits its parser.
    EXPECTED = {
        "acunetix", "appspider", "auditjs", "invicti", "microfocus_webinspect", "netsparker", "nexpose",
        "nikto", "nmap", "nuclei", "openscap", "pingcastle", "qualys_hacker_guardian", "testssl", "wapiti",
    }

    def test_declared_parsers(self):
        declared = {
            type(parser).__module__.split(".")[2]
            for parser in PARSERS.values()
            if getattr(parser, "SPLITTABLE_PER_LOCATION", False)
        }
        self.assertEqual(self.EXPECTED, declared)

    def test_lookup_by_scan_type(self):
        with self.subTest("merge keeps locations"):
            self.assertTrue(is_splittable_per_location("Netsparker Scan"))
        with self.subTest("count-only merge"):
            self.assertFalse(is_splittable_per_location("Semgrep JSON Report"))
        with self.subTest("no merge at all"):
            self.assertFalse(is_splittable_per_location("GitLab SAST Report"))
        with self.subTest("unknown scan type"):
            self.assertFalse(is_splittable_per_location("No Such Scan"))
