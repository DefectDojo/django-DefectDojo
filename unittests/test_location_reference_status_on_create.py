"""
A location reference the importer creates carries the status of what it references.

# Regression: an import created every new finding reference as Active, even for a finding that arrived
# already mitigated, and never reactivated an Asset reference that was Mitigated when a new Active finding
# reference joined it. The Locations list then counted closed findings as active on a location whose Asset
# reference read Mitigated.
"""

from django.test import override_settings
from django.utils import timezone

from dojo.importers.location_manager import LocationManager
from dojo.location.models import LocationFindingReference, LocationProductReference
from dojo.location.status import FindingLocationStatus, ProductLocationStatus
from dojo.models import Dojo_User, Engagement, Finding, Product, Product_Type, Test, Test_Type
from dojo.tools.locations import LocationData
from dojo.url.models import URL

from .dojo_test_case import DojoTestCase

LOCATION = "https://status-on-create.example.com/login"


@override_settings(V3_FEATURE_LOCATIONS=True)
class TestLocationReferenceStatusOnCreate(DojoTestCase):

    def setUp(self):
        super().setUp()
        now = timezone.now()
        test_type = Test_Type.objects.get_or_create(name="Manual Test")[0]
        product_type = Product_Type.objects.create(name="Status on create org")
        self.product = Product.objects.create(name="Status on create asset", description="test", prod_type=product_type)
        engagement = Engagement.objects.create(name="Status on create", product=self.product, target_start=now, target_end=now)
        self.test = Test.objects.create(engagement=engagement, test_type=test_type, target_start=now, target_end=now)
        self.reporter = Dojo_User.objects.create(username="status-on-create-reporter")

    def _finding(self, title, **status):
        return Finding.objects.create(test=self.test, title=title, severity="High", reporter=self.reporter, **status)

    def _import(self, *findings):
        """Persist ``LOCATION`` on each finding the way an import does."""
        manager = LocationManager(self.product)
        manager.set_test(self.test)
        for finding in findings:
            manager.record_locations_for_finding(finding, [LocationData.url(url=LOCATION)])
        manager.persist()

    def _finding_ref_status(self, finding):
        return LocationFindingReference.objects.get(finding=finding).status

    def _asset_ref_status(self):
        return LocationProductReference.objects.get(product=self.product).status

    def test_a_new_finding_reference_follows_the_findings_status(self):
        cases = [
            ("open finding", {"active": True}, FindingLocationStatus.Active),
            ("mitigated finding", {"active": False, "is_mitigated": True, "mitigated": timezone.now()}, FindingLocationStatus.Mitigated),
            ("inactive finding", {"active": False}, FindingLocationStatus.Mitigated),
            ("duplicate", {"active": False, "duplicate": True}, FindingLocationStatus.Mitigated),
        ]
        for label, status, expected in cases:
            with self.subTest(label):
                finding = self._finding(label, **status)
                self._import(finding)
                persisted = self._finding_ref_status(finding)
                self.assertEqual(expected, persisted, f"{label}: expected {expected}, persisted {persisted}")

    def test_a_new_asset_reference_is_active_only_when_a_finding_reference_is_active(self):
        cases = [
            ("only a mitigated finding", [{"active": False, "is_mitigated": True}], ProductLocationStatus.Mitigated),
            ("an open finding", [{"active": True}], ProductLocationStatus.Active),
            ("an open and a mitigated finding", [{"active": False, "is_mitigated": True}, {"active": True}], ProductLocationStatus.Active),
        ]
        for label, statuses, expected in cases:
            with self.subTest(label):
                LocationProductReference.objects.filter(product=self.product).delete()
                findings = [self._finding(f"{label} {index}", **status) for index, status in enumerate(statuses)]
                self._import(*findings)
                persisted = self._asset_ref_status()
                self.assertEqual(expected, persisted, f"{label}: expected {expected}, persisted {persisted}")

    def test_a_mitigated_asset_reference_is_reactivated_by_a_new_active_finding_reference(self):
        cases = [
            ("open finding", {"active": True}, ProductLocationStatus.Active),
            ("mitigated finding", {"active": False, "is_mitigated": True}, ProductLocationStatus.Mitigated),
        ]
        location = URL.create_location_from_value(LOCATION).location
        for label, status, expected in cases:
            with self.subTest(label):
                LocationProductReference.objects.update_or_create(
                    location=location, product=self.product, defaults={"status": ProductLocationStatus.Mitigated},
                )
                self._import(self._finding(label, **status))
                persisted = self._asset_ref_status()
                self.assertEqual(expected, persisted, f"{label}: expected {expected}, persisted {persisted}")
