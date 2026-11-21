"""
A location reference records which test reported it.

One ``LocationFindingReference`` exists per (location, finding, test). A finding normally holds rows
from its own test only, but several tests can report the same location on one finding, and a
reimport of one test then changes only that test's rows: it never mitigates a location another
test still reports. A location's status on the finding rolls up across its rows.
"""

from django.core.exceptions import ValidationError
from django.test import SimpleTestCase, override_settings
from django.utils import timezone

from dojo.importers.location_manager import LocationManager
from dojo.location.models import LocationFindingReference
from dojo.location.status import FindingLocationStatus, rollup_finding_location_status
from dojo.models import Dojo_User, Engagement, Finding, Product, Product_Type, Test, Test_Type
from dojo.tools.locations import LocationData
from dojo.url.models import URL

from .dojo_test_case import DojoTestCase

Active = FindingLocationStatus.Active
Mitigated = FindingLocationStatus.Mitigated
FalsePositive = FindingLocationStatus.FalsePositive


class TestRollupFindingLocationStatus(SimpleTestCase):

    def test_rollup(self):
        cases = [
            ("no rows", [], None),
            ("one test reports it", [Active], Active),
            ("still reported by another test", [Mitigated, Active], Active),
            ("no test reports it any more", [Mitigated, Mitigated], Mitigated),
            ("a person's decision outranks a scan", [Active, FalsePositive], FalsePositive),
            ("risk acceptance outranks out of scope", [FindingLocationStatus.OutOfScope, FindingLocationStatus.RiskAccepted], FindingLocationStatus.RiskAccepted),
        ]
        for label, statuses, expected in cases:
            with self.subTest(label):
                self.assertEqual(expected, rollup_finding_location_status(statuses))


@override_settings(V3_FEATURE_LOCATIONS=True)
class TestLocationReferenceTestAttribution(DojoTestCase):

    def setUp(self):
        super().setUp()
        now = timezone.now()
        test_type = Test_Type.objects.get_or_create(name="Manual Test")[0]
        product_type = Product_Type.objects.create(name="Attribution org")
        self.product = Product.objects.create(name="Attribution asset", description="test", prod_type=product_type)
        engagement = Engagement.objects.create(name="Attribution", product=self.product, target_start=now, target_end=now)
        self.test_a = Test.objects.create(engagement=engagement, test_type=test_type, target_start=now, target_end=now)
        self.test_b = Test.objects.create(engagement=engagement, test_type=test_type, target_start=now, target_end=now)
        self.reporter = Dojo_User.objects.create(username="attribution-reporter")
        self.finding = Finding.objects.create(
            test=self.test_a, title="Shared finding", severity="High", reporter=self.reporter,
        )
        self.first = URL.create_location_from_value("https://first.example.com/").location
        self.second = URL.create_location_from_value("https://second.example.com/").location

    def _row(self, location, test, status=Active):
        return LocationFindingReference.objects.create(location=location, finding=self.finding, test=test, status=status)

    def _status(self, location, test):
        return LocationFindingReference.objects.get(location=location, finding=self.finding, test=test).status

    def _reimport(self, test, *, reported):
        """Run the reimport status comparison for the shared finding as ``test`` reporting ``reported``."""
        manager = LocationManager(self.product)
        manager.set_test(test)
        new_finding = Finding(test=test, title=self.finding.title, severity="High", reporter=self.reporter)
        new_finding.unsaved_locations = [LocationData.url(url=value) for value in reported]
        manager.update_location_status(self.finding, new_finding, None)
        manager.persist()

    def test_row_without_a_test_belongs_to_the_findings_test(self):
        row = LocationFindingReference.objects.create(location=self.first, finding=self.finding)
        self.assertEqual(self.test_a.id, row.test_id)

    def test_associate_with_finding_attributes_rows(self):
        with self.subTest("default: the finding's own test"):
            self.assertEqual(self.test_a.id, self.first.associate_with_finding(self.finding).test_id)
        with self.subTest("another test adds its own row"):
            row = self.first.associate_with_finding(self.finding, test=self.test_b)
            self.assertEqual(self.test_b.id, row.test_id)
        self.assertEqual(2, LocationFindingReference.objects.filter(location=self.first, finding=self.finding).count())

    def test_one_row_per_location_finding_and_test(self):
        self._row(self.first, self.test_a)
        self._row(self.first, self.test_b)
        with self.assertRaises(ValidationError):
            self._row(self.first, self.test_a)

    def test_recorded_locations_are_attributed_to_the_importing_test(self):
        """A finding owned by test A that test B reports gets rows attributed to B."""
        manager = LocationManager(self.product)
        manager.set_test(self.test_b)
        manager.record_locations_for_finding(self.finding, [LocationData.url(url="https://first.example.com/")])
        manager.persist()
        rows = LocationFindingReference.objects.filter(finding=self.finding)
        self.assertEqual([(self.first.id, self.test_b.id)], list(rows.values_list("location_id", "test_id")))

    def test_reimport_mitigates_only_its_own_tests_rows(self):
        self._row(self.first, self.test_a)
        self._row(self.first, self.test_b)
        self._row(self.second, self.test_b)
        # Test B fixed the first location and still reports the second.
        self._reimport(self.test_b, reported=["https://second.example.com/"])
        with self.subTest("test B's row for the fixed location"):
            self.assertEqual(Mitigated, self._status(self.first, self.test_b))
        with self.subTest("test A still reports the fixed location"):
            self.assertEqual(Active, self._status(self.first, self.test_a))
        with self.subTest("test B's row for the location it still reports"):
            self.assertEqual(Active, self._status(self.second, self.test_b))
        with self.subTest("roll-up: the first location is still active on the finding"):
            rolled = LocationFindingReference.objects.filter(finding=self.finding).rolled_up_statuses()
            self.assertEqual(Active, rolled[self.finding.id, self.first.id])

    def test_reimport_without_a_test_touches_the_findings_own_rows(self):
        self._row(self.first, self.test_a)
        self._row(self.first, self.test_b)
        manager = LocationManager(self.product)
        new_finding = Finding(test=self.test_a, title=self.finding.title, severity="High", reporter=self.reporter)
        new_finding.unsaved_locations = []
        manager.update_location_status(self.finding, new_finding, None)
        manager.persist()
        self.assertEqual(Mitigated, self._status(self.first, self.test_a))
        self.assertEqual(Active, self._status(self.first, self.test_b))

    def test_reimport_keeps_a_persons_decision(self):
        self._row(self.first, self.test_b, status=FalsePositive)
        self._reimport(self.test_b, reported=[])
        self.assertEqual(FalsePositive, self._status(self.first, self.test_b))

    def test_copy_moves_rows_to_the_copys_test(self):
        """A location two tests reported is copied once, onto the copy's test, with the rolled-up status."""
        self._row(self.first, self.test_a, status=Mitigated)
        self._row(self.first, self.test_b, status=Active)
        copy = self.finding.copy(test=self.test_b)
        self.assertEqual(
            [(self.first.id, self.test_b.id, Active)],
            list(LocationFindingReference.objects.filter(finding=copy).values_list("location_id", "test_id", "status")),
        )
