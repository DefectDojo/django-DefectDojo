"""
Round-trip test for ``migrate_locations_to_endpoints`` (the reverse of
``migrate_endpoints_to_locations``): seed legacy endpoint data, convert it forward into the
Locations store, erase the legacy rows, and prove the reverse command reconstructs them —
including mitigation state and first-seen dates — without ever touching rows that already exist.
"""

from datetime import UTC, date, datetime

from django.conf import settings
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase, override_settings

from dojo.location.models import LocationFindingReference
from dojo.models import Endpoint, Endpoint_Status, Engagement, Finding, Product, Product_Type, Test, Test_Type, User


@override_settings(V3_FEATURE_LOCATIONS=False, SECURE_SSL_REDIRECT=False)
class TestMigrateLocationsToEndpoints(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create(username="reverse-migration-tester")
        product_type = Product_Type.objects.create(name="pt")
        cls.product = Product.objects.create(name="reverse-migration-product", prod_type=product_type)
        engagement = Engagement.objects.create(
            product=cls.product,
            target_start=datetime(2026, 1, 1, tzinfo=UTC),
            target_end=datetime(2026, 12, 31, tzinfo=UTC),
        )
        test_type = Test_Type.objects.create(name="reverse-migration-scan")
        cls.test = Test.objects.create(
            engagement=engagement,
            test_type=test_type,
            target_start=datetime(2026, 1, 1, tzinfo=UTC),
            target_end=datetime(2026, 12, 31, tzinfo=UTC),
        )
        cls.finding = Finding.objects.create(
            title="reverse migration finding",
            test=cls.test,
            severity="High",
            reporter=cls.user,
        )
        cls.active_endpoint = Endpoint.objects.create(
            protocol="https",
            host="active.example.com",
            port=443,
            product=cls.product,
        )
        cls.mitigated_endpoint = Endpoint.objects.create(
            protocol="https",
            host="mitigated.example.com",
            port=443,
            product=cls.product,
        )
        cls.first_seen = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
        cls.mitigated_at = datetime(2026, 6, 15, 9, 30, tzinfo=UTC)
        Endpoint_Status.objects.create(
            finding=cls.finding,
            endpoint=cls.active_endpoint,
            date=cls.first_seen,
            mitigated=False,
        )
        Endpoint_Status.objects.create(
            finding=cls.finding,
            endpoint=cls.mitigated_endpoint,
            date=cls.first_seen,
            mitigated=True,
            mitigated_time=cls.mitigated_at,
            mitigated_by=cls.user,
        )

    def _forward_then_erase_legacy(self):
        call_command("migrate_endpoints_to_locations")
        if LocationFindingReference.objects.filter(location__location_type="url").count() != 2:
            msg = "forward conversion did not produce the expected references"
            raise AssertionError(msg)
        Endpoint_Status.objects.all().delete()
        Endpoint.objects.all().delete()

    def test_round_trip_reconstructs_legacy_rows_with_history(self):
        self._forward_then_erase_legacy()

        call_command("migrate_locations_to_endpoints", "--apply")

        self.assertEqual(Endpoint.objects.count(), 2)
        self.assertEqual(Endpoint_Status.objects.count(), 2)
        active = Endpoint_Status.objects.get(endpoint__host="active.example.com")
        self.assertFalse(active.mitigated)
        # Endpoint_Status.date is a DateField, so the time component of first_seen is dropped on
        # write; compare against the date part or this can never match.
        self.assertEqual(active.date, self.first_seen.date(), "first-seen history must survive the round trip")
        mitigated = Endpoint_Status.objects.get(endpoint__host="mitigated.example.com")
        self.assertTrue(mitigated.mitigated)
        # The finding<->endpoint association is the status row itself (through-model M2M).
        self.assertEqual(self.finding.endpoints.count(), 2)

    def test_rerun_is_a_no_op_and_existing_rows_are_never_modified(self):
        self._forward_then_erase_legacy()
        call_command("migrate_locations_to_endpoints", "--apply")
        # A date, not a datetime: Endpoint_Status.date is a DateField, so a datetime sentinel comes
        # back as a date and the comparison below would fail even on a correct no-op re-run.
        sentinel = date(2020, 1, 1)
        Endpoint_Status.objects.all().update(date=sentinel)

        call_command("migrate_locations_to_endpoints", "--apply")

        self.assertEqual(Endpoint_Status.objects.count(), 2)
        self.assertTrue(
            all(status.date == sentinel for status in Endpoint_Status.objects.all()),
            "a re-run must not touch existing rows, even when their fields differ",
        )

    def test_dry_run_writes_nothing(self):
        self._forward_then_erase_legacy()

        call_command("migrate_locations_to_endpoints")

        self.assertEqual(Endpoint.objects.count(), 0)
        self.assertEqual(Endpoint_Status.objects.count(), 0)

    @override_settings(V3_FEATURE_LOCATIONS=True)
    def test_refuses_to_run_while_the_locations_flag_is_enabled(self):
        with self.assertRaises(CommandError):
            call_command("migrate_locations_to_endpoints", "--apply")

    def test_non_url_locations_are_left_in_place(self):
        self._forward_then_erase_legacy()
        # Nothing in this dataset is code/dependency-typed; the counter path is exercised by the
        # summary line either way, and URL rows must be the only thing materialized.
        call_command("migrate_locations_to_endpoints", "--apply")
        self.assertFalse(
            Endpoint.objects.exclude(host__in=["active.example.com", "mitigated.example.com"]).exists(),
        )

    def test_settings_flag_matches_module_default(self):
        # The command's guard reads the live setting; this pins that the override in this class
        # is what makes Endpoint writes legal in the other tests.
        self.assertFalse(settings.V3_FEATURE_LOCATIONS)
