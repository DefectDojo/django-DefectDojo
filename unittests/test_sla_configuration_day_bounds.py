# Regression: SLA configurations accepted negative and out-of-range day counts. A negative period put
# every finding's SLA expiration before its own date; a huge one overflowed the date arithmetic.
import importlib

from django.apps import apps

from dojo.api_v2.serializers import SLAConfigurationSerializer
from dojo.forms import SLAConfigForm
from dojo.models import SLA_Configuration
from unittests.dojo_test_case import DojoTestCase

DAY_FIELDS = ("critical", "high", "medium", "low")
migration = importlib.import_module("dojo.db_migrations.0314_sla_configuration_day_bounds")
# Written out rather than imported, so the test pins the bound itself.
SLA_DAYS_MAX = 36500


def _payload(**overrides):
    return {
        "name": "Day bounds",
        "critical": 7,
        "enforce_critical": True,
        "high": 30,
        "enforce_high": True,
        "medium": 90,
        "enforce_medium": True,
        "low": 120,
        "enforce_low": True,
        "restart_sla_on_reactivation": False,
        **overrides,
    }


class TestSLAConfigurationDayBounds(DojoTestCase):

    def test_api_serializer_refuses_out_of_range_days(self):
        for field in DAY_FIELDS:
            for days in (-1, -7, SLA_DAYS_MAX + 1, 1_000_000_000):
                with self.subTest(field=field, days=days):
                    serializer = SLAConfigurationSerializer(data=_payload(**{field: days}))
                    self.assertFalse(serializer.is_valid(), msg=f"{field}={days} was accepted")
                    self.assertIn(field, serializer.errors)

    def test_api_serializer_accepts_the_ends_of_the_range(self):
        for field in DAY_FIELDS:
            for days in (0, SLA_DAYS_MAX):
                with self.subTest(field=field, days=days):
                    serializer = SLAConfigurationSerializer(data=_payload(name=f"{field} {days}", **{field: days}))
                    self.assertTrue(serializer.is_valid(), msg=serializer.errors)
                    sla = serializer.save()
                    self.assertEqual(SLA_Configuration.objects.values_list(field, flat=True).get(id=sla.id), days)

    def test_form_refuses_out_of_range_days(self):
        for field in DAY_FIELDS:
            for days in (-1, SLA_DAYS_MAX + 1):
                with self.subTest(field=field, days=days):
                    form = SLAConfigForm(data=_payload(**{field: days}))
                    self.assertFalse(form.is_valid(), msg=f"{field}={days} was accepted")
                    self.assertIn(field, form.errors)

    def test_form_accepts_the_ends_of_the_range(self):
        for field in DAY_FIELDS:
            for days in (0, SLA_DAYS_MAX):
                with self.subTest(field=field, days=days):
                    form = SLAConfigForm(data=_payload(name=f"{field} {days}", **{field: days}))
                    self.assertTrue(form.is_valid(), msg=form.errors)

    def test_migration_brings_stored_days_into_range(self):
        # Stored the way the unbounded API stored them: straight to the row, no validation.
        below = SLA_Configuration.objects.create(name="Below range")
        above = SLA_Configuration.objects.create(name="Above range")
        kept = SLA_Configuration.objects.create(name="In range")
        SLA_Configuration.objects.filter(id=below.id).update(**dict.fromkeys(DAY_FIELDS, -7))
        SLA_Configuration.objects.filter(id=above.id).update(**dict.fromkeys(DAY_FIELDS, 1_000_000_000))
        SLA_Configuration.objects.filter(id=kept.id).update(critical=0, high=1, medium=SLA_DAYS_MAX, low=120)

        # A row that holds an out-of-range value cannot be saved through the form until it is clamped.
        self.assertFalse(SLAConfigForm(data=_payload(name="Below range", critical=-7), instance=below).is_valid())

        migration.clamp_sla_day_counts(apps, None)
        migration.clamp_sla_day_counts(apps, None)  # a second run changes nothing

        rows = SLA_Configuration.objects.in_bulk([below.id, above.id, kept.id])
        self.assertEqual([getattr(rows[below.id], f) for f in DAY_FIELDS], [0, 0, 0, 0])
        self.assertEqual([getattr(rows[above.id], f) for f in DAY_FIELDS], [SLA_DAYS_MAX] * 4)
        self.assertEqual([getattr(rows[kept.id], f) for f in DAY_FIELDS], [0, 1, SLA_DAYS_MAX, 120])
        stored = {f: getattr(rows[below.id], f) for f in DAY_FIELDS}
        self.assertTrue(SLAConfigForm(data=_payload(name="Below range", **stored), instance=rows[below.id]).is_valid())
