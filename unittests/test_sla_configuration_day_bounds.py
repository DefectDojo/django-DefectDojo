# Regression: SLA configurations accepted negative and out-of-range day counts. A negative period put
# every finding's SLA expiration before its own date; a huge one overflowed the date arithmetic.
from dojo.api_v2.serializers import SLAConfigurationSerializer
from dojo.forms import SLAConfigForm
from dojo.models import SLA_Configuration
from unittests.dojo_test_case import DojoTestCase

DAY_FIELDS = ("critical", "high", "medium", "low")
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
