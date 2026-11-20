# Regression: a non-integer `lead` query value made the calendar views return 500.
from django.core.cache import cache
from django.db.models import Q
from django.urls import reverse

from dojo.models import Engagement, User
from dojo.utils import get_lead_filter
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures

CALENDARS = (("engagement_calendar", "engagements"), ("test_calendar", "tests"))


class GetLeadFilterTest(DojoTestCase):

    def test_get_lead_filter_no_values_is_none(self):
        self.assertIsNone(get_lead_filter([]))

    def test_get_lead_filter_zero_means_all(self):
        self.assertIsNone(get_lead_filter(["abc", "0"]))

    def test_get_lead_filter_only_invalid_matches_nothing(self):
        self.assertEqual(get_lead_filter(["abc"]), Q(lead__in=[]))

    def test_get_lead_filter_drops_invalid_values(self):
        self.assertEqual(
            get_lead_filter(["-1", "2", "x", "²", "1.5"]),
            Q(lead__isnull=True) | Q(lead__in=[2]),
        )


@versioned_fixtures
class CalendarLeadFilterTest(DojoTestCase):

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.system_settings(enable_calendar=True)
        cache.clear()
        self.client.force_login(self.get_test_admin())
        self.lead_id = User.objects.get(username="user1").id
        Engagement.objects.filter(pk=6).update(lead=None)

    def get_calendar(self, url_name, query):
        return self.client.get(reverse(url_name) + "?" + query)

    def test_non_numeric_lead_returns_200(self):
        for url_name, _ in CALENDARS:
            with self.subTest(url_name):
                self.assertEqual(self.get_calendar(url_name, "lead=abc").status_code, 200)

    def test_superscript_digit_lead_returns_200(self):
        for url_name, _ in CALENDARS:
            with self.subTest(url_name):
                self.assertEqual(self.get_calendar(url_name, "lead=%C2%B2").status_code, 200)

    def test_huge_digit_string_lead_returns_200(self):
        for url_name, _ in CALENDARS:
            with self.subTest(url_name):
                self.assertEqual(self.get_calendar(url_name, "lead=" + "1" * 4301).status_code, 200)

    def test_mixed_leads_keep_valid_ids(self):
        for url_name, context_key in CALENDARS:
            with self.subTest(url_name):
                response = self.get_calendar(url_name, f"lead=-1&lead=abc&lead={self.lead_id}")
                self.assertEqual(response.status_code, 200)
                lead_ids = {obj.lead_id for obj in response.context[context_key]}
                self.assertEqual(lead_ids, {None, self.lead_id})
