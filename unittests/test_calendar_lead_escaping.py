import datetime

from django.core.cache import cache
from django.utils import timezone

from dojo.models import Dojo_User, Engagement, Product, Product_Type, Test, Test_Type
from unittests.dojo_test_case import DojoTestCase

START = datetime.date(2026, 1, 5)
END = datetime.date(2026, 1, 9)


class TestCalendarLeadEscaping(DojoTestCase):

    @classmethod
    def setUpTestData(cls):
        cls.user = Dojo_User.objects.create(username="calendar_lead_user", is_active=True)

    def setUp(self):
        cache.clear()
        self.client.force_login(self.user)

    def test_lead_values_stay_inside_the_js_string(self):
        for url in ("/calendar", "/calendar/engagements", "/calendar/tests"):
            with self.subTest(url=url):
                response = self.client.get(url, {"lead": ["0", "\\", "+alert(1)]);//"]})
                self.assertEqual(response.status_code, 200)
                content = response.content.decode()
                self.assertNotIn("'\\',", content)
                self.assertIn("'\\u005C',", content)


class TestCalendarEventTitleEscaping(DojoTestCase):

    """Stored names are written into single-quoted JS strings for the event titles."""

    @classmethod
    def setUpTestData(cls):
        cls.admin = Dojo_User.objects.create(username="calendar_admin", is_active=True, is_superuser=True)
        cls.lead = Dojo_User.objects.create(username="calendar_lead", first_name="Lead\\", is_active=True)
        prod_type = Product_Type.objects.create(name="calendar pt")
        product = Product.objects.create(name="Prod\\", description="calendar", prod_type=prod_type)
        cls.led = Engagement.objects.create(
            name="Eng'</script>", product=product, lead=cls.lead, target_start=START, target_end=END,
        )
        cls.unassigned = Engagement.objects.create(
            name="Unassigned eng", product=product, target_start=START, target_end=END,
        )
        test_type, _ = Test_Type.objects.get_or_create(name="Type\\")
        Test.objects.create(
            engagement=cls.led, test_type=test_type, lead=cls.lead,
            target_start=timezone.make_aware(datetime.datetime.combine(START, datetime.time())),
            target_end=timezone.make_aware(datetime.datetime.combine(END, datetime.time())),
        )

    def setUp(self):
        cache.clear()
        self.client.force_login(self.admin)

    def _get(self, url, params=None):
        response = self.client.get(url, params or {})
        self.assertEqual(response.status_code, 200)
        return response.content.decode()

    def test_engagement_titles_stay_inside_the_js_string(self):
        content = self._get("/calendar/engagements")
        self.assertIn(
            "title: 'Prod\\u005C: Eng\\u0027\\u003C/script\\u003E (Lead\\u005C  (calendar_lead))',", content,
        )
        self.assertNotIn("Prod\\:", content)
        self.assertNotIn("Lead\\ ", content)

    def test_test_titles_stay_inside_the_js_string(self):
        content = self._get("/calendar/tests")
        self.assertIn(
            "title: 'Prod\\u005C: Eng\\u0027\\u003C/script\\u003E - Type\\u005C (Lead\\u005C  (calendar_lead))',", content,
        )
        self.assertNotIn("Type\\ (", content)

    def test_lead_filter_still_selects_engagements(self):
        content = self._get("/calendar/engagements", {"lead": [str(self.lead.id)]})
        self.assertIn(f"$('#lead').val([ '{self.lead.id}', ]);", content)
        self.assertIn("Eng\\u0027", content)
        self.assertNotIn("Unassigned eng", content)

        content = self._get("/calendar/engagements", {"lead": ["-1"]})
        self.assertIn("$('#lead').val([ '\\u002D1', ]);", content)
        self.assertIn("Unassigned eng", content)
        self.assertNotIn("Eng\\u0027", content)

    def test_lead_filter_still_selects_tests(self):
        content = self._get("/calendar/tests", {"lead": [str(self.lead.id)]})
        self.assertIn("Type\\u005C", content)
        content = self._get("/calendar/tests", {"lead": ["-1"]})
        self.assertNotIn("Type\\u005C", content)
