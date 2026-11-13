import datetime

from django.core.cache import cache
from django.urls import reverse
from django.utils import timezone

from dojo.models import Dojo_User, Engagement, Product, Product_Type, Test, Test_Type
from unittests.dojo_test_case import DojoTestCase

START = datetime.date(2026, 1, 5)
END = datetime.date(2026, 1, 9)
LINE_SEPARATOR = chr(0x2028)
HOSTILE = ["\\", "'", "</script>", "+alert(1)]);//", LINE_SEPARATOR, "-1"]
JS_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}


def read_js_string(content, i):
    """Decode the single-quoted JS string literal that opens at content[i], as a browser would."""
    out = []
    i += 1
    while True:
        c = content[i]
        if c == "'":
            return i + 1, "".join(out)
        if c in "\r\n":
            msg = "unterminated JS string literal"
            raise AssertionError(msg)
        if c == "\\":
            nxt = content[i + 1]
            if nxt == "u":
                out.append(chr(int(content[i + 2:i + 6], 16)))
                i += 6
                continue
            out.append(JS_ESCAPES.get(nxt, nxt))
            i += 2
            continue
        out.append(c)
        i += 1


class CalendarScriptMixin:

    def read_js_string_array(self, content, prefix):
        """Decode the array of JS string literals that follows prefix; fail on anything that is not a literal."""
        i = content.index(prefix) + len(prefix)
        values = []
        while True:
            while content[i] in " ,\n":
                i += 1
            if content[i] == "]":
                return values
            self.assertEqual(content[i], "'", f"code outside a string literal: {content[i:i + 40]!r}")
            i, value = read_js_string(content, i)
            values.append(value)

    def read_js_strings_after(self, content, marker):
        """Decode every JS string literal that directly follows marker."""
        values = []
        start = content.find(marker)
        while start != -1:
            _, value = read_js_string(content, start + len(marker) - 1)
            values.append(value)
            start = content.find(marker, start + 1)
        return values

    def get_calendar(self, url, params=None):
        response = self.client.get(url, params or {})
        self.assertEqual(response.status_code, 200)
        return response.content.decode()


class TestCalendarLeadEscaping(CalendarScriptMixin, DojoTestCase):

    @classmethod
    def setUpTestData(cls):
        cls.user = Dojo_User.objects.create(username="calendar_lead_user", is_active=True)

    def setUp(self):
        cache.clear()
        self.client.force_login(self.user)

    def test_lead_values_stay_inside_the_js_string(self):
        submitted = ["0", *HOSTILE]
        for url in ("/calendar", "/calendar/engagements", "/calendar/tests"):
            with self.subTest(url=url):
                content = self.get_calendar(url, {"lead": submitted})
                self.assertEqual(self.read_js_string_array(content, "$('#lead').val(["), submitted)


class TestCalendarEventTitleEscaping(CalendarScriptMixin, DojoTestCase):

    """Stored names are written into single-quoted JS strings for the event titles."""

    @classmethod
    def setUpTestData(cls):
        cls.admin = Dojo_User.objects.create(username="calendar_admin", is_active=True, is_superuser=True)
        cls.lead = Dojo_User.objects.create(username="calendar_lead", first_name="Lead\\", is_active=True)
        prod_type = Product_Type.objects.create(name="calendar pt")
        product = Product.objects.create(name="Prod\\", description="calendar", prod_type=prod_type)
        cls.led = Engagement.objects.create(
            name="Eng'</script>" + LINE_SEPARATOR, product=product, lead=cls.lead, target_start=START, target_end=END,
        )
        cls.unassigned = Engagement.objects.create(
            name="Unassigned eng", product=product, target_start=START, target_end=END,
        )
        test_type, _ = Test_Type.objects.get_or_create(name="Type\\")
        dates = {
            "target_start": timezone.make_aware(datetime.datetime.combine(START, datetime.time())),
            "target_end": timezone.make_aware(datetime.datetime.combine(END, datetime.time())),
        }
        cls.led_test = Test.objects.create(engagement=cls.led, test_type=test_type, lead=cls.lead, **dates)
        cls.unassigned_test = Test.objects.create(engagement=cls.unassigned, test_type=test_type, **dates)

    def setUp(self):
        cache.clear()
        self.client.force_login(self.admin)

    def test_engagement_titles_stay_inside_the_js_string(self):
        content = self.get_calendar("/calendar/engagements")
        self.assertCountEqual(self.read_js_strings_after(content, "title: '"), [
            f"Prod\\: Eng'</script>{LINE_SEPARATOR} ({self.lead})",
            "Prod\\: Unassigned eng (Unassigned)",
        ])

    def test_test_titles_stay_inside_the_js_string(self):
        content = self.get_calendar("/calendar/tests")
        self.assertCountEqual(self.read_js_strings_after(content, "title: '"), [
            f"Prod\\: Eng'</script>{LINE_SEPARATOR} - Type\\ ({self.lead})",
            "Prod\\: Unassigned eng - Type\\ (Unassigned)",
        ])

    def assert_events(self, content, view_name, shown, hidden):
        urls = self.read_js_strings_after(content, "url: '")
        self.assertCountEqual(urls, [reverse(view_name, args=(obj.id,)) for obj in shown])
        for obj in hidden:
            self.assertNotIn(reverse(view_name, args=(obj.id,)), urls)

    def test_lead_filter_still_selects_engagements(self):
        url = "/calendar/engagements"
        content = self.get_calendar(url, {"lead": [str(self.lead.id)]})
        self.assertEqual(self.read_js_string_array(content, "$('#lead').val(["), [str(self.lead.id)])
        self.assertEqual(self.read_js_strings_after(content, "$('#caltype').val('"), ["engagements"])
        self.assert_events(content, "view_engagement", shown=[self.led], hidden=[self.unassigned])

        content = self.get_calendar(url, {"lead": ["-1"]})
        self.assertEqual(self.read_js_string_array(content, "$('#lead').val(["), ["-1"])
        self.assert_events(content, "view_engagement", shown=[self.unassigned], hidden=[self.led])

    def test_lead_filter_still_selects_tests(self):
        url = "/calendar/tests"
        content = self.get_calendar(url, {"lead": [str(self.lead.id)]})
        self.assertEqual(self.read_js_strings_after(content, "$('#caltype').val('"), ["tests"])
        self.assert_events(content, "view_test", shown=[self.led_test], hidden=[self.unassigned_test])

        content = self.get_calendar(url, {"lead": ["-1"]})
        self.assert_events(content, "view_test", shown=[self.unassigned_test], hidden=[self.led_test])
