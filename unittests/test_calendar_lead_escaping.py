from django.core.cache import cache

from dojo.models import Dojo_User
from unittests.dojo_test_case import DojoTestCase


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
