from datetime import datetime, timedelta
from typing import List, Tuple
from unittest.mock import patch

from dateutil.relativedelta import relativedelta
from .dojo_test_case import DojoTestCase
from django.urls import reverse
from django.utils import timezone

from dojo.models import Finding, Test, Engagement, Risk_Acceptance, System_Settings

class TestResponseHeaders(DojoTestCase):
    fixtures = ['dojo_testdata.json']

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.now = timezone.now()
        cls.week_ago = cls.now - timedelta(weeks=1)
        cls.month_ago = cls.now - relativedelta(months=1)
        cls.year_ago = cls.now - relativedelta(years=1)

    @classmethod
    def setUpTestData(cls) -> None:
        System_Settings.objects.update(enable_deduplication=False)  # The default deduplication does not work.
        Engagement.objects.all().delete()

    def test_server_header_not_in_response(self):
        response = self.client.get(reverse('login'))

        self.assertFalse('Server' in response.headers)
