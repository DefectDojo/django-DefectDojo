import logging
from unittest.mock import patch

import django
from dateutil.relativedelta import relativedelta
from django.utils import timezone

from dojo.models import (
    Finding,
    SLA_Configuration,
    Test,
)
from dojo.templatetags.display_tags import finding_sla

from .dojo_test_case import DojoTestCase

logger = logging.getLogger(__name__)


class TestSLACalculations(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.now = timezone.now()

        cls.sla_config = SLA_Configuration.objects.all().first()
        cls.sla_config.enforce_critical = True
        cls.sla_config.enforce_high = True
        cls.sla_config.enforce_medium = True
        cls.sla_config.enforce_low = True
        cls.sla_config.save()
        # for finding in Finding.objects.all().order_by("test"):
        #     logger.error(f"Finding: {finding.test.id} {finding.id} {finding.date} {finding.sla_expiration_date}")
        logger.error(f"SLA Config: {cls.sla_config.critical} {cls.sla_config.high} {cls.sla_config.medium} {cls.sla_config.low}")

    # New finding should have sla_expiration_date set
    def test_new_finding(self):
        finding = Finding(test=Test.objects.get(id=89), title="Test Finding", severity="High")
        finding.save()

        logger.debug(f"Finding: {finding.test.id} {finding.id} {finding.date} {finding.mitigated}  {finding.sla_expiration_date}")
        logger.debug(finding_sla(finding))

        self.assertEqual((self.now + relativedelta(days=self.sla_config.high)).date(), finding.sla_expiration_date)
        self.assertEqual(self.sla_config.high, finding.sla_days_remaining())

    # Finding within SLA should have correct sla_expiration_date and days_remaining
    def test_active_within_sla(self):
        finding = Finding(test=Test.objects.get(id=89), title="Test Finding", severity="High")
        finding.save()

        logger.debug(f"Finding: {finding.test.id} {finding.id} {finding.date} {finding.mitigated}  {finding.sla_expiration_date}")
        logger.debug(finding_sla(finding))

        with patch("django.db.models.fields.timezone.now") as mock_now:
            mock_now.return_value = self.now + relativedelta(days=10)
            self.assertEqual((self.now + relativedelta(days=self.sla_config.high)).date(), finding.sla_expiration_date)
            self.assertEqual(self.sla_config.high - 10, finding.sla_days_remaining())

    # Finding outside SLA should have correct sla_expiration_date and days_remaining
    def test_active_outside_sla(self):
        finding = Finding(test=Test.objects.get(id=89), title="Test Finding", severity="High")
        finding.save()

        logger.debug(f"Finding: {finding.test.id} {finding.id} {finding.date} {finding.mitigated}  {finding.sla_expiration_date}")
        logger.debug(finding_sla(finding))

        with patch("django.db.models.fields.timezone.now") as mock_now:
            mock_now.return_value = self.now + relativedelta(days=50)
            self.assertEqual((self.now + relativedelta(days=self.sla_config.high)).date(), finding.sla_expiration_date)
            self.assertEqual(self.sla_config.high - 50, finding.sla_days_remaining())

    # Finding mitigated inside SLA should have correct sla_expiration_date and days_remaining
    def test_mitigated_inside_sla(self):
        finding = Finding(test=Test.objects.get(id=89), title="Test Finding", severity="High")
        finding.save()

        logger.debug(f"Finding: {finding.test.id} {finding.id} {finding.date} {finding.mitigated}  {finding.sla_expiration_date}")
        logger.debug(finding_sla(finding))

        initial_sla_expiration_date = finding.sla_expiration_date

        with patch("django.db.models.fields.timezone.now") as mock_now:
            mock_now.return_value = self.now + relativedelta(days=10)
            finding.mitigated = mock_now.return_value
            finding.is_mitigated = True
            finding.active = False
            finding.save()
            logger.debug(f"Finding: {finding.test.id} {finding.id} {finding.date} {finding.mitigated}  {finding.sla_expiration_date}")
            logger.debug(finding_sla(finding))

            # sla_expiration_date should not change just because a finding is mitigated
            self.assertEqual(initial_sla_expiration_date, finding.sla_expiration_date)
            self.assertEqual((self.now + relativedelta(days=self.sla_config.high)).date(), finding.sla_expiration_date)
            self.assertEqual(20, finding.sla_days_remaining())
            self.assertTrue("within SLA" in finding_sla(finding))
            self.assertTrue(">20<" in finding_sla(finding))

        with patch("django.db.models.fields.timezone.now") as mock_now:
            mock_now.return_value = self.now + relativedelta(days=20)
            finding.save()

            logger.debug(f"Finding: {finding.test.id} {finding.id} {finding.date} {finding.mitigated}  {finding.sla_expiration_date}")
            logger.debug(finding_sla(finding))

            # sla_expiration_date should not change just because a finding is saved
            self.assertEqual(initial_sla_expiration_date, finding.sla_expiration_date)
            self.assertEqual((self.now + relativedelta(days=self.sla_config.high)).date(), finding.sla_expiration_date)
            self.assertEqual(20, finding.sla_days_remaining())
            self.assertTrue("within SLA" in finding_sla(finding))
            self.assertTrue(">20<" in finding_sla(finding))

    # Finding mitigated outside SLA should have correct sla_expiration_date and days_remaining
    def test_mitigated_outside_sla(self):
        finding = Finding(test=Test.objects.get(id=89), title="Test Finding", severity="High")
        finding.save()

        logger.debug(f"Finding: {finding.test.id} {finding.id} {finding.date} {finding.mitigated}  {finding.sla_expiration_date}")
        logger.debug(finding_sla(finding))

        initial_sla_expiration_date = finding.sla_expiration_date

        with patch("django.db.models.fields.timezone.now") as mock_now:
            mock_now.return_value = self.now + relativedelta(days=45)
            finding.mitigated = mock_now.return_value
            finding.is_mitigated = True
            finding.active = False
            finding.save()

            logger.debug(f"Finding: {finding.test.id} {finding.id} {finding.date} {finding.mitigated}  {finding.sla_expiration_date}")
            logger.debug(finding_sla(finding))

            # sla_expiration_date should not change just because a finding is mitigated
            self.assertEqual(initial_sla_expiration_date, finding.sla_expiration_date)
            self.assertEqual((self.now + relativedelta(days=self.sla_config.high)).date(), finding.sla_expiration_date)
            self.assertEqual(-15, finding.sla_days_remaining())
            self.assertTrue("Out of SLA" in finding_sla(finding))
            self.assertTrue("15 days past" in finding_sla(finding))
            self.assertTrue(">15<" in finding_sla(finding))

        with patch("django.db.models.fields.timezone.now") as mock_now:
            mock_now.return_value = self.now + relativedelta(days=55)
            finding.save()

            logger.debug(f"Finding: {finding.test.id} {finding.id} {finding.date} {finding.mitigated}  {finding.sla_expiration_date}")
            logger.debug(finding_sla(finding))

            # sla_expiration_date should not change just because a finding is saved
            self.assertEqual(initial_sla_expiration_date, finding.sla_expiration_date)
            self.assertEqual((self.now + relativedelta(days=self.sla_config.high)).date(), finding.sla_expiration_date)
            self.assertEqual(-15, finding.sla_days_remaining())
            self.assertTrue("Out of SLA" in finding_sla(finding))
            self.assertTrue("15 days past" in finding_sla(finding))
            self.assertTrue(">15<" in finding_sla(finding))

    # test implicit parsing of finding.date (GitHub #12299)
    def test_finding_date_formats(self):
        with self.subTest(i=0):
            # date set to now shouldn't result in an error
            finding = Finding(test=Test.objects.get(id=89), title="Test Finding 1", severity="High")
            finding.date = timezone.now()
            finding.save()

        with self.subTest(i=1):
            # date set to simple date string shouldn't result in an error
            finding = Finding(test=Test.objects.get(id=89), title="Test Finding 2", severity="High")
            finding.date = "2025-04-23"
            finding.save()

        with self.subTest(i=2):
            # date set to ISO date string shouldn't result in an error
            finding = Finding(test=Test.objects.get(id=89), title="Test Finding 3", severity="High")
            finding.date = "2025-04-23T12:00:00Z"[:10]
            finding.save()

        with self.subTest(i=3) and self.assertRaises(django.core.exceptions.ValidationError):
            # date set to ISO datetime string will result in a Django Error, not an error in our code
            finding = Finding(test=Test.objects.get(id=89), title="Test Finding 3", severity="High")
            finding.date = "2025-04-23T12:00:00+02:00"
            finding.save()
