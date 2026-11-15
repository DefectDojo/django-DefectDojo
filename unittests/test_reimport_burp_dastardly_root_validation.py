"""
Reimport integrity: a well-formed XML report whose root element is not part of
the Burp Dastardly JUnit-style contract must be rejected with a validation
error and must not mitigate existing findings.

Regression for the defect where BurpDastardlyParser returned [] for any
well-formed non-testsuites document, so an authorized same-Test reimport with
close_old_findings=True silently mitigated every active finding in the Test.
"""

import io
from datetime import datetime

from crum import impersonate
from django.utils import timezone

from dojo.importers.default_reimporter import DefaultReImporter
from dojo.models import (
    Development_Environment,
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
    User,
)

from .dojo_test_case import DojoTestCase

SCAN_DATE = timezone.make_aware(datetime(2026, 1, 15, 12, 0, 0))

UNEXPECTED_ROOT = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<unexpected/>'
)

VALID_EMPTY = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<testsuites/>'
)


class BurpDastardlyUnexpectedRootReimportTest(DojoTestCase):

    def setUp(self):
        super().setUp()
        self.user, _ = User.objects.get_or_create(username="admin")
        self.environment, _ = Development_Environment.objects.get_or_create(name="Development")
        self.product_type, _ = Product_Type.objects.get_or_create(name="burp-root-reimport")
        product = Product.objects.create(
            name="burp-root-reimport-product", description="Test", prod_type=self.product_type,
        )
        engagement = Engagement.objects.create(
            name="burp-root-reimport-engagement",
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        self.test_type, _ = Test_Type.objects.get_or_create(name="Burp Dastardly Scan")
        self.test = Test.objects.create(
            engagement=engagement,
            test_type=self.test_type,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        for i in range(3):
            Finding.objects.create(
                title=f"Pre-existing finding {i}",
                test=self.test,
                description=f"Pre-existing finding {i}",
                severity="High",
                numerical_severity=4,
                active=True,
                false_p=False,
                duplicate=False,
                out_of_scope=False,
                mitigated=None,
                date=SCAN_DATE.date(),
            )

    def _reimport(self, report: str, **kwargs):
        with impersonate(self.user):
            importer = DefaultReImporter(
                test=self.test,
                scan_type="Burp Dastardly Scan",
                user=self.user,
                environment=self.environment,
                **kwargs,
            )
            return importer.process_scan(
                io.BytesIO(report.encode("utf-8")),  # type: ignore[arg-type]
            )

    def test_unexpected_root_reimport_rejected_without_mitigating(self):
        active_before = list(self.test.finding_set.filter(active=True).order_by("id"))
        self.assertEqual(3, len(active_before))

        with self.assertRaises(Exception) as ctx:
            self._reimport(UNEXPECTED_ROOT, close_old_findings=True)

        self.assertIn("Unexpected root element", str(ctx.exception))

        # All original findings must remain active and unmitigated
        for finding in active_before:
            finding.refresh_from_db()
            self.assertTrue(finding.active)
            self.assertFalse(finding.is_mitigated)

    def test_valid_empty_report_still_mitigates(self):
        """The fix must preserve legitimate empty-scan closure semantics."""
        self._reimport(VALID_EMPTY, close_old_findings=True)
        for finding in self.test.finding_set.all():
            finding.refresh_from_db()
            self.assertFalse(finding.active)
            self.assertTrue(finding.is_mitigated)
