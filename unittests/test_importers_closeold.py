import logging

from django.utils import timezone

from dojo.importers.default_importer import DefaultImporter
from dojo.models import Development_Environment, Engagement, Product, Product_Type, User

from .dojo_test_case import DojoTestCase, get_unit_tests_scans_path

logger = logging.getLogger(__name__)


class TestDojoCloseOld(DojoTestCase):
    def test_close_old_same_engagement(self):
        scan_type = "Acunetix Scan"
        user, _ = User.objects.get_or_create(username="admin")
        product_type, _ = Product_Type.objects.get_or_create(name="closeold")
        environment, _ = Development_Environment.objects.get_or_create(name="Development")
        product, _ = Product.objects.get_or_create(
            name="TestDojoCloseOldImporter1",
            prod_type=product_type,
        )
        engagement, _ = Engagement.objects.get_or_create(
            name="Close Old Same Engagement",
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        import_options = {
            "user": user,
            "lead": user,
            "scan_date": None,
            "environment": environment,
            "active": True,
            "verified": False,
            "engagement": engagement,
            "scan_type": scan_type,
        }
        # Import first test
        with open(get_unit_tests_scans_path("acunetix") / "many_findings.xml", "r+", encoding="utf-8") as many_findings_scan:
            importer = DefaultImporter(close_old_findings=False, **import_options)
            _, _, len_new_findings, len_closed_findings, _, _, _ = importer.process_scan(many_findings_scan)
            self.assertEqual(4, len_new_findings)
            self.assertEqual(0, len_closed_findings)
        # Import same test, should close no findings
        with open(get_unit_tests_scans_path("acunetix") / "many_findings.xml", "r+", encoding="utf-8") as many_findings_scan:
            importer = DefaultImporter(close_old_findings=True, **import_options)
            _, _, len_new_findings, len_closed_findings, _, _, _ = importer.process_scan(many_findings_scan)
            self.assertEqual(4, len_new_findings)
            self.assertEqual(0, len_closed_findings)
        # Import test with only one finding. Remaining findings should close
        with open(get_unit_tests_scans_path("acunetix") / "one_finding.xml", "r+", encoding="utf-8") as single_finding_scan:
            importer = DefaultImporter(close_old_findings=True, **import_options)
            _, _, len_new_findings, len_closed_findings, _, _, _ = importer.process_scan(single_finding_scan)
            self.assertEqual(1, len_new_findings)
            # Dedupe is off and close old findings does not close old findings if they are the same finding.
            # If this behavior changes, or dedupe is on, the number of closed findings will be 4
            self.assertEqual(8, len_closed_findings)

    def test_close_old_same_product_scan(self):
        scan_type = "Acunetix Scan"
        user, _ = User.objects.get_or_create(username="admin")
        product_type, _ = Product_Type.objects.get_or_create(name="test2")
        product, _ = Product.objects.get_or_create(
            name="TestDojoCloseOldImporter2",
            prod_type=product_type,
        )
        engagement1, _ = Engagement.objects.get_or_create(
            name="Close Old Same Product 1",
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        engagement2, _ = Engagement.objects.get_or_create(
            name="Close Old Same Product 2",
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        engagement3, _ = Engagement.objects.get_or_create(
            name="Close Old Same Product 3",
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        environment, _ = Development_Environment.objects.get_or_create(name="Development")
        import_options = {
            "user": user,
            "lead": user,
            "scan_date": None,
            "environment": environment,
            "active": True,
            "verified": False,
            "close_old_findings_product_scope": True,
            "scan_type": scan_type,
        }
        # Import first test
        with open(get_unit_tests_scans_path("acunetix") / "many_findings.xml", "r+", encoding="utf-8") as many_findings_scan:
            importer = DefaultImporter(engagement=engagement1, close_old_findings=False, **import_options)
            _, _, len_new_findings, len_closed_findings, _, _, _ = importer.process_scan(many_findings_scan)
            self.assertEqual(4, len_new_findings)
            self.assertEqual(0, len_closed_findings)
        # Import same test, should close no findings
        with open(get_unit_tests_scans_path("acunetix") / "many_findings.xml", "r+", encoding="utf-8") as many_findings_scan:
            importer = DefaultImporter(engagement=engagement2, close_old_findings=True, **import_options)
            _, _, len_new_findings, len_closed_findings, _, _, _ = importer.process_scan(many_findings_scan)
            self.assertEqual(4, len_new_findings)
            self.assertEqual(0, len_closed_findings)
        # Import test with only one finding. Remaining findings should close
        with open(get_unit_tests_scans_path("acunetix") / "one_finding.xml", "r+", encoding="utf-8") as single_finding_scan:
            importer = DefaultImporter(engagement=engagement3, close_old_findings=True, **import_options)
            _, _, len_new_findings, len_closed_findings, _, _, _ = importer.process_scan(single_finding_scan)
            self.assertEqual(1, len_new_findings)
            # Dedupe is off, and close old findings does not close old findings if they are the same finding.
            # If this behavior changes, or dedupe is on, the number of closed findings will be 4
            self.assertEqual(8, len_closed_findings)
