from .dojo_test_case import DojoTestCase, get_unit_tests_path
from django.utils import timezone
from dojo.importers.importer.importer import DojoDefaultImporter as Importer
from dojo.models import Development_Environment, Engagement, Product, Product_Type, User
import logging


logger = logging.getLogger(__name__)


class TestDojoCloseOld(DojoTestCase):
    def test_close_old_same_engagement(self):
        scan = get_unit_tests_path() + "/scans/acunetix/many_findings.xml"
        scan_type = "Acunetix Scan"

        user, _ = User.objects.get_or_create(username="admin")
        user_reporter, _ = User.objects.get_or_create(username="user_reporter")

        product_type, _ = Product_Type.objects.get_or_create(name="closeold")
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
        importer = Importer()
        scan_date = None
        environment, _ = Development_Environment.objects.get_or_create(name="Development")
        # Import first test
        test, len_new_findings, len_closed_findings, _ = importer.import_scan(scan, scan_type, engagement, lead=None, environment=environment,
                    active=True, verified=False, tags=None, minimum_severity=None,
                    user=user, endpoints_to_add=None, scan_date=scan_date, version=None, branch_tag=None, build_id=None,
                    commit_hash=None, push_to_jira=None, close_old_findings=False, group_by=None, api_scan_configuration=None)

        self.assertEqual(4, len_new_findings)
        self.assertEqual(0, len_closed_findings)
        # Import same test, should close no findings
        test, len_new_findings, len_closed_findings, _ = importer.import_scan(scan, scan_type, engagement, lead=None, environment=environment,
                    active=True, verified=False, tags=None, minimum_severity=None,
                    user=user, endpoints_to_add=None, scan_date=scan_date, version=None, branch_tag=None, build_id=None,
                    commit_hash=None, push_to_jira=None, close_old_findings=True, group_by=None, api_scan_configuration=None)
        self.assertEqual(4, len_new_findings)
        self.assertEqual(0, len_closed_findings)
        # Import test with only one finding. Remaining findings should close
        scan = open(get_unit_tests_path() + "/scans/acunetix/one_finding.xml")
        test, len_new_findings, len_closed_findings, _ = importer.import_scan(scan, scan_type, engagement, lead=None, environment=environment,
                    active=True, verified=False, tags=None, minimum_severity=None,
                    user=user, endpoints_to_add=None, scan_date=scan_date, version=None, branch_tag=None, build_id=None,
                    commit_hash=None, push_to_jira=None, close_old_findings=True, group_by=None, api_scan_configuration=None)
        self.assertEqual(1, len_new_findings)
        # Dedupe is off and close old findings does not close old findings if they are the same finding.
        # If this behaviour changes, or dedupe is on, the number of closed findings will be 4
        self.assertEqual(8, len_closed_findings)

    def test_close_old_same_product_scan(self):
        scan = get_unit_tests_path() + "/scans/acunetix/many_findings.xml"
        scan_type = "Acunetix Scan"

        user, _ = User.objects.get_or_create(username="admin")
        user_reporter, _ = User.objects.get_or_create(username="user_reporter")

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
        importer = Importer()
        scan_date = None
        environment, _ = Development_Environment.objects.get_or_create(name="Development")
        # Import first test
        test, len_new_findings, len_closed_findings, _ = importer.import_scan(scan, scan_type, engagement1, lead=None, environment=environment,
                    active=True, verified=False, tags=None, minimum_severity=None,
                    user=user, endpoints_to_add=None, scan_date=scan_date, version=None, branch_tag=None, build_id=None,
                    commit_hash=None, push_to_jira=None, close_old_findings=False, close_old_findings_product_scope=True, group_by=None, api_scan_configuration=None)

        self.assertEqual(4, len_new_findings)
        self.assertEqual(0, len_closed_findings)
        # Import same test, should close no findings
        test, len_new_findings, len_closed_findings, _ = importer.import_scan(scan, scan_type, engagement2, lead=None, environment=environment,
                    active=True, verified=False, tags=None, minimum_severity=None,
                    user=user, endpoints_to_add=None, scan_date=scan_date, version=None, branch_tag=None, build_id=None,
                    commit_hash=None, push_to_jira=None, close_old_findings=True, close_old_findings_product_scope=True, group_by=None, api_scan_configuration=None)
        self.assertEqual(4, len_new_findings)
        self.assertEqual(0, len_closed_findings)
        # Import test with only one finding. Remaining findings should close
        scan = open(get_unit_tests_path() + "/scans/acunetix/one_finding.xml")
        test, len_new_findings, len_closed_findings, _ = importer.import_scan(scan, scan_type, engagement3, lead=None, environment=environment,
                    active=True, verified=False, tags=None, minimum_severity=None,
                    user=user, endpoints_to_add=None, scan_date=scan_date, version=None, branch_tag=None, build_id=None,
                    commit_hash=None, push_to_jira=None, close_old_findings=True, close_old_findings_product_scope=True, group_by=None, api_scan_configuration=None)
        self.assertEqual(1, len_new_findings)
        # Dedupe is off, and close old findings does not close old findings if they are the same finding.
        # If this behaviour changes, or dedupe is on, the number of closed findings will be 4
        self.assertEqual(8, len_closed_findings)
