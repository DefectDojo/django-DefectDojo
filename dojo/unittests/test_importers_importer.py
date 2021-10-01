import datetime

from django.test import TestCase
from django.utils import timezone
from dojo.importers.importer.importer import DojoDefaultImporter as Importer
from dojo.models import Engagement, Product, Product_Type, User
from dojo.tools.factory import get_parser
from dojo.tools.sarif.parser import SarifParser
from dojo.tools.gitlab_sast.parser import GitlabSastParser


class TestDojoDefaultImporter(TestCase):
    def test_parse_findings(self):
        scan_type = "Acunetix Scan"
        scan = open("dojo/unittests/scans/acunetix/one_finding.xml")

        user, created = User.objects.get_or_create(username="admin")

        product_type, created = Product_Type.objects.get_or_create(name="test")
        if created:
            product_type.save()
        product, created = Product.objects.get_or_create(
            name="TestDojoDefaultImporter",
            prod_type=product_type,
        )
        if created:
            product.save()

        engagement_name = "Test Create Engagement"
        engagement, created = Engagement.objects.get_or_create(
            name=engagement_name,
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        if created:
            engagement.save()
        lead = None
        environment = None

        # boot
        importer = Importer()

        # create the test
        # by defaut test_type == scan_type
        test = importer.create_test(scan_type, scan_type, engagement, lead, environment)

        # parse the findings
        parser = get_parser(scan_type)
        parsed_findings = parser.get_findings(scan, test)

        # process
        minimum_severity = "Info"
        active = True
        verified = True
        new_findings = importer.process_parsed_findings(
            test,
            parsed_findings,
            scan_type,
            user,
            active,
            verified,
            minimum_severity=minimum_severity,
        )

        for finding in new_findings:
            self.assertIn(finding.numerical_severity, ["S0", "S1", "S2", "S3", "S4"])

    def test_import_scan(self):
        scan = open("dojo/unittests/scans/sarif/spotbugs.sarif")
        scan_type = SarifParser().get_scan_types()[0]  # SARIF format implement the new method

        user, _ = User.objects.get_or_create(username="admin")
        user_reporter, _ = User.objects.get_or_create(username="user_reporter")

        product_type, _ = Product_Type.objects.get_or_create(name="test2")
        product, _ = Product.objects.get_or_create(
            name="TestDojoDefaultImporter2",
            prod_type=product_type,
        )

        engagement, _ = Engagement.objects.get_or_create(
            name="Test Create Engagement2",
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )

        importer = Importer()
        scan_date = timezone.make_aware(datetime.datetime(2021, 9, 1), timezone.get_default_timezone())
        test, len_new_findings, len_closed_findings = importer.import_scan(scan, scan_type, engagement, lead=None, environment=None, active=True, verified=True, tags=None, minimum_severity=None,
                    user=user, endpoints_to_add=None, scan_date=scan_date, version=None, branch_tag=None, build_id=None,
                    commit_hash=None, push_to_jira=None, close_old_findings=False, group_by=None, sonarqube_config=None,
                    cobaltio_config=None)

        self.assertEqual(f"SpotBugs Scan ({scan_type})", test.test_type.name)
        self.assertEqual(56, len_new_findings)
        self.assertEqual(0, len_closed_findings)

    def test_import_scan_without_test_scan_type(self):
        # GitLabSastParser implements get_tests but report has no scanner name
        scan = open("dojo/unittests/scans/gitlab_sast/gl-sast-report-1-vuln.json")
        scan_type = GitlabSastParser().get_scan_types()[0]

        user, _ = User.objects.get_or_create(username="admin")
        user_reporter, _ = User.objects.get_or_create(username="user_reporter")

        product_type, _ = Product_Type.objects.get_or_create(name="test2")
        product, _ = Product.objects.get_or_create(
            name="TestDojoDefaultImporter2",
            prod_type=product_type,
        )

        engagement, _ = Engagement.objects.get_or_create(
            name="Test Create Engagement2",
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )

        importer = Importer()
        scan_date = timezone.make_aware(datetime.datetime(2021, 9, 1), timezone.get_default_timezone())
        test, len_new_findings, len_closed_findings = importer.import_scan(scan, scan_type, engagement, lead=None, environment=None, active=True, verified=True, tags=None, minimum_severity=None,
                    user=user, endpoints_to_add=None, scan_date=scan_date, version=None, branch_tag=None, build_id=None,
                    commit_hash=None, push_to_jira=None, close_old_findings=False, group_by=None, sonarqube_config=None,
                    cobaltio_config=None)

        self.assertEqual("GitLab SAST Report", test.test_type.name)
        self.assertEqual(1, len_new_findings)
        self.assertEqual(0, len_closed_findings)
