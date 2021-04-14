from django.test import TestCase
from django.utils import timezone
from dojo.importers import utils as importer_utils
from dojo.importers.importer.importer import DojoDefaultImporter as Importer
from dojo.models import Engagement, Product, Product_Type, User


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
        test = importer.create_test(scan_type, engagement, lead, environment)

        # parse the findings
        active = False
        verified = False
        parsed_findings = importer_utils.parse_findings(
            scan, test, active, verified, scan_type
        )

        # process
        minimum_severity = "Info"
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
