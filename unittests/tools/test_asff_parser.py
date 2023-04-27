import datetime
import os.path

from dojo.models import Test
from dojo.tools.asff.parser import AsffParser

from ..dojo_test_case import DojoTestCase, get_unit_tests_path


def sample_path(file_name):
    return os.path.join("/scans/asff", file_name)


class TestAsffParser(DojoTestCase):
    def test_get_severity(self):
        """To designate severity, the finding must have either the Label or Normalized field populated.
        Label is the preferred attribute. If neither attribute is populated, then the finding is not valid."""
        parser = AsffParser()

        with self.subTest(type="invalid"):
            self.assertEqual(None, parser.get_severity({"Seveiryt": 3}))

        with self.subTest(type="label low"):
            self.assertEqual("Low", parser.get_severity({"Label": "LOW", "Normalized": 40, "Product": 2}))
        with self.subTest(type="label medium"):
            self.assertEqual("Medium", parser.get_severity({"Label": "MEDIUM", "Normalized": 50, "Product": 5}))
        with self.subTest(type="label"):
            self.assertEqual("Low", parser.get_severity({"Label": "LOW", "Normalized": 40, "Product": 2}))

        # 0 - INFORMATIONAL
        # 1–39 - LOW
        # 40–69 - MEDIUM
        # 70–89 - HIGH
        # 90–100 - CRITICAL
        with self.subTest(type="normalized low"):
            self.assertEqual("Low", parser.get_severity({"Normalized": 20, "Product": 2}))
        with self.subTest(type="normalized medium"):
            self.assertEqual("Medium", parser.get_severity({"Normalized": 50, "Product": 5}))
        with self.subTest(type="normalized high"):
            self.assertEqual("High", parser.get_severity({"Normalized": 80, "Product": 2}))
        with self.subTest(type="normalizedinfo"):
            self.assertEqual("Info", parser.get_severity({"Normalized": 0, "Product": 2}))

    def test_prowler_finding(self):
        with open(get_unit_tests_path() + sample_path("prowler-output.asff.json")) as test_file:
            parser = AsffParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(731, len(findings))
            for finding in findings:
                self.common_check_finding(finding)
            with self.subTest(i=0):
                finding = findings[0]
                self.assertIn("Check if IAM Access Analyzer is enabled", finding.title)
                self.assertIn("IAM Access Analyzer in account 123456789012 is not enabled", finding.description)
                self.assertEqual(datetime.date(2023, 3, 18), finding.date.date())
                self.assertEqual("Low", finding.severity)
                self.assertTrue(finding.active)
                self.assertEqual(
                    "prowler-accessanalyzer_enabled-123456789012-ap-northeast-1-fb33278bd", finding.unique_id_from_tool
                )

            with self.subTest(i=300):
                finding = findings[300]
                self.assertIn(
                    "Ensure no security groups allow ingress from 0.0.0.0/0 or ::/0 to Elasticsearch/Kibana ports",
                    finding.title,
                )
                self.assertIn(
                    "Security group default (sg-3965844c) has not Elasticsearch/Kibana ports 9200, 9300 and 5601 open to the Internet",
                    finding.description,
                )
                self.assertEqual(datetime.date(2023, 3, 18), finding.date.date())
                self.assertEqual("High", finding.severity)
                self.assertTrue(finding.active)
                self.assertEqual(
                    "prowler-ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_elasticsearch_kibana_9200_9300_5601-123456789012-sa-east-1-49c27aa6d",
                    finding.unique_id_from_tool,
                )

            with self.subTest(i=700):
                finding = findings[700]
                self.assertIn("Check if Security Hub is enabled and its standard subscriptions", finding.title)
                self.assertIn("Security Hub is not enabled", finding.description)
                self.assertEqual(datetime.date(2023, 3, 18), finding.date.date())
                self.assertEqual("Medium", finding.severity)
                self.assertTrue(finding.active)
                self.assertEqual(
                    "prowler-securityhub_enabled-123456789012-ap-southeast-1-d053c2dfc", finding.unique_id_from_tool
                )

    def test_guardduty_finding(self):
        with open(
            get_unit_tests_path()
            + sample_path("guardduty/Unusual Behaviors-User-Persistence IAMUser-NetworkPermissions.json")
        ) as test_file:
            parser = AsffParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(1, len(findings))
            for finding in findings:
                self.common_check_finding(finding)
            with self.subTest(i=0):
                finding = findings[0]
                self.assertIn("Unusual changes to network permissions by GeneratedFindingUserName", finding.title)
                self.assertIn(
                    "APIs commonly used to change the network access permissions for security groups, routes and ACLs, was invoked by IAM principal GeneratedFindingUserName",
                    finding.description,
                )
                self.assertEqual(datetime.date(2020, 11, 11), finding.date.date())
                self.assertEqual("Medium", finding.severity)
                self.assertTrue(finding.active)
                self.assertEqual(
                    "arn:aws:guardduty:eu-west-1:123456789012:detector/cab6a714deb3b739eaddacbdfd5ef2f2/finding/d6badb90e557d4bd811488a53ca89895",
                    finding.unique_id_from_tool,
                )
