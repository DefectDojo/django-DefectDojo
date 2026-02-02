
from dojo.models import Test
from dojo.tools.cloudflare_insights.parser import CloudflareInsightsParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestCloudflareInsightsParser(DojoTestCase):

    def test_cloudflare_insights_parser_with_one_finding(self):
        with (get_unit_tests_scans_path("cloudflare_insights") / "one_finding.csv").open(encoding="utf-8") as testfile:
            parser = CloudflareInsightsParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Exposed infrastructure: domain.com", finding.title)
            self.assertEqual("Medium", finding.severity)

    def test_cloudflare_insights_parser_with_many_findings(self):
        with (get_unit_tests_scans_path("cloudflare_insights") / "many_findings.csv").open(encoding="utf-8") as testfile:
            parser = CloudflareInsightsParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(14, len(findings))
            finding = findings[0]
            self.assertEqual("Exposed infrastructure: domain1.com", finding.title)
            self.assertEqual("Medium", finding.severity)

    def test_cloudflare_insights_parser_with_one_finding_json(self):
        with (get_unit_tests_scans_path("cloudflare_insights") / "one_finding.json").open(encoding="utf-8") as testfile:
            parser = CloudflareInsightsParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("configuration_suggestion: domain.com", finding.title)
            self.assertEqual("Low", finding.severity)

    def test_cloudflare_insights_parser_with_many_findings_json(self):
        with (get_unit_tests_scans_path("cloudflare_insights") / "many_findings.json").open(encoding="utf-8") as testfile:
            parser = CloudflareInsightsParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))
            finding = findings[0]
            self.assertEqual("configuration_suggestion: test.de", finding.title)
            self.assertEqual("Low", finding.severity)
