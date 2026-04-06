from datetime import date, datetime

from dateutil.tz import tzoffset

from dojo.models import Test
from dojo.tools.aws_inspector2.parser import AWSInspector2Parser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestAWSInspector2Parser(DojoTestCase):

    def test_aws_inspector2_parser_with_no_vuln_has_no_findings(self):
        with (get_unit_tests_scans_path("aws_inspector2") / "aws_inspector2_zero_vul.json").open(encoding="utf-8") as testfile:
            parser = AWSInspector2Parser()
            findings = parser.get_findings(testfile, Test())
            testfile.close()
            self.assertEqual(0, len(findings))

    def test_aws_inspector2_parser_with_one_vuln_has_one_findings(self):
        with (get_unit_tests_scans_path("aws_inspector2") / "aws_inspector2_one_vul.json").open(encoding="utf-8") as testfile:
            parser = AWSInspector2Parser()
            findings = parser.get_findings(testfile, Test())
            testfile.close()
            self.validate_locations(findings)
            self.assertEqual(1, len(findings))
            self.assertEqual("CVE-2021-3744 - linux", findings[0].title)
            self.assertEqual("Medium", findings[0].severity)
            self.assertEqual("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", findings[0].cvssv3)
            self.assertEqual(5.5, findings[0].cvssv3_score)

    def test_aws_inspector2_parser_with_many_vuln_has_many_findings(self):
        with (get_unit_tests_scans_path("aws_inspector2") / "aws_inspector2_many_vul.json").open(encoding="utf-8") as testfile:
            parser = AWSInspector2Parser()
            findings = parser.get_findings(testfile, Test())
            testfile.close()
            self.validate_locations(findings)
            self.assertEqual(8, len(findings))
            self.assertEqual(True, findings[0].is_mitigated)
            # 2024-06-14T04:03:53.051000+02:00
            self.assertEqual(datetime(2024, 6, 14, 4, 3, 53, 51000, tzinfo=tzoffset(None, 7200)), findings[0].mitigated)
            self.assertEqual("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", findings[0].cvssv3)
            self.assertEqual(5.5, findings[0].cvssv3_score)

    def test_aws_inspector2_package_vuln_metadata_fields(self):
        """Verify that packageVulnerabilityDetails metadata fields are populated on findings."""
        with (get_unit_tests_scans_path("aws_inspector2") / "aws_inspector2_package_vuln_metadata.json").open(encoding="utf-8") as testfile:
            parser = AWSInspector2Parser()
            findings = parser.get_findings(testfile, Test())
        self.assertEqual(28, len(findings))
        # Use the first finding (CVE-2025-58187 - go/stdlib) for field assertions
        finding = findings[0]
        # component_name and component_version from vulnerablePackages[0]
        self.assertEqual("go/stdlib", finding.component_name)
        self.assertEqual("1.24.4", finding.component_version)
        # file_path from vulnerablePackages[0].filePath
        self.assertEqual("extensions/collector", finding.file_path)
        # references from referenceUrls joined with newlines
        self.assertEqual(
            "https://nvd.nist.gov/vuln/detail/CVE-2025-58187\nhttps://groups.google.com/g/golang-announce/c/4Emdl2iQ_bI",
            finding.references,
        )
        # publish_date parsed from vendorCreatedAt
        self.assertEqual(date(2025, 10, 30), finding.publish_date)
        # cvssv3_score from packageVulnerabilityDetails.cvss[].baseScore (v3.x entry)
        self.assertEqual(7.5, finding.cvssv3_score)
        # vulnerability ID still populated
        self.assertIn("CVE-2025-58187", finding.unsaved_vulnerability_ids)
        # LocationData.dependency populated for package vulnerability findings
        dependency_locations = [loc for loc in finding.unsaved_locations if loc.type == "dependency"]
        self.assertEqual(1, len(dependency_locations))
        self.assertEqual("go/stdlib", dependency_locations[0].data["name"])
        self.assertEqual("1.24.4", dependency_locations[0].data["version"])
        self.assertEqual("extensions/collector", dependency_locations[0].data["file_path"])

    def test_aws_inspector2_parser_empty_with_error(self):
        with self.assertRaises(TypeError) as context, \
          (get_unit_tests_scans_path("aws_inspector2") / "empty_with_error.json").open(encoding="utf-8") as testfile:
            parser = AWSInspector2Parser()
            parser.get_findings(testfile, Test())
            testfile.close()
            self.assertTrue(
                "Incorrect Inspector2 report format" in str(context.exception),
            )
