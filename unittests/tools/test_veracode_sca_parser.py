import datetime

from ..dojo_test_case import DojoTestCase
from dojo.tools.veracode_sca.parser import VeracodeScaParser
from dojo.models import Test

from dateutil.tz import UTC


class TestVeracodeScaScannerParser(DojoTestCase):

    def test_parse_csv(self):
        testfile = open("unittests/scans/veracode_sca/veracode_sca.csv")
        parser = VeracodeScaParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(3, len(findings))

        finding = findings[0]
        self.assertEqual("Medium", finding.severity)
        self.assertTrue(finding.active)
        self.assertFalse(finding.is_mitigated)
        self.assertEqual("aws-java-sdk-s3", finding.component_name)
        self.assertEqual("1.11.951", finding.component_version)
        self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2022-31159", finding.unsaved_vulnerability_ids[0])
        self.assertEqual(6.4, finding.cvssv3_score)
        self.assertEqual("127637430", finding.unique_id_from_tool)
        self.assertEqual(datetime.datetime(2022, 7, 7, 9, 15, 0), finding.date)

        finding = findings[1]
        self.assertEqual("Medium", finding.severity)
        self.assertTrue(finding.active)
        self.assertFalse(finding.is_mitigated)
        self.assertEqual("spring-cloud-function-context", finding.component_name)
        self.assertEqual("3.2.5", finding.component_version)
        self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2022-22979", finding.unsaved_vulnerability_ids[0])
        self.assertEqual(5, finding.cvssv3_score)
        self.assertEqual("122648496", finding.unique_id_from_tool)
        self.assertEqual(datetime.datetime(2022, 6, 14, 11, 34, 0), finding.date)

        finding = findings[2]
        self.assertEqual("High", finding.severity)
        self.assertFalse(finding.active)
        self.assertTrue(finding.is_mitigated)
        self.assertEqual("commons-configuration2", finding.component_name)
        self.assertEqual("2.1.1", finding.component_version)
        self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2022-33980", finding.unsaved_vulnerability_ids[0])
        self.assertEqual(7.5, finding.cvssv3_score)
        self.assertEqual("126041205", finding.unique_id_from_tool)
        self.assertEqual(datetime.datetime(2022, 7, 2, 23, 19, 0), finding.date)

    def test_parse_json(self):
        testfile = open("unittests/scans/veracode_sca/veracode_sca.json")
        parser = VeracodeScaParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("High", finding.severity)
        self.assertTrue(finding.active)
        self.assertFalse(finding.is_mitigated)
        self.assertEqual("avatica-core", finding.component_name)
        self.assertEqual("1.11.0", finding.component_version)
        self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2022-36364", finding.unsaved_vulnerability_ids[0])
        self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", finding.cvssv3)
        self.assertEqual(665, finding.cwe)
        self.assertEqual("ddcc6e1b-3ed9-45c8-b77a-ead759fb5e2c", finding.unique_id_from_tool)
        self.assertEqual(datetime.datetime(2022, 7, 29, 5, 13, 0, 924000).astimezone(UTC), finding.date)

    def test_parse_json_fixed(self):
        testfile = open("unittests/scans/veracode_sca/veracode_sca_fixed.json")
        parser = VeracodeScaParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Medium", finding.severity)
        self.assertFalse(finding.active)
        self.assertTrue(finding.is_mitigated)
        self.assertEqual("aws-java-sdk-s3", finding.component_name)
        self.assertEqual("1.11.951", finding.component_version)
        self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2022-31159", finding.unsaved_vulnerability_ids[0])
        self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", finding.cvssv3)
        self.assertEqual(22, finding.cwe)
