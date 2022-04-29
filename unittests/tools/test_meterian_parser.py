from ..dojo_test_case import DojoTestCase
from dojo.models import Test
from dojo.tools.meterian.parser import MeterianParser


class TestMeterianParser(DojoTestCase):

    def test_meterianParser_invalid_security_report_raise_ValueError_exception(self):
        with self.assertRaises(ValueError):
            testfile = open("unittests/scans/meterian/report_invalid.json")
            parser = MeterianParser()
            findings = parser.get_findings(testfile, Test())

    def test_meterianParser_report_has_no_finding(self):
        testfile = open("unittests/scans/meterian/report_no_vulns.json")

        parser = MeterianParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()

        self.assertEqual(0, len(findings))

    def test_meterianParser_report_has_one_findings(self):
        testfile = open("unittests/scans/meterian/report_one_vuln.json")

        parser = MeterianParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()

        self.assertEqual(1, len(findings))

    def test_meterianParser_report_has_many_findings(self):
        testfile = open("unittests/scans/meterian/report_many_vulns.json")

        parser = MeterianParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()

        self.assertEqual(20, len(findings))

    def test_meterianParser_finding_has_fields(self):
        testfile = open("unittests/scans/meterian/report_one_vuln.json")

        parser = MeterianParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()

        finding = findings[0]
        self.assertEqual(1, len(findings))
        self.assertEqual("date-and-time:0.6.3", finding.title)
        self.assertEqual("2021-06-02", finding.date)
        self.assertEqual("High", finding.severity)
        self.assertEqual("Issue severity of: **High** from a base " +
            "CVSS score of: **7.5**", finding.severity_justification)
        self.assertEqual("date-and-time is an npm package for manipulating " +
            "date and time. In date-and-time before version 0.14.2, there a regular " +
            "expression involved in parsing which can be exploited to to cause a denial " +
            "of service. This is fixed in version 0.14.2.", finding.description)
        self.assertEqual("7be36211-b569-30c0-8851-26b4bb8740ca", finding.unique_id_from_tool)
        self.assertEqual("CVE-2020-26289", finding.cve)
        self.assertEqual(400, finding.cwe)
        self.assertTrue(finding.mitigation.startswith("## Remediation"))
        self.assertTrue("Upgrade date-and-time to version 0.14.2 or higher." in finding.mitigation)
        self.assertTrue("https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-26289" in finding.references, "found " + finding.references)
        self.assertTrue("https://nvd.nist.gov/vuln/detail/CVE-2020-26289" in finding.references, "found " + finding.references)
        self.assertTrue("https://www.npmjs.com/package/date-and-time" in finding.references, "found " + finding.references)
        self.assertTrue("https://github.com/knowledgecode/date-and-time/security/advisories/GHSA-r92x-f52r-x54g" in finding.references, "found " + finding.references)
        self.assertTrue("https://github.com/knowledgecode/date-and-time/commit/9e4b501eacddccc8b1f559fb414f48472ee17c2a" in finding.references, "found " + finding.references)
        self.assertTrue("Manifest file", finding.file_path)
        self.assertEqual(["nodejs"], finding.tags)

    def test_meterianParser_finding_has_no_remediation(self):
        testfile = open("unittests/scans/meterian/report_one_vuln_no_remediation.json")

        parser = MeterianParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()

        finding = findings[0]
        self.assertTrue(finding.mitigation.startswith("We were not able to provide a safe version for this library."))
        self.assertTrue("You should consider replacing this component as it could be an " +
            "issue for the safety of your application." in finding.mitigation)

    def test_meterianParser_dual_language_report_has_two_findins(self):
        testfile = open("unittests/scans/meterian/report_multi_language.json")

        parser = MeterianParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()

        self.assertEqual(2, len(findings))
        self.assertIn("nodejs", findings[0].tags)
        self.assertIn("ruby", findings[1].tags)
