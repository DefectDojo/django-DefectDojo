from ..dojo_test_case import DojoTestCase
from dojo.models import Test
from dojo.tools.ibm_app.parser import IbmAppParser


class TestIbmAppParser(DojoTestCase):

    def test_parse_file(self):
        testfile = open("unittests/scans/ibm_app/testfire.xml")
        parser = IbmAppParser()
        findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        testfile.close()
        self.assertEqual(27, len(findings))

        finding = findings[15]
        self.assertEqual('High', finding.severity)
        self.assertEqual(79, finding.cwe)
        self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
        self.assertEqual('CVE-2022-00001', finding.unsaved_vulnerability_ids[0])

        finding = findings[1]
        self.assertEqual('Info', finding.severity)
