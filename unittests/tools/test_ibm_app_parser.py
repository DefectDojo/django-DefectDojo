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
        finding = findings[0]
        self.assertEqual('Low', finding.severity)
        # FIXME manage CWE
        # self.assertEqual(79, finding.cwe)
        finding = findings[1]
        # FIXME fix Info/Informational drama for this parser
        self.assertEqual('Informational', finding.severity)
        # FIXME manage CWE
        # self.assertEqual(79, finding.cwe)
