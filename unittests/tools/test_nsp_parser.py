from ..dojo_test_case import DojoTestCase
from dojo.tools.nsp.parser import NspParser
from dojo.models import Test


class TestNspParser(DojoTestCase):
    def test_parse_none(self):
        parser = NspParser()
        with open("unittests/scans/nsp/none.json") as test_file:
            findings = parser.get_findings(test_file, Test())
        self.assertEqual(0, len(findings))

    def test_parse_ok(self):
        parser = NspParser()
        with open("unittests/scans/nsp/scan.json") as test_file:
            findings = parser.get_findings(test_file, Test())
        self.assertEqual(9, len(findings))

        # Count each type of finding to check afterwards
        codeExec = 0
        dos = 0

        for finding in findings:
            if finding.title.startswith("Remote Code Execution"):
                self.assertEqual(findings[0].severity, "High")
                self.assertEqual(findings[0].references, "https://nodesecurity.io/advisories/521")
                codeExec += 1
            elif finding.title.startswith("Regular Expression Denial of Service"):
                self.assertEqual(findings[0].severity, "High")
                self.assertTrue(
                    finding.references == "https://nodesecurity.io/advisories/106" or
                    finding.references == "https://nodesecurity.io/advisories/526" or
                    finding.references == "https://nodesecurity.io/advisories/534" or
                    finding.references == "https://nodesecurity.io/advisories/535"
                )
                dos += 1
            else:
                self.fail("Unexpected NSP finding.")

        self.assertEqual(codeExec, 1)
        self.assertEqual(dos, 8)
