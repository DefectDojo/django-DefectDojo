from ..dojo_test_case import DojoTestCase
from dojo.tools.popeye.parser import PopeyeParser
from dojo.models import Test


class TestPopeyeParser(DojoTestCase):

    def test_popeye_parser_with_no_vuln_has_no_findings(self):
        testfile = open("unittests/scans/popeye/popeye_zero_vul.json")
        parser = PopeyeParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_popeye_parser_with_one_warning_has_one_findings(self):
        testfile = open("unittests/scans/popeye/popeye_one_vul.json")
        parser = PopeyeParser()
        findings = parser.get_findings(testfile, Test())
        finding_title = "pods test-namespace/6cff44dc94-d92km [POP-106] No resources requests/limits defined"
        finding_description = "**Sanitizer** : pods" + "\n\n" + \
                            "**Resource** : test-namespace/6cff44dc94-d92km" + "\n\n" + \
                            "**Group** : test-group" + "\n\n" + \
                            "**Severity** : Warning" + "\n\n" + \
                            "**Message** : [POP-106] No resources requests/limits defined"
        testfile.close()
        self.assertEqual(1, len(findings))
        self.assertEqual("Low", findings[0].severity)
        self.assertEqual(finding_title, findings[0].title)
        self.assertEqual(finding_description, findings[0].description)

    def test_popeye_parser_with_many_vuln_has_many_findings(self):
        testfile = open("unittests/scans/popeye/popeye_many_vul.json")
        parser = PopeyeParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(229, len(findings))
