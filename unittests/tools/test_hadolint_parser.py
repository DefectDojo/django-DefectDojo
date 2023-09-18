from ..dojo_test_case import DojoParserTestCase
from dojo.models import Test
from dojo.tools.hadolint.parser import HadolintParser


class TesthadolintParser(DojoParserTestCase):

    parser = HadolintParser()

    def test_parse_file_with_one_dockerfile(self):
        testfile = open("unittests/scans/hadolint/one_dockerfile.json")
        findings = self.parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(4, len(findings))
        finding = list(findings)[0]
        self.assertEqual(finding.line, 9)
        self.assertEqual(finding.file_path, "django-DefectDojo\\Dockerfile.django")

    def test_parse_file_with_many_dockerfile(self):
        testfile = open("unittests/scans/hadolint/many_dockerfile.json")
        findings = self.parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(12, len(findings))
