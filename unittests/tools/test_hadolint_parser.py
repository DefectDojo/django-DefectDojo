from ..dojo_test_case import DojoTestCase
from dojo.models import Test
from dojo.tools.hadolint.parser import HadolintParser


class TesthadolintParser(DojoTestCase):

    def test_parse_file_with_one_dockerfile(self):
        testfile = open("unittests/scans/hadolint/one_dockerfile.json")
        parser = HadolintParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(4, len(findings))
        finding = list(findings)[0]
        self.assertEqual(finding.line, 9)
        self.assertEqual(finding.file_path, "django-DefectDojo\\Dockerfile.django")

    def test_parse_file_with_many_dockerfile(self):
        testfile = open("unittests/scans/hadolint/many_dockerfile.json")
        parser = HadolintParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(12, len(findings))
