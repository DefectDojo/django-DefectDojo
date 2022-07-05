from dojo.models import Test
from dojo.tools.fortify.parser import FortifyParser

from ..dojo_test_case import DojoTestCase, get_unit_tests_path


class TestFortifyParser(DojoTestCase):
    def test_fortify_many_findings(self):
        testfile = get_unit_tests_path() + "/scans/fortify/fortify_many_findings.xml"
        parser = FortifyParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(324, len(findings))
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("Poor Logging Practice: Use of a System Output Stream - XXE.java: 81", finding.title)
            self.assertEqual("Low", finding.severity)
            self.assertEqual("src/main/java/org/joychou/controller/XXE.java", finding.file_path)
            self.assertEqual(81, finding.line)

    def test_fortify_few_findings(self):
        testfile = get_unit_tests_path() + "/scans/fortify/fortify_few_findings.xml"
        parser = FortifyParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(2, len(findings))
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("Privilege Management: Unnecessary Permission - AndroidManifest.xml: 11", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual("app/build/intermediates/bundle_manifest/developDebug/processDevelopDebugManifest/bundle-manifest/AndroidManifest.xml", finding.file_path)
            self.assertEqual(11, finding.line)
            self.assertEqual('53C25D2FC6950554F16D3CEF9E41EF6F', finding.unique_id_from_tool)

    def test_fortify_few_findings_count_chart(self):
        testfile = get_unit_tests_path() + "/scans/fortify/fortify_few_findings_count_chart.xml"
        parser = FortifyParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(3, len(findings))
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("Privilege Management: Unnecessary Permission - AndroidManifest.xml: 11", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual("app/build/intermediates/bundle_manifest/developDebug/processDevelopDebugManifest/bundle-manifest/AndroidManifest.xml", finding.file_path)
            self.assertEqual(11, finding.line)
            self.assertEqual('53C25D2FC6950554F16D3CEF9E41EF6F', finding.unique_id_from_tool)

    def test_fortify_issue6260(self):
        testfile = get_unit_tests_path() + "/scans/fortify/issue6260.xml"
        parser = FortifyParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(16, len(findings))
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("Command Injection - command.java: 40", finding.title)
            self.assertEqual("Low", finding.severity)
            self.assertEqual("src/main/java/command.java", finding.file_path)
            self.assertEqual(40, finding.line)
            self.assertEqual('7A2F1C728BDDBB17C7CB31CEDF5D8F85', finding.unique_id_from_tool)
