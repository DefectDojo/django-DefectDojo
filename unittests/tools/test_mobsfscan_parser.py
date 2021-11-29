from ..dojo_test_case import DojoTestCase
from dojo.tools.mobsfscan.parser import MobsfscanParser
from dojo.models import Test


class TestMobsfscanParser(DojoTestCase):

    def test_parse_no_findings(self):
        testfile = open("unittests/scans/mobsfscan/no_findings.json")
        parser = MobsfscanParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_parse_many_findings(self):
        testfile = open("unittests/scans/mobsfscan/many_findings.json")
        parser = MobsfscanParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(7, len(findings))

        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("android_certificate_transparency", finding.title)
            self.assertEqual("Low", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertEqual(295, finding.cwe)
            self.assertIsNotNone(finding.references)

        with self.subTest(i=1):
            finding = findings[1]
            self.assertEqual("android_kotlin_hardcoded", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertEqual(798, finding.cwe)
            self.assertIsNotNone(finding.references)
            self.assertEqual("app/src/main/java/com/routes/domain/analytics/event/Signatures.kt", finding.file_path)
            self.assertEqual(10, finding.line)

        with self.subTest(i=2):
            finding = findings[2]
            self.assertEqual("android_prevent_screenshot", finding.title)
            self.assertEqual("Low", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertEqual(200, finding.cwe)
            self.assertIsNotNone(finding.references)

        with self.subTest(i=3):
            finding = findings[3]
            self.assertEqual("android_root_detection", finding.title)
            self.assertEqual("Low", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertEqual(919, finding.cwe)
            self.assertIsNotNone(finding.references)

        with self.subTest(i=4):
            finding = findings[4]
            self.assertEqual("android_safetynet", finding.title)
            self.assertEqual("Low", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertEqual(353, finding.cwe)
            self.assertIsNotNone(finding.references)

        with self.subTest(i=5):
            finding = findings[5]
            self.assertEqual("android_ssl_pinning", finding.title)
            self.assertEqual("Low", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertEqual(295, finding.cwe)
            self.assertIsNotNone(finding.references)

        with self.subTest(i=6):
            finding = findings[6]
            self.assertEqual("android_tapjacking", finding.title)
            self.assertEqual("Low", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertEqual(200, finding.cwe)
            self.assertIsNotNone(finding.references)
