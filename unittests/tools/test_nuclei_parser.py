from ..dojo_test_case import DojoTestCase
from dojo.tools.nuclei.parser import NucleiParser
from dojo.models import Test


class TestNucleiParser(DojoTestCase):

    def test_parse_no_empty(self):
        testfile = open("unittests/scans/nuclei/empty.jsonl")
        parser = NucleiParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_no_findings(self):
        testfile = open("unittests/scans/nuclei/no_findings.json")
        parser = NucleiParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_many_findings(self):
        testfile = open("unittests/scans/nuclei/many_findings.json")
        parser = NucleiParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()

        self.assertEqual(7, len(findings))

        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("OpenSSH 5.3 Detection", finding.title)
            self.assertEqual("Low", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertIn("network", finding.unsaved_tags)
            self.assertIn("openssh", finding.unsaved_tags)
            self.assertIsNotNone(finding.references)
            self.assertEqual("nuclei-example.com", finding.unsaved_endpoints[0].host)
            self.assertEqual(22, finding.unsaved_endpoints[0].port)
            self.assertEqual("openssh5.3-detect", finding.vuln_id_from_tool)

        with self.subTest(i=1):
            finding = findings[1]
            self.assertEqual("nginx version detect", finding.title)
            self.assertEqual("Info", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertIsNone(finding.unsaved_tags)
            self.assertIsNone(finding.references)
            self.assertEqual(None, finding.unsaved_endpoints[0].path)
            self.assertEqual("nuclei-example.com", finding.unsaved_endpoints[0].host)
            self.assertEqual(443, finding.unsaved_endpoints[0].port)
            self.assertEqual("nginx-version", finding.vuln_id_from_tool)

        with self.subTest(i=2):
            finding = findings[2]
            self.assertEqual("phpMyAdmin setup page", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertIsNotNone(finding.references)
            self.assertIn("phpmyadmin", finding.unsaved_tags)
            self.assertEqual("phpmyadmin/setup/index.php", finding.unsaved_endpoints[0].path)
            self.assertEqual("nuclei-example.com", finding.unsaved_endpoints[0].host)
            self.assertEqual(443, finding.unsaved_endpoints[0].port)
            self.assertEqual("phpmyadmin-setup", finding.vuln_id_from_tool)

        with self.subTest(i=3):
            finding = findings[3]
            self.assertEqual("Wappalyzer Technology Detection", finding.title)
            self.assertEqual("Info", finding.severity)
            self.assertEqual(11, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertIsNone(finding.references)
            self.assertIsNone(finding.unsaved_tags)
            self.assertEqual("WebGoat", finding.unsaved_endpoints[0].path)
            self.assertEqual("127.0.0.1", finding.unsaved_endpoints[0].host)
            self.assertEqual(8080, finding.unsaved_endpoints[0].port)
            self.assertEqual("WebWolf", finding.unsaved_endpoints[1].path)
            self.assertEqual("127.0.0.1", finding.unsaved_endpoints[1].host)
            self.assertEqual(9090, finding.unsaved_endpoints[1].port)
            self.assertEqual(None, finding.unsaved_endpoints[2].path)
            self.assertEqual("nuclei-example.com", finding.unsaved_endpoints[2].host)
            self.assertEqual(443, finding.unsaved_endpoints[2].port)
            self.assertEqual("tech-detect", finding.vuln_id_from_tool)

        with self.subTest(i=4):
            finding = findings[4]
            self.assertEqual("WAF Detection", finding.title)
            self.assertEqual("Info", finding.severity)
            self.assertEqual(2, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertIsNone(finding.references)
            self.assertIsNone(finding.unsaved_tags)
            self.assertEqual(None, finding.unsaved_endpoints[0].path)
            self.assertEqual("nuclei-example.com", finding.unsaved_endpoints[0].host)
            self.assertEqual(443, finding.unsaved_endpoints[0].port)
            self.assertEqual("waf-detect", finding.vuln_id_from_tool)

        with self.subTest(i=5):
            finding = findings[5]
            self.assertEqual("phpMyAdmin Panel", finding.title)
            self.assertEqual("Info", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertIsNone(finding.references)
            self.assertIn("panel", finding.unsaved_tags)
            self.assertEqual("phpmyadmin/", finding.unsaved_endpoints[0].path)
            self.assertEqual("nuclei-example.com", finding.unsaved_endpoints[0].host)
            self.assertEqual(443, finding.unsaved_endpoints[0].port)
            self.assertEqual("phpmyadmin-panel", finding.vuln_id_from_tool)

        with self.subTest(i=6):
            finding = findings[6]
            self.assertEqual("MySQL DB with enabled native password", finding.title)
            self.assertEqual("Info", finding.severity)
            self.assertEqual(1, finding.nb_occurences)
            self.assertIsNotNone(finding.description)
            self.assertIsNone(finding.references)
            self.assertIn("network", finding.unsaved_tags)
            self.assertIn("mysql", finding.unsaved_tags)
            self.assertIn("bruteforce", finding.unsaved_tags)
            self.assertIn("db", finding.unsaved_tags)
            self.assertEqual(None, finding.unsaved_endpoints[0].path)
            self.assertEqual("nuclei-example.com", finding.unsaved_endpoints[0].host)
            self.assertEqual(3306, finding.unsaved_endpoints[0].port)
            self.assertEqual("mysql-native-password-bruteforce", finding.vuln_id_from_tool)
