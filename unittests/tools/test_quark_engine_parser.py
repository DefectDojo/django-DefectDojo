from dojo.models import Test
from dojo.tools.quark_engine.parser import QuarkEngineParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestQuarkEngineParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("quark_engine") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = QuarkEngineParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("quark_engine") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = QuarkEngineParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Send Location via SMS", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual("sendLocation_SMS.json", finding.vuln_id_from_tool)
            self.assertEqual("14d9f1a92dd984d6040cc41ed06e273e.apk", finding.component_name)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

            with self.subTest("the behaviour's evidence reaches the description"):
                self.assertIn("**Confidence:** 100%", finding.description)
                self.assertIn("android.permission.SEND_SMS", finding.description)
                self.assertIn("Landroid/telephony/SmsManager;sendTextMessage", finding.description)
                self.assertIn("**Labels:** location, collection", finding.description)
                self.assertIn("**MD5:** 14d9f1a92dd984d6040cc41ed06e273e", finding.description)

    def test_parse_many_findings(self):
        with (get_unit_tests_scans_path("quark_engine") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = QuarkEngineParser().get_findings(testfile, Test())
            self.assertEqual(3, len(findings))

            with self.subTest("confidence drives severity"):
                by_rule = {f.vuln_id_from_tool: f for f in findings}
                self.assertEqual("High", by_rule["sendLocation_SMS.json"].severity)
                self.assertEqual("Medium", by_rule["readSensitiveData.json"].severity)
                self.assertEqual("Low", by_rule["openSocket.json"].severity)

            with self.subTest("every crime is attributed to the same APK"):
                for finding in findings:
                    self.assertEqual("14d9f1a92dd984d6040cc41ed06e273e.apk", finding.component_name)

    def test_confidence_parsing_is_tolerant(self):
        """Quark writes confidence as a percentage string; anything else scores zero."""
        parser = QuarkEngineParser()
        self.assertEqual(100, parser._confidence("100%"))
        self.assertEqual(80, parser._confidence(" 80% "))
        self.assertEqual(0, parser._confidence(None))
        self.assertEqual(0, parser._confidence("unknown"))
        self.assertEqual("Info", parser._severity(0))
