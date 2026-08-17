from dojo.models import Test
from dojo.tools.noir.parser import NoirParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestNoirParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("noir") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = NoirParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("noir") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = NoirParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("POST /api/login", finding.title)
            # An untagged endpoint is plain attack-surface inventory.
            self.assertEqual("Info", finding.severity)
            self.assertEqual("POST /api/login", finding.vuln_id_from_tool)
            self.assertEqual("app/app.py", finding.file_path)
            self.assertIn("**Technology:** python_flask", finding.description)
            self.assertIn("**Parameters:** username (form)", finding.description)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

    def test_a_tagged_endpoint_is_raised_above_inventory(self):
        with (get_unit_tests_scans_path("noir") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = NoirParser().get_findings(testfile, Test())
            self.assertEqual(3, len(findings))

            with self.subTest("only the admin endpoint carries a tag, so only it is Low"):
                low = [f for f in findings if f.severity == "Low"]
                self.assertEqual(1, len(low))
                self.assertEqual("DELETE /admin/delete", low[0].title)
                self.assertIn("**Tag `admin`:**", low[0].description)

            with self.subTest("the rest are informational inventory"):
                self.assertEqual(2, len([f for f in findings if f.severity == "Info"]))

            with self.subTest("every endpoint is anchored to its source location"):
                for finding in findings:
                    self.assertEqual("app/app.py", finding.file_path)
                    self.assertIsNotNone(finding.line)
