from dojo.models import Test
from dojo.tools.kubesec.parser import KubesecParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestKubesecParser(DojoTestCase):

    def test_parse_no_findings(self):
        """Rules in the passed bucket are already satisfied and are not findings."""
        with (get_unit_tests_scans_path("kubesec") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = KubesecParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("kubesec") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = KubesecParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("High", finding.severity)
            self.assertEqual("Privileged", finding.vuln_id_from_tool)
            self.assertEqual("Deployment/example-api.example-ns", finding.component_name)
            self.assertEqual("manifests/deployment.yaml", finding.file_path)
            self.assertIn("Privileged containers can allow almost completely unrestricted host access", finding.description)
            self.assertIn("**Bucket:** critical", finding.description)
            self.assertIn("**Points:** -30", finding.description)
            self.assertIn("**Object score:** -30", finding.description)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

    def test_parse_many_findings(self):
        """Two scanned manifests, one failing and one passing, in a single report."""
        with (get_unit_tests_scans_path("kubesec") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = KubesecParser().get_findings(testfile, Test())
            self.assertEqual(22, len(findings))

            with self.subTest("critical is High, advise is Low"):
                self.assertEqual(1, len([f for f in findings if f.severity == "High"]))
                self.assertEqual(21, len([f for f in findings if f.severity == "Low"]))

            with self.subTest("findings are attributed to the manifest they came from"):
                self.assertEqual(
                    {"manifests/deployment.yaml", "manifests/dep2.yaml"},
                    {f.file_path for f in findings},
                )

            with self.subTest("the passing manifest contributes no critical finding"):
                critical = [f for f in findings if f.severity == "High"]
                self.assertEqual("manifests/deployment.yaml", critical[0].file_path)

            with self.subTest("every finding names the rule that raised it"):
                for finding in findings:
                    self.assertTrue(finding.vuln_id_from_tool)
                    self.assertIn(":", finding.title)
