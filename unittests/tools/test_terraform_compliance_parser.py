from dojo.models import Test
from dojo.tools.terraform_compliance.parser import TerraformComplianceParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestTerraformComplianceParser(DojoTestCase):

    def test_parse_no_findings_junit(self):
        with (get_unit_tests_scans_path("terraform_compliance") / "no_findings.xml").open(encoding="utf-8") as testfile:
            findings = TerraformComplianceParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_no_findings_cucumber(self):
        with (get_unit_tests_scans_path("terraform_compliance") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = TerraformComplianceParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding_junit(self):
        with (get_unit_tests_scans_path("terraform_compliance") / "one_finding.xml").open(encoding="utf-8") as testfile:
            findings = TerraformComplianceParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(
                "Postgres servers must not use a public network",
                finding.vuln_id_from_tool,
            )

            with self.subTest("the junit report names the resource that failed"):
                self.assertEqual("azurerm_postgresql_server.example", finding.component_name)
                self.assertIn("azurerm_postgresql_server.example", finding.title)
                self.assertIn("**Resource:** azurerm_postgresql_server.example", finding.description)
                self.assertIn("**Property:** public_network_access_enabled", finding.description)

            with self.subTest("the failing step and the value found are recorded"):
                self.assertIn("**Failed step:** And its value must be false", finding.description)
                self.assertIn("It is set to True", finding.description)

    def test_parse_many_findings_junit(self):
        with (get_unit_tests_scans_path("terraform_compliance") / "many_findings.xml").open(encoding="utf-8") as testfile:
            findings = TerraformComplianceParser().get_findings(testfile, Test())
            self.assertEqual(3, len(findings))

            with self.subTest("one finding per failing scenario, not per failing step"):
                self.assertEqual(
                    {
                        "Postgres servers must not use a public network",
                        "Postgres servers must enforce a minimum TLS version",
                        "Postgres servers must have geo redundant backups",
                    },
                    {f.vuln_id_from_tool for f in findings},
                )

            with self.subTest("the passing scenario is not imported"):
                self.assertNotIn(
                    "Postgres servers must enforce SSL",
                    {f.vuln_id_from_tool for f in findings},
                )

            with self.subTest("every finding resolves the offending resource and property"):
                for finding in findings:
                    self.assertEqual("azurerm_postgresql_server.example", finding.component_name)
                    self.assertIn("**Property:**", finding.description)

    def test_parse_many_findings_cucumber(self):
        """The cucumber report identifies the failing scenario but carries no failure detail."""
        with (get_unit_tests_scans_path("terraform_compliance") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = TerraformComplianceParser().get_findings(testfile, Test())
            self.assertEqual(3, len(findings))

            with self.subTest("the missing detail is stated rather than left looking absent"):
                self.assertIn("Re-run with --junit-xml", findings[0].description)

            with self.subTest("the feature file and failing line are still located"):
                self.assertEqual("features/many.feature", findings[0].file_path)
                self.assertEqual({6, 11, 16}, {f.line for f in findings})

            with self.subTest("the scenario is still the unit of a finding"):
                self.assertEqual(
                    {
                        "Postgres servers must not use a public network",
                        "Postgres servers must enforce a minimum TLS version",
                        "Postgres servers must have geo redundant backups",
                    },
                    {f.vuln_id_from_tool for f in findings},
                )

    def test_resource_and_property_extraction(self):
        parser = TerraformComplianceParser()
        resource, prop = parser._resource_and_property(
            "public_network_access_enabled property in azurerm_postgresql_server.example resource "
            "does not match with ^false$ case insensitive regex. It is set to True.",
        )
        self.assertEqual("azurerm_postgresql_server.example", resource)
        self.assertEqual("public_network_access_enabled", prop)

        with self.subTest("a message in another shape does not raise"):
            self.assertEqual((None, None), parser._resource_and_property("Something else failed"))
            self.assertEqual((None, None), parser._resource_and_property(None))
