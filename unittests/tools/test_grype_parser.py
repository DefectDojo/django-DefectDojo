from dojo.models import Test
from dojo.tools.grype.parser import GrypeParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestGrypeParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("grype") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = GrypeParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("grype") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = GrypeParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("High", finding.severity)
            self.assertEqual("GHSA-x84v-xcm2-53pg", finding.vuln_id_from_tool)
            self.assertEqual("requests", finding.component_name)
            self.assertEqual("2.19.1", finding.component_version)
            self.assertEqual("Upgrade requests to 2.20.0.", finding.mitigation)
            self.assertEqual("/uv.lock", finding.file_path)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

            with self.subTest("the aliased CVE, CWE and CVSS score are carried across"):
                self.assertIn("CVE-2018-18074", finding.unsaved_vulnerability_ids)
                self.assertEqual(522, finding.cwe)
                self.assertEqual(7.5, finding.cvssv3_score)

    def test_parse_many_findings(self):
        with (get_unit_tests_scans_path("grype") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = GrypeParser().get_findings(testfile, Test())
            self.assertEqual(8, len(findings))

            with self.subTest("Grype's own severities are preserved"):
                self.assertEqual(6, len([f for f in findings if f.severity == "High"]))
                self.assertEqual(2, len([f for f in findings if f.severity == "Medium"]))

            with self.subTest("every match is tied to a package and version"):
                for finding in findings:
                    self.assertTrue(finding.component_name)
                    self.assertTrue(finding.component_version)
                    self.assertTrue(finding.vuln_id_from_tool)

    def test_highest_cvss_base_score_is_used(self):
        parser = GrypeParser()
        cvss = [
            {"metrics": {"baseScore": 5.3}},
            {"metrics": {"baseScore": 7.5}},
        ]
        self.assertEqual(7.5, parser._cvss_score(cvss))
        self.assertIsNone(parser._cvss_score([]))

    def test_cwe_is_read_from_either_shape(self):
        parser = GrypeParser()
        self.assertEqual(522, parser._cwe([{"cwe": "CWE-522"}]))
        self.assertEqual(79, parser._cwe(["CWE-79"]))
        self.assertIsNone(parser._cwe([]))
