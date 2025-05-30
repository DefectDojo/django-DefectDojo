from dojo.models import Test
from dojo.tools.anchore_engine.parser import AnchoreEngineParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestAnchoreEngineParser(DojoTestCase):
    def test_anchore_engine_parser_has_no_finding(self):
        with (get_unit_tests_scans_path("anchore_engine") / "no_vuln.json").open(encoding="utf-8") as testfile:
            parser = AnchoreEngineParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_anchore_engine_parser_has_one_finding(self):
        with (get_unit_tests_scans_path("anchore_engine") / "one_vuln.json").open(encoding="utf-8") as testfile:
            parser = AnchoreEngineParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

    def test_anchore_engine_parser_has_many_findings(self):
        with (get_unit_tests_scans_path("anchore_engine") / "many_vulns.json").open(encoding="utf-8") as testfile:
            parser = AnchoreEngineParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(23, len(findings))

    def test_anchore_engine_parser_has_many_findings_2_4_1(self):
        with (get_unit_tests_scans_path("anchore_engine") / "many_vulns_2.4.1.json").open(encoding="utf-8") as testfile:
            parser = AnchoreEngineParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(51, len(findings))
            finding = findings[50]
            self.assertEqual("CVE-2020-13776", finding.vuln_id_from_tool)
            self.assertEqual("systemd-pam", finding.component_name)
            self.assertEqual("239-41.el8_3.1", finding.component_version)
            self.assertEqual(6.7, finding.cvssv3_score)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2020-13776", finding.unsaved_vulnerability_ids[0])

    def test_anchore_engine_parser_new_fomrat_issue_11552(self):
        with (get_unit_tests_scans_path("anchore_engine") / "new_format_issue_11552.json").open(encoding="utf-8") as testfile:
            parser = AnchoreEngineParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(84, len(findings))
            finding = findings[50]
            self.assertEqual("CVE-2023-0466", finding.vuln_id_from_tool)
            self.assertEqual("openssl-libs-1:1.1.1k-14.el8_6", finding.component_name)
            self.assertEqual("CVE-2023-0466-openssl-libs-1:1.1.1k-14.el8_6(RPM)", finding.title)
