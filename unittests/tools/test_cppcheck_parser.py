from dojo.models import Finding, Test
from dojo.tools.cppcheck.parser import CppcheckParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestCppcheckParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("cppcheck") / filename).open(encoding="utf-8") as file:
            return list(CppcheckParser().get_findings(file, Test()))

    def test_scan_type_metadata(self):
        parser = CppcheckParser()
        self.assertEqual(["Cppcheck Scan"], parser.get_scan_types())
        self.assertEqual("Cppcheck Scan", parser.get_label_for_scan_types("Cppcheck Scan"))
        # The description has to mention the stderr redirect, because getting that wrong yields an
        # empty report rather than an error.
        self.assertIn("stderr", parser.get_description_for_scan_types("Cppcheck Scan"))

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("cppcheck_no_vuln.sarif")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("cppcheck_one_vuln.sarif")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, from a real `cppcheck --output-format=sarif cc_single.c` run."""
        findings = self.parse("cppcheck_one_vuln.sarif")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Array 'values[10]' accessed at index 10, which is out of bounds.", finding.title)
        self.assertEqual("arrayIndexOutOfBounds", finding.vuln_id_from_tool)
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("cc_single.c", finding.file_path)
        self.assertEqual(8, finding.line)

        # Cppcheck's SARIF carries no CWE taxonomy at all, which is why "Cppcheck Scan" is registered in
        # HASHCODE_ALLOWS_NULL_CWE.
        self.assertIsNone(finding.cwe)

    def test_many_vuln(self):
        """
        Ten findings from seven SARIF results.

        A cppcheck result can carry several locations - the same null-dereference-on-allocation-failure
        reported at more than one line - and the shared SARIF parser emits one finding per location. That
        is the behaviour worth pinning, because a naive count of `results` would say seven.
        """
        findings = self.parse("cppcheck_many_vuln.sarif")
        self.assertEqual(10, len(findings))
        for finding in findings:
            self.assertIn(finding.severity, Finding.SEVERITIES)
            self.assertEqual("cc_many.c", finding.file_path)

    def test_many_vuln_rules_and_severities(self):
        """Each defect class keeps its own rule id and severity."""
        findings = self.parse("cppcheck_many_vuln.sarif")
        rules = sorted({finding.vuln_id_from_tool for finding in findings})
        self.assertEqual(
            [
                "arrayIndexOutOfBounds",
                "memleak",
                "nullPointer",
                "nullPointerOutOfMemory",
                "unassignedVariable",
                "uninitvar",
                "unreadVariable",
            ],
            rules,
        )

        by_rule = {}
        for finding in findings:
            by_rule.setdefault(finding.vuln_id_from_tool, []).append(finding)

        # cppcheck "error" severity maps to Critical, "warning" to Medium.
        self.assertEqual("Critical", by_rule["arrayIndexOutOfBounds"][0].severity)
        self.assertEqual("Critical", by_rule["memleak"][0].severity)
        self.assertEqual("Critical", by_rule["uninitvar"][0].severity)
        self.assertEqual("Medium", by_rule["nullPointerOutOfMemory"][0].severity)

    def test_many_vuln_multi_location_result_expands(self):
        """
        The nullPointerOutOfMemory result is reported at three locations and becomes three findings, so a
        reader sees every line the defect applies to rather than just the first.
        """
        findings = self.parse("cppcheck_many_vuln.sarif")
        out_of_memory = [f for f in findings if f.vuln_id_from_tool == "nullPointerOutOfMemory"]
        self.assertEqual(3, len(out_of_memory))
        self.assertEqual([6, 6, 7], sorted(f.line for f in out_of_memory))

    def test_many_vuln_line_numbers(self):
        findings = self.parse("cppcheck_many_vuln.sarif")
        by_rule = {}
        for finding in findings:
            by_rule.setdefault(finding.vuln_id_from_tool, []).append(finding.line)

        self.assertEqual([8], by_rule["memleak"])
        self.assertEqual([12], by_rule["arrayIndexOutOfBounds"])
        self.assertEqual([17], by_rule["uninitvar"])
        self.assertEqual([21, 22], sorted(by_rule["nullPointer"]))
