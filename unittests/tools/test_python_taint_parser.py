from dojo.models import Test
from dojo.tools.python_taint.parser import PythonTaintParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestPythonTaintParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("python_taint") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = PythonTaintParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("python_taint") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = PythonTaintParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Tainted flow: request.args.get( to subprocess.call(", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual("taintapp.py", finding.file_path)
            # The finding anchors on the sink, where the dangerous operation happens.
            self.assertEqual(8, finding.line)
            self.assertEqual("request.args.get( -> subprocess.call(", finding.vuln_id_from_tool)
            self.assertIn("**Source:** taintapp.py:7", finding.description)
            self.assertIn("**Sink:** taintapp.py:8", finding.description)
            self.assertIn("**Propagation:**", finding.description)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

    def test_each_flow_is_its_own_finding(self):
        with (get_unit_tests_scans_path("python_taint") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = PythonTaintParser().get_findings(testfile, Test())
            self.assertEqual(2, len(findings))
            self.assertEqual({"High"}, {f.severity for f in findings})

            with self.subTest("the second flow reaches a SQL sink on its own line"):
                sql = next(f for f in findings if "cursor.execute(" in f.vuln_id_from_tool)
                self.assertEqual(14, sql.line)
                self.assertIn("request.form.get(", sql.vuln_id_from_tool)
