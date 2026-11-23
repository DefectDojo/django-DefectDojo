import datetime
import io

from dojo.models import Finding, Test
from dojo.tools.ddtrace_iast.parser import DdtraceIastParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


def parse(name):
    with (get_unit_tests_scans_path("ddtrace_iast") / name).open(encoding="utf-8") as testfile:
        return DdtraceIastParser().get_findings(testfile, Test())


class TestDdtraceIastParser(DojoTestCase):

    def test_no_vuln(self):
        with self.assertLogs("dojo.tools.ddtrace_iast.parser", level="INFO") as logs:
            self.assertEqual(0, len(parse("no_vuln.json")))
        self.assertEqual(["dd-trace IAST report holds no vulnerabilities"], [r.getMessage() for r in logs.records])

    def test_one_vuln(self):
        with self.assertNoLogs("dojo.tools.ddtrace_iast.parser", level="INFO"):
            findings = parse("one_vuln.json")
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("SQL_INJECTION in app.py:6", finding.title)
        self.assertEqual("High", finding.severity)
        self.assertEqual(89, finding.cwe)
        self.assertEqual("app.py", finding.file_path)
        self.assertEqual(6, finding.line)
        self.assertEqual("demo", finding.component_name)
        self.assertEqual("651293933", finding.vuln_id_from_tool)
        self.assertIsNone(finding.unique_id_from_tool)
        self.assertFalse(finding.static_finding)
        self.assertTrue(finding.dynamic_finding)
        self.assertEqual(1, finding.nb_occurences)
        self.assertEqual(datetime.date(2026, 11, 23), finding.date)
        self.assertEqual(["ddtrace-iast", "synthetic"], finding.unsaved_tags)

    def test_one_vuln_description_keeps_redaction(self):
        description = parse("one_vuln.json")[0].description
        self.assertIn("**Evidence:** `select * from u where n='[redacted]'`", description)
        self.assertIn("**Route:** GET /sqli", description)
        self.assertIn("http.request.parameter:n", description)
        self.assertIn("GET /sqli", description)
        self.assertIn("sqli", description)
        self.assertIn("651293933", description)
        self.assertNotIn("pattern", description)

    def test_many_vulns(self):
        findings = parse("many_vulns.json")
        self.assertEqual(4, len(findings))
        for finding in findings:
            with self.subTest(title=finding.title, service=finding.component_name):
                self.assertIn(finding.severity, Finding.SEVERITIES)
                self.assertTrue(finding.dynamic_finding)
        self.assertEqual(
            [
                ("PATH_TRAVERSAL in app.py:9", "demo", 22, 1),
                ("COMMAND_INJECTION in app.py:12", "demo", 78, 1),
                ("SQL_INJECTION in app.py:6", "demo", 89, 2),
                ("SQL_INJECTION in app.py:6", "demo-worker", 89, 1),
            ],
            [(f.title, f.component_name, f.cwe, f.nb_occurences) for f in findings],
        )

    def test_unredacted_source_value_is_never_rendered(self):
        description = parse("many_vulns.json")[0].description
        self.assertIn("/tmp/../etc/passwd", description)  # the evidence the tracer chose to show
        self.assertIn("http.request.parameter:f", description)
        self.assertEqual(1, description.count("../etc/passwd"))  # but not the source value again

    def test_edge_cases_import_cleanly(self):
        findings = parse("edge_cases.json")
        self.assertEqual(3, len(findings))
        weak_hash, traversal, unknown = findings
        with self.subTest("evidence without valueParts"):
            self.assertEqual("WEAK_HASH in crypto.py:3", weak_hash.title)
            self.assertEqual("Medium", weak_hash.severity)
            self.assertEqual(328, weak_hash.cwe)
            self.assertIn("md5", weak_hash.description)
        with self.subTest("source index one past the last source"):
            self.assertIn("/tmp/[redacted]", traversal.description)
            self.assertEqual("files.py", traversal.file_path)
        with self.subTest("unknown type and no location"):
            self.assertEqual("SOME_FUTURE_TYPE", unknown.title)
            self.assertEqual("Info", unknown.severity)
            self.assertIsNone(unknown.cwe)
            self.assertIsNone(unknown.file_path)
            self.assertIsNone(unknown.line)

    def test_record_without_optional_fields_does_not_inherit(self):
        report = io.StringIO(
            '[{"service": "a", "env": "qa", "resource": "GET /a", "start": 1795433469000000000,'
            ' "iast": {"vulnerabilities": [{"type": "XSS", "hash": 1,'
            ' "location": {"path": "a.py", "line": 1}}]}},'
            ' {"iast": {"vulnerabilities": [{"type": "XSS", "hash": 2}]}}]',
        )
        first, second = DdtraceIastParser().get_findings(report, Test())
        self.assertEqual("a", first.component_name)
        self.assertIsNone(second.component_name)
        self.assertEqual(["ddtrace-iast"], second.unsaved_tags)
        self.assertNotIn("GET /a", second.description)
        self.assertIsNone(second.file_path)

    def test_vulnerabilities_without_hash_stay_separate(self):
        report = io.StringIO(
            '[{"service": "a", "iast": {"vulnerabilities": ['
            '"not a vulnerability", {"type": "XSS"}, {"type": "XSS"}]}}]',
        )
        findings = DdtraceIastParser().get_findings(report, Test())
        self.assertEqual([("XSS", None, 1), ("XSS", None, 1)],
                         [(f.title, f.vuln_id_from_tool, f.nb_occurences) for f in findings])

    def test_span_start_becomes_the_date(self):
        def date_of(start):
            report = io.StringIO(
                f'[{{"start": {start}, "iast": {{"vulnerabilities": [{{"type": "XSS", "hash": 1}}]}}}}]',
            )
            return DdtraceIastParser().get_findings(report, Test())[0].date

        epoch = datetime.date(1970, 1, 1)
        self.assertEqual(epoch, date_of(1))  # one nanosecond after the epoch is a real start
        self.assertNotEqual(epoch, date_of(0))  # 0 is the tracer's "unset": keep DefectDojo's default
        self.assertNotEqual(epoch, date_of('"1"'))  # not a number: ignored

    def test_scan_type(self):
        parser = DdtraceIastParser()
        self.assertEqual(["Datadog dd-trace IAST JSON"], parser.get_scan_types())
        self.assertEqual("Datadog dd-trace IAST JSON", parser.get_label_for_scan_types("Datadog dd-trace IAST JSON"))
        self.assertIn("dd-trace", parser.get_description_for_scan_types("Datadog dd-trace IAST JSON"))

    def test_wrong_format_raises(self):
        for content in ('{"vulnerabilities": []}', '[{"finding": {"service": "a"}}]', "[1]", "not json"):
            with self.subTest(content=content), self.assertRaises(ValueError):
                DdtraceIastParser().get_findings(io.StringIO(content), Test())
