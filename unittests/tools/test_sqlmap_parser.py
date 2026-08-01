import io

from dojo.models import Finding, Test
from dojo.tools.sqlmap.parser import SqlmapParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestSqlmapParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("sqlmap") / filename).open(encoding="utf-8") as file:
            return list(SqlmapParser().get_findings(file, Test()))

    def test_scan_type_metadata(self):
        parser = SqlmapParser()
        self.assertEqual(["Sqlmap Scan"], parser.get_scan_types())
        self.assertEqual("Sqlmap Scan", parser.get_label_for_scan_types("Sqlmap Scan"))
        self.assertIn("log file", parser.get_description_for_scan_types("Sqlmap Scan"))

    def test_no_vuln_log_is_empty(self):
        """
        A sqlmap run that finds no injection writes a ZERO-BYTE log file.

        The fixture is that real empty file. Finding no injection is the ordinary result of scanning
        an application that binds its parameters, so it must parse rather than raise.
        """
        self.assertEqual(0, (get_unit_tests_scans_path("sqlmap") / "sqlmap_no_vuln.log").stat().st_size)
        self.assertEqual(0, len(self.parse("sqlmap_no_vuln.log")))

    def test_no_vuln_csv_is_header_only(self):
        """The matching clean CSV is the header row and nothing else."""
        self.assertEqual(0, len(self.parse("sqlmap_no_vuln.csv")))

    def test_one_vuln_log(self):
        self.assertEqual(1, len(self.parse("sqlmap_one_vuln.log")))

    def test_one_vuln_log_field_mapping(self):
        """Full field mapping, from a real sqlmap 1.10.7 run against a local injectable target."""
        findings = self.parse("sqlmap_one_vuln.log")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("SQL injection in GET parameter 'id'", finding.title)
        self.assertEqual("High", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual(89, finding.cwe)
        self.assertTrue(finding.dynamic_finding)
        self.assertFalse(finding.static_finding)
        self.assertIn("bound value", finding.mitigation)

        self.assertIn("**Parameter:** id (GET)", finding.description)
        self.assertIn("**Back-end DBMS:** SQLite", finding.description)
        # Every technique sqlmap confirmed is kept, each with its title and payload.
        self.assertIn("**Type:** boolean-based blind", finding.description)
        self.assertIn("**Type:** time-based blind", finding.description)
        self.assertIn("**Type:** UNION query", finding.description)
        self.assertIn("**Payload:** `id=1 AND 1415=1415`", finding.description)

    def test_one_vuln_csv_field_mapping(self):
        """The CSV of the same scan, whose technique letters expand to names."""
        findings = self.parse("sqlmap_one_vuln.csv")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("SQL injection in GET parameter 'id'", finding.title)
        self.assertEqual("High", finding.severity)
        self.assertEqual(89, finding.cwe)
        self.assertIn("**Target:** http://wave3sqli:5000/item?id=1", finding.description)
        self.assertIn(
            "**Techniques:** boolean-based blind, time-based blind, UNION query",
            finding.description,
        )

    def test_only_the_csv_carries_an_endpoint(self):
        """
        The log file has no target URL in it - it is written into a directory named after the host.

        So a log import has no endpoint and a CSV import does, rather than a host being invented.
        """
        self.assertEqual([], self.get_unsaved_locations(self.parse("sqlmap_one_vuln.log")[0]))

        endpoints = self.get_unsaved_locations(self.parse("sqlmap_one_vuln.csv")[0])
        self.assertEqual(1, len(endpoints))
        self.assertEqual("wave3sqli", endpoints[0].host)

    def test_many_vuln_log(self):
        """One finding per injectable parameter, not one per confirmed technique."""
        findings = self.parse("sqlmap_many_vuln.log")
        self.assertEqual(2, len(findings))
        self.assertEqual(
            ["SQL injection in GET parameter 'id'", "SQL injection in GET parameter 'name'"],
            sorted(finding.title for finding in findings),
        )

    def test_many_vuln_csv(self):
        findings = self.parse("sqlmap_many_vuln.csv")
        self.assertEqual(2, len(findings))

        by_parameter = {finding.title: finding for finding in findings}
        # id was injectable three ways, name only two - the letters differ per row.
        self.assertIn(
            "**Techniques:** boolean-based blind, time-based blind, UNION query",
            by_parameter["SQL injection in GET parameter 'id'"].description,
        )
        self.assertIn(
            "**Techniques:** boolean-based blind, time-based blind",
            by_parameter["SQL injection in GET parameter 'name'"].description,
        )

    def test_a_resumed_run_does_not_double_the_findings(self):
        """
        Sqlmap APPENDS to its log, so scanning the same target twice writes the report twice.

        The fixture is a real log holding both an "identified" and a "resumed ... from stored
        session" report for the same two parameters. Keying on place and parameter keeps two
        findings rather than four.
        """
        content = (get_unit_tests_scans_path("sqlmap") / "sqlmap_resumed_session.log").read_text(
            encoding="utf-8",
        )
        self.assertIn("sqlmap identified the following injection point", content)
        self.assertIn("resumed the following injection point", content)
        self.assertEqual(4, content.count("Parameter: "))

        self.assertEqual(2, len(self.parse("sqlmap_resumed_session.log")))

    def test_a_repeated_run_does_not_double_the_csv_findings(self):
        """The CSV results file appends too, so the same two rows appear twice in this fixture."""
        content = (get_unit_tests_scans_path("sqlmap") / "sqlmap_repeated_run.csv").read_text(
            encoding="utf-8",
        )
        self.assertEqual(4, len([line for line in content.splitlines()[1:] if line.strip()]))

        self.assertEqual(2, len(self.parse("sqlmap_repeated_run.csv")))

    def test_every_csv_technique_letter_is_named(self):
        """
        The CSV technique letter is the first letter of the technique NAME, uppercased.

        That matters for an inline query, which is "I" in the CSV but "Q" on the --technique flag.
        """
        report = io.StringIO(
            "Target URL,Place,Parameter,Technique(s),Note(s)\n"
            "http://target.example.com/x?a=1,GET,a,BEISTU,\n",
        )
        finding = list(SqlmapParser().get_findings(report, Test()))[0]
        self.assertIn(
            "**Techniques:** boolean-based blind, error-based, inline query, stacked queries, "
            "time-based blind, UNION query",
            finding.description,
        )

    def test_a_post_parameter_is_reported_as_post(self):
        report = io.StringIO(
            "Target URL,Place,Parameter,Technique(s),Note(s)\n"
            "http://target.example.com/login,POST,username,B,\n",
        )
        finding = list(SqlmapParser().get_findings(report, Test()))[0]
        self.assertEqual("SQL injection in POST parameter 'username'", finding.title)

    def test_a_csv_note_is_kept(self):
        report = io.StringIO(
            "Target URL,Place,Parameter,Technique(s),Note(s)\n"
            "http://target.example.com/x?a=1,GET,a,B,false positive or unexploitable\n",
        )
        finding = list(SqlmapParser().get_findings(report, Test()))[0]
        self.assertIn("**Notes:** false positive or unexploitable", finding.description)

    def test_the_same_parameter_on_two_targets_stays_two_findings(self):
        report = io.StringIO(
            "Target URL,Place,Parameter,Technique(s),Note(s)\n"
            "http://one.example.com/x?a=1,GET,a,B,\n"
            "http://two.example.com/x?a=1,GET,a,B,\n",
        )
        self.assertEqual(2, len(list(SqlmapParser().get_findings(report, Test()))))

    def test_an_unknown_technique_letter_is_kept_verbatim(self):
        """A future sqlmap technique should not be dropped silently."""
        report = io.StringIO(
            "Target URL,Place,Parameter,Technique(s),Note(s)\n"
            "http://target.example.com/x?a=1,GET,a,BZ,\n",
        )
        finding = list(SqlmapParser().get_findings(report, Test()))[0]
        self.assertIn("**Techniques:** boolean-based blind, Z", finding.description)

    def test_empty_report(self):
        self.assertEqual([], list(SqlmapParser().get_findings(io.StringIO(""), Test())))

    def test_bytes_input(self):
        report = io.BytesIO(
            b"sqlmap identified the following injection point(s):\n"
            b"---\n"
            b"Parameter: id (GET)\n"
            b"    Type: boolean-based blind\n"
            b"    Title: AND boolean-based blind\n"
            b"    Payload: id=1 AND 1=1\n"
            b"---\n",
        )
        self.assertEqual(1, len(list(SqlmapParser().get_findings(report, Test()))))
