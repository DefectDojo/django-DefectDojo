import io
import json

from dojo.models import Finding, Test
from dojo.tools.dirsearch.parser import DirsearchParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestDirsearchParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("dirsearch") / filename).open(encoding="utf-8") as file:
            return list(DirsearchParser().get_findings(file, Test()))

    def test_scan_type_metadata(self):
        parser = DirsearchParser()
        self.assertEqual(["Dirsearch Scan"], parser.get_scan_types())
        self.assertEqual("Dirsearch Scan", parser.get_label_for_scan_types("Dirsearch Scan"))
        self.assertIn("dirsearch --format=json",
                      parser.get_description_for_scan_types("Dirsearch Scan"))

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("dirsearch_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("dirsearch_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, from a real `dirsearch --format=json` run against a local target."""
        findings = self.parse("dirsearch_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("HTTP 301: /admin", finding.title)
        self.assertEqual("Info", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertTrue(finding.dynamic_finding)
        self.assertFalse(finding.static_finding)
        self.assertEqual(1, len(finding.unsaved_endpoints))

        self.assertIn("**Status:** 301", finding.description)
        self.assertIn("**Content length:** 169", finding.description)
        self.assertIn("**Content type:** text/html", finding.description)
        self.assertIn("**Redirects to:** http://wave3target/admin/", finding.description)

    def test_the_url_becomes_an_endpoint(self):
        """A discovered path is a URL, so it maps to an endpoint rather than a file path."""
        finding = self.parse("dirsearch_one_vuln.json")[0]
        self.assertIsNone(getattr(finding, "file_path", None))
        self.assertIsNone(getattr(finding, "line", None))

    def test_severity_is_info_because_discovery_is_not_a_weakness(self):
        """
        Discovery is not the same as a weakness.

        dirsearch reports paths that exist; whether one matters depends on which path it is, so
        everything imports at Info - the same call the ffuf parser makes.
        """
        findings = self.parse("dirsearch_many_vuln.json")
        self.assertEqual({"Info"}, {finding.severity for finding in findings})

    def test_many_vuln(self):
        findings = self.parse("dirsearch_many_vuln.json")
        self.assertEqual(4, len(findings))
        self.assertEqual(
            [
                "HTTP 200: /robots.txt",
                "HTTP 301: /.git",
                "HTTP 301: /admin",
                "HTTP 301: /backup",
            ],
            sorted(finding.title for finding in findings),
        )
        for finding in findings:
            self.assertEqual(1, len(finding.unsaved_endpoints))

    def test_the_invocation_is_kept_as_evidence(self):
        """The wordlist and status filters decide what counted as a hit."""
        finding = self.parse("dirsearch_one_vuln.json")[0]
        self.assertIn("**Command:** `", finding.description)

    def test_a_null_redirect_is_omitted(self):
        """
        Dirsearch always emits a redirect key and leaves it null for a direct hit.

        Printing "Redirects to: None" would be worse than saying nothing.
        """
        report = io.StringIO(json.dumps({
            "info": {"args": "dirsearch -u http://target.example.com/"},
            "results": [{
                "url": "http://target.example.com/found",
                "status": 200,
                "content-length": 10,
                "content-type": "text/plain",
                "redirect": None,
            }],
        }))
        finding = list(DirsearchParser().get_findings(report, Test()))[0]
        self.assertNotIn("**Redirects to:**", finding.description)

    def test_result_without_a_status(self):
        report = io.StringIO(json.dumps({
            "results": [{"url": "http://target.example.com/x"}],
        }))
        finding = list(DirsearchParser().get_findings(report, Test()))[0]
        self.assertEqual("Discovered: /x", finding.title)

    def test_result_without_a_url(self):
        report = io.StringIO(json.dumps({"results": [{"status": 200}]}))
        finding = list(DirsearchParser().get_findings(report, Test()))[0]
        self.assertEqual("HTTP 200: /", finding.title)
        self.assertEqual([], finding.unsaved_endpoints)

    def test_absent_results_key(self):
        self.assertEqual([], list(DirsearchParser().get_findings(io.StringIO("{}"), Test())))

    def test_wrong_shape_is_rejected(self):
        with self.assertRaises(TypeError):
            list(DirsearchParser().get_findings(io.StringIO("[]"), Test()))
        with self.assertRaises(TypeError):
            list(DirsearchParser().get_findings(io.StringIO('{"results": ["x"]}'), Test()))
