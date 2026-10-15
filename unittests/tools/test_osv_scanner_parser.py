import io
import json

from dojo.models import Test
from dojo.tools.osv_scanner.parser import OSVScannerParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestOSVScannerParser(DojoTestCase):
    def test_no_findings(self):
        with (get_unit_tests_scans_path("osv_scanner") / "no_findings.json").open(encoding="utf-8") as testfile:
            parser = OSVScannerParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_some_findings(self):
        with (get_unit_tests_scans_path("osv_scanner") / "some_findings.json").open(encoding="utf-8") as testfile:
            parser = OSVScannerParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual(finding.cwe, "CWE-506")
            self.assertEqual(finding.title, "MAL-2023-1035_flot-axis")
            self.assertEqual(finding.cve, None)
            self.assertEqual(finding.unsaved_vulnerability_ids[0], "MAL-2023-1035")
            self.assertEqual(finding.severity, "Low")

    def test_multi_cwe(self):
        with (get_unit_tests_scans_path("osv_scanner") / "multi_cwe_fabricated.json").open(encoding="utf-8") as testfile:
            parser = OSVScannerParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual(finding.cwe, "CWE-79")
            self.assertEqual(["CWE-79", "CWE-89"], finding.unsaved_cwes)

    def test_many_findings(self):
        with (get_unit_tests_scans_path("osv_scanner") / "many_findings.json").open(encoding="utf-8") as testfile:
            parser = OSVScannerParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(66, len(findings))
            finding = findings[0]
            self.assertEqual(finding.title, "GHSA-25mq-v84q-4j7r_guzzlehttp/guzzle")
            self.assertEqual(finding.cve, None)
            self.assertEqual(finding.unsaved_vulnerability_ids[0], "GHSA-25mq-v84q-4j7r")
            self.assertEqual(finding.severity, "High")
            finding = findings[3]
            self.assertEqual(finding.static_finding, True)
            self.assertEqual(finding.title, "GHSA-q559-8m2m-g699_guzzlehttp/guzzle")
            self.assertEqual(finding.file_path, "/tmpcardmarket-api/composer.lock")
            self.assertEqual(finding.component_name, "guzzlehttp/guzzle")
            finding = findings[17]
            self.assertEqual(finding.references, "https://nvd.nist.gov/vuln/detail/CVE-2021-45115\nhttps://docs.djangoproject.com/en/4.0/releases/security\nhttps://github.com/django/django\nhttps://groups.google.com/forum/#!forum/django-announce\nhttps://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/B4SQG2EAF4WCI2SLRL6XRDJ3RPK3ZRDV\nhttps://security.netapp.com/advisory/ntap-20220121-0005\nhttps://www.djangoproject.com/weblog/2022/jan/04/security-releases\n")
            self.assertEqual(finding.title, "GHSA-53qw-q765-4fww_django")
            self.assertEqual(finding.mitigation, "**Upgrade to versions**:\n\tECOSYSTEM :\n\t\t- 2.2.26\n")

    # Regression: the OSV `aliases` (the CVE for a GHSA-keyed advisory) were dropped, so an
    # OSV finding carried only the OSV id and never its CVE.
    def test_aliases_become_vulnerability_ids(self):
        with (get_unit_tests_scans_path("osv_scanner") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = OSVScannerParser().get_findings(testfile, Test())
        expected = {
            0: ["GHSA-25mq-v84q-4j7r", "CVE-2022-31090"],
            17: ["GHSA-53qw-q765-4fww", "BIT-django-2021-45115", "CVE-2021-45115", "PYSEC-2022-1"],
        }
        for index, vulnerability_ids in expected.items():
            with self.subTest(finding=index):
                parsed = findings[index].unsaved_vulnerability_ids
                self.assertEqual(vulnerability_ids, parsed, msg=f"finding {index}: expected {vulnerability_ids}, parsed {parsed}")
        with self.subTest("a non-CVE id keeps its GHSA alias"):
            with (get_unit_tests_scans_path("osv_scanner") / "some_findings.json").open(encoding="utf-8") as testfile:
                finding = OSVScannerParser().get_findings(testfile, Test())[0]
            self.assertEqual(["MAL-2023-1035", "GHSA-8348-2q94-ffjx"], finding.unsaved_vulnerability_ids)

    def test_malformed_aliases_are_ignored(self):
        def parse(aliases):
            vulnerability = {"id": "GHSA-jfh8-c2jp-5v3q"}
            if aliases != "absent":
                vulnerability["aliases"] = aliases
            report = {"results": [{"packages": [{"package": {"name": "log4j-core"}, "vulnerabilities": [vulnerability]}]}]}
            return OSVScannerParser().get_findings(io.StringIO(json.dumps(report)), Test())[0].unsaved_vulnerability_ids

        cases = {
            "absent": ["GHSA-jfh8-c2jp-5v3q"],
            "null": ["GHSA-jfh8-c2jp-5v3q"],
            "a string, not a list": ["GHSA-jfh8-c2jp-5v3q"],
            "non-strings and blanks dropped, whitespace stripped": ["GHSA-jfh8-c2jp-5v3q", "CVE-2021-44228"],
        }
        inputs = {
            "absent": "absent",
            "null": None,
            "a string, not a list": "CVE-2021-44228",
            "non-strings and blanks dropped, whitespace stripped": [5, {"x": 1}, None, " ", " CVE-2021-44228 ", "GHSA-jfh8-c2jp-5v3q"],
        }
        for name, expected in cases.items():
            with self.subTest(name):
                self.assertEqual(expected, parse(inputs[name]))
