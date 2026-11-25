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

    def _parse_severity_report(self, vulnerabilities, groups=None):
        package = {
            "package": {
                "name": "example-package",
                "version": "1.0.0",
                "ecosystem": "PyPI",
            },
            "vulnerabilities": vulnerabilities,
        }

        if groups is not None:
            package["groups"] = groups

        report = {
            "results": [
                {
                    "source": {
                        "path": "/example/uv.lock",
                        "type": "lockfile",
                    },
                    "packages": [package],
                },
            ],
        }

        return OSVScannerParser().get_findings(
            io.StringIO(json.dumps(report)),
            Test(),
        )

    def test_database_severity_takes_precedence(self):
        vulnerability = {
            "id": "TEST-001",
            "database_specific": {
                "severity": "HIGH",
            },
            "severity": [
                {
                    "type": "CVSS_V4",
                    "score": (
                        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/"
                        "VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
                    ),
                },
            ],
        }

        groups = [
            {
                "ids": ["TEST-001"],
                "max_severity": "9.2",
            },
        ]

        findings = self._parse_severity_report(
            [vulnerability], groups,
        )

        self.assertEqual(1, len(findings))
        self.assertEqual("High", findings[0].severity)

    def test_group_severity_fallback(self):
        cases = [
            ("10.0", "Critical"),
            ("9.2", "Critical"),
            ("9.0", "Critical"),
            ("8.9", "High"),
            ("7.5", "High"),
            ("7.0", "High"),
            ("6.9", "Medium"),
            ("5.5", "Medium"),
            ("4.0", "Medium"),
            ("3.9", "Low"),
            ("0.1", "Low"),
            ("0.0", "Info"),
        ]

        database_cases = [
            ("missing_database_specific", {}),
            ("missing_severity", {"database_specific": {}}),
            ("null_severity", {
                "database_specific": {"severity": None},
            }),
        ]

        for database_case, metadata in database_cases:
            for score, expected in cases:
                with self.subTest(
                    database_case=database_case,
                    score=score,
                ):
                    vulnerability = {
                        "id": "TEST-001",
                        **metadata,
                    }

                    groups = [
                        {
                            "ids": ["TEST-001"],
                            "max_severity": score,
                        },
                    ]

                    findings = self._parse_severity_report(
                        [vulnerability], groups,
                    )

                    self.assertEqual(1, len(findings))
                    self.assertEqual(
                        expected,
                        findings[0].severity,
                    )

    def test_group_severity_matches_vulnerability_id(self):
        vulnerabilities = [
            {"id": "TEST-001"},
            {"id": "TEST-002"},
            {"id": "TEST-003"},
        ]

        groups = [
            {
                "ids": ["TEST-002"],
                "max_severity": "9.2",
            },
            {
                "ids": ["TEST-001"],
                "max_severity": "5.5",
            },
        ]

        findings = self._parse_severity_report(
            vulnerabilities, groups,
        )

        self.assertEqual(3, len(findings))
        self.assertEqual("Medium", findings[0].severity)
        self.assertEqual("Critical", findings[1].severity)
        self.assertEqual("Low", findings[2].severity)

    def test_group_severity_takes_precedence_over_vector(self):
        vulnerability = {
            "id": "TEST-001",
            "severity": [
                {
                    "type": "CVSS_V4",
                    "score": (
                        "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/"
                        "VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
                    ),
                },
            ],
        }

        groups = [
            {
                "ids": ["TEST-001"],
                "max_severity": "7.5",
            },
        ]

        findings = self._parse_severity_report(
            [vulnerability], groups,
        )

        self.assertEqual(1, len(findings))
        self.assertEqual("High", findings[0].severity)

    def test_cvss_vector_severity_fallback(self):
        cases = [
            (
                "CVSS_V2",
                "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                "High",
            ),
            (
                "CVSS_V3",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                "High",
            ),
            (
                "CVSS_V4",
                (
                    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/"
                    "VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
                ),
                "Critical",
            ),
        ]

        for version, vector, expected in cases:
            with self.subTest(version=version):
                vulnerability = {
                    "id": "TEST-001",
                    "severity": [
                        {
                            "type": version,
                            "score": vector,
                        },
                    ],
                }

                findings = self._parse_severity_report(
                    [vulnerability],
                )

                self.assertEqual(1, len(findings))
                self.assertEqual(
                    expected,
                    findings[0].severity,
                )

    def test_cvss_vector_fallback_when_group_score_missing(self):
        vulnerability = {
            "id": "TEST-001",
            "database_specific": {
                "severity": None,
            },
            "severity": [
                {
                    "type": "CVSS_V3",
                    "score": (
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/"
                        "S:U/C:N/I:N/A:H"
                    ),
                },
            ],
        }

        cases = [
            [{"ids": ["TEST-001"]}],
            [{"ids": ["TEST-001"], "max_severity": None}],
            [{"ids": ["TEST-002"], "max_severity": "9.2"}],
        ]

        for groups in cases:
            with self.subTest(groups=groups):
                findings = self._parse_severity_report(
                    [vulnerability], groups,
                )

                self.assertEqual(1, len(findings))
                self.assertEqual("High", findings[0].severity)
