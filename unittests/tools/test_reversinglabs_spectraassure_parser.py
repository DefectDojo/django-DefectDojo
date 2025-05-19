# import datetime

"""
run with:
- ./run-unittest.sh --test-case unittests.tools.test_reversinglabs_spectraassure_parser.TestReversingLabsSpectraAssureParser

FD13-FullUSb.zip: finds no vulnerabilities
putty_win_x64-0.80.exe: finds only one vulnerability
HxDSetup_2.5.0.exe: has multiple components with the same name but different sha256 (different languages)

"""

from dojo.models import (
    # Engagement,
    Finding,
    # Product,
    Test,
)
from unittests.dojo_test_case import (
    DojoTestCase,
    get_unit_tests_scans_path,
)

from dojo.tools.reversinglabs_spectraassure.parser import (
    ReversinglabsSpectraassureParser,
)

_WHERE = "reversinglabs_spectraassure"

_FILES = [
    "FD13-FullUSB.zip-report.rl.json",  # No Vulnerabilities
    "putty_win_x64-0.80.exe-report.rl.json",  # One vulnerability
    "HxDSetup_2.5.0.exe-report.rl.json",  # Multiple with identical component name but different sha256
]


# mypy gives:  error: Class cannot subclass "DojoTestCase" (has type "Any")  [misc]
class TestReversingLabsSpectraAssureParser(DojoTestCase):  # type: ignore[misc]
    def common_checks(self, finding: Finding) -> None:
        self.assertLessEqual(len(finding.title), 250)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        if finding.cwe:
            self.assertIsInstance(finding.cwe, int)
        self.assertEqual(True, finding.static_finding)  # by specification
        self.assertEqual(False, finding.dynamic_finding)  # by specification

    def test_parse_file_with_no_vuln(self) -> None:
        with (get_unit_tests_scans_path(_WHERE) / "FD13-FullUSB.zip-report.rl.json").open(encoding="utf-8") as testfile:
            parser = ReversinglabsSpectraassureParser()
            findings = parser.get_findings(
                testfile,
                Test(),
            )
            self.assertEqual(0, len(findings))
            for finding in findings:
                self.common_checks(finding)
                self.assertEqual(1, len(finding.unsaved_vulnerability_ids))

    def test_parse_file_with_one_vuln(self) -> None:
        with (get_unit_tests_scans_path(_WHERE) / "putty_win_x64-0.80.exe-report.rl.json").open(
            encoding="utf-8",
        ) as testfile:
            parser = ReversinglabsSpectraassureParser()
            findings = parser.get_findings(
                testfile,
                Test(),
            )
            self.assertEqual(1, len(findings))
            for finding in findings:
                self.common_checks(finding)
                self.assertEqual(1, len(finding.unsaved_vulnerability_ids))

    def test_parse_file_with_many_vulns(self) -> None:
        with (get_unit_tests_scans_path(_WHERE) / "HxDSetup_2.5.0.exe-report.rl.json").open(
            encoding="utf-8",
        ) as testfile:
            parser = ReversinglabsSpectraassureParser()
            findings = parser.get_findings(
                testfile,
                Test(),
            )
            self.assertEqual(12, len(findings))
            for finding in findings:
                self.common_checks(finding)
                self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
