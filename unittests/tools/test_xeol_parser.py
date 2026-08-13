import json
from datetime import datetime
from io import StringIO
from unittest import mock

from dojo.models import Test
from dojo.tools import xeol
from dojo.tools.xeol.parser import XeolParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


def _clock_reading(fixed_now):
    """
    A stand-in for the parser's ``datetime`` that reports a fixed "now".

    Subclassed rather than mocked so ``strptime`` keeps working: the parser uses it to
    read the EOL date out of the report.
    """

    class FixedDatetime(datetime):
        @classmethod
        def now(cls, _tz=None):
            return fixed_now

    return FixedDatetime


def _report_with_eol(eol):
    """
    A minimal one-match xeol report carrying the given EOL value.

    Built in memory on purpose. A new file under ``unittests/scans/xeol/`` would be
    picked up by corpus-walking snapshot tests downstream, and this only needs to vary
    one field.
    """
    return StringIO(json.dumps({
        "matches": [{
            "Cycle": {"ProductName": "Example", "ReleaseCycle": "1.0", "Eol": eol},
            "artifact": {"name": "example", "version": "1.0.0", "type": "apk"},
        }],
        "distro": {"name": "alpine", "version": "3.19"},
    }))


class TestXeolParser(DojoTestCase):

    def test_parse_file_with_zero_finding(self):
        testfile = (get_unit_tests_scans_path("xeol") / "xeol_zero.json").open(encoding="utf-8")
        parser = XeolParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_finding(self):
        testfile = (get_unit_tests_scans_path("xeol") / "xeol_one_finding.json").open(encoding="utf-8")
        parser = XeolParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))
        finding = list(findings)[0]
        self.assertEqual(finding.title, "Perl EOL Information")
        # Assertable only because severity no longer depends on the parse date. This
        # sample's Eol is 2026-07-02, so under the old age-banded grading it read Low,
        # then Medium, then High, then Critical over the six weeks that followed.
        self.assertEqual(finding.severity, "Critical")
        self.assertEqual(finding.component_name, "perl")
        self.assertEqual(finding.component_version, "5.38.2-r0")

    def test_parse_file_with_multiple_finding(self):
        testfile = (get_unit_tests_scans_path("xeol") / "xeol_multiple_findings.json").open(encoding="utf-8")
        parser = XeolParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(8, len(findings))
        finding = list(findings)[0]
        self.assertEqual(finding.severity, "Critical")
        self.assertEqual(finding.cwe, 672)
        self.assertEqual(finding.component_name, "spring-boot")
        self.assertEqual(finding.component_version, "2.0.4.RELEASE")
        finding = list(findings)[2]
        self.assertEqual(finding.title, "org.springframework.boot:spring-boot-autoconfigure EOL Information")
        self.assertEqual(finding.severity, "Critical")
        self.assertEqual(finding.cwe, 672)
        self.assertEqual(finding.component_name, "spring-boot-autoconfigure")
        self.assertEqual(finding.component_version, "2.0.4.RELEASE")

    def test_severity_does_not_move_with_the_parse_date(self):
        """
        The same report must grade the same way whenever it is parsed.

        Severity used to band the age of the EOL date, so a single unchanged report
        walked Low -> Medium -> High -> Critical across the six weeks after a component
        went end of life. That re-graded findings on every reimport, and wherever
        severity is one of the configured hash fields it moved hash_code with it, so
        reimport stopped matching the stored findings and created duplicates instead.
        """
        eol = "2026-07-02"
        readings = {}
        for label, fixed_now in (
            ("1 day after EOL", datetime(2026, 7, 3)),
            ("6 weeks after EOL", datetime(2026, 8, 13)),
            ("10 years after EOL", datetime(2036, 7, 2)),
        ):
            with mock.patch.object(xeol.parser, "datetime", _clock_reading(fixed_now)):
                findings = XeolParser().get_findings(_report_with_eol(eol), Test())
            readings[label] = findings[0].severity

        self.assertEqual(
            readings,
            {
                "1 day after EOL": "Critical",
                "6 weeks after EOL": "Critical",
                "10 years after EOL": "Critical",
            },
        )

    def test_cycle_that_has_not_reached_eol_is_informational(self):
        """Reaching the EOL date is a real state change, and the one the date decides."""
        with mock.patch.object(xeol.parser, "datetime", _clock_reading(datetime(2026, 7, 1))):
            findings = XeolParser().get_findings(_report_with_eol("2026-07-02"), Test())
        self.assertEqual(findings[0].severity, "Info")

    def test_unusable_eol_value_is_informational(self):
        """endoflife.date cycles carry non-date values too, and must not raise."""
        for eol in (None, "", "false", True, "not-a-date"):
            with self.subTest(eol=eol):
                findings = XeolParser().get_findings(_report_with_eol(eol), Test())
                self.assertEqual(findings[0].severity, "Info")
