"""
Parsers emit ``LocationData.code`` for source-code findings under V3.

Mirrors how dependency emission (PR #14395) is exercised: parse a real report
fixture, then assert the findings carry code ``LocationData`` in
``unsaved_locations`` that matches the finding's own coordinates. A gate-off
class proves the emission is completely inert without V3_FEATURE_LOCATIONS.
"""

from django.test import override_settings

from dojo.models import Test
from dojo.tools.bandit.parser import BanditParser
from dojo.tools.brakeman.parser import BrakemanParser
from dojo.tools.gitleaks.parser import GitleaksParser
from dojo.tools.gosec.parser import GosecParser
from dojo.tools.huskyci.parser import HuskyCIParser
from dojo.tools.sarif.parser import SarifParser
from dojo.tools.semgrep.parser import SemgrepParser
from dojo.tools.tfsec.parser import TFSecParser
from dojo.tools.whispers.parser import WhispersParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path

# (parser class, scans dir, fixture) — fixtures known to produce static findings
PARSER_FIXTURES = [
    (BanditParser, "bandit", "many_vulns.json"),
    (BrakemanParser, "brakeman", "many_findings.json"),
    (GitleaksParser, "gitleaks", "gitleaks8_many.json"),
    (GosecParser, "gosec", "many_vulns.json"),
    (HuskyCIParser, "huskyci", "huskyci_report_many_finding_one_tool.json"),
    (SarifParser, "sarif", "appendix_k.sarif"),
    (SemgrepParser, "semgrep", "close_old_findings_report_line31.json"),
    (TFSecParser, "tfsec", "many_findings_current.json"),
    (WhispersParser, "whispers", "whispers_many_vul.json"),
]


def _parse(parser_class, scans_dir, fixture):
    with (get_unit_tests_scans_path(scans_dir) / fixture).open(encoding="utf-8") as testfile:
        return parser_class().get_findings(testfile, Test())


def _code_locations(finding):
    return [
        location
        for location in getattr(finding, "unsaved_locations", [])
        if getattr(location, "type", None) == "code"
    ]


@override_settings(V3_FEATURE_LOCATIONS=True)
class TestCodeLocationEmission(DojoTestCase):

    """Every converted parser emits code locations coherent with its scalars."""

    def test_parsers_emit_code_locations(self):
        for parser_class, scans_dir, fixture in PARSER_FIXTURES:
            with self.subTest(parser=parser_class.__name__):
                findings = _parse(parser_class, scans_dir, fixture)
                emitting = [f for f in findings if _code_locations(f)]
                self.assertTrue(
                    emitting,
                    f"{parser_class.__name__} produced no code LocationData for {fixture}",
                )
                for finding in emitting:
                    for location in _code_locations(finding):
                        self.assertTrue(location.data["file_path"], "code location must carry a file path")
                        line = location.data.get("line")
                        self.assertTrue(
                            line is None or isinstance(line, int),
                            f"line must be int or None, got {line!r}",
                        )

    def test_emitted_identity_matches_finding_scalars(self):
        """
        The finding's own file_path/line and the emitted location agree —
        the scalars stay the single source the location machinery derives from.
        """
        findings = _parse(SemgrepParser, "semgrep", "close_old_findings_report_line31.json")
        self.assertEqual(1, len(findings))
        finding = findings[0]
        locations = _code_locations(finding)
        self.assertEqual(1, len(locations))
        self.assertEqual(finding.file_path, locations[0].data["file_path"])
        self.assertEqual(31, locations[0].data["line"])
        self.assertEqual(finding.line, locations[0].data["line"])

    def test_snippet_context_rides_along_when_extracted(self):
        """Parsers that already extract a code snippet pass it as context."""
        findings = _parse(BanditParser, "bandit", "many_vulns.json")
        snippets = [
            location.data.get("snippet")
            for finding in findings
            for location in _code_locations(finding)
        ]
        self.assertTrue(any(snippets), "bandit extracts code blocks; at least one snippet expected")

    def test_sarif_emits_per_location_with_region_context(self):
        """
        The SARIF parser explodes multi-location results into one finding per
        location; each finding carries its own code location.
        """
        findings = _parse(SarifParser, "sarif", "appendix_k.sarif")
        emitting = [f for f in findings if f.file_path]
        self.assertTrue(emitting)
        for finding in emitting:
            locations = _code_locations(finding)
            self.assertEqual(1, len(locations))
            self.assertEqual(finding.file_path, locations[0].data["file_path"])


@override_settings(V3_FEATURE_LOCATIONS=False)
class TestCodeLocationEmissionGateOff(DojoTestCase):

    """Without V3 the emission is inert: no code locations, scalars untouched."""

    def test_no_code_locations_without_v3(self):
        for parser_class, scans_dir, fixture in PARSER_FIXTURES:
            with self.subTest(parser=parser_class.__name__):
                findings = _parse(parser_class, scans_dir, fixture)
                self.assertTrue(findings, f"fixture must still parse: {fixture}")
                for finding in findings:
                    self.assertEqual([], _code_locations(finding))
