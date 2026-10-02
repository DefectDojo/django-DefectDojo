import io
import json

from dojo.models import Finding, Test
from dojo.tools.dotnet_vulnerable.parser import DotnetVulnerableParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestDotnetVulnerableParser(DojoTestCase):
    def parse(self, filename):
        path = get_unit_tests_scans_path("dotnet_vulnerable") / filename
        with path.open(encoding="utf-8") as file:
            return list(DotnetVulnerableParser().get_findings(file, Test()))

    def test_scan_type_metadata(self):
        parser = DotnetVulnerableParser()
        self.assertEqual(["Dotnet Vulnerable Packages Scan"], parser.get_scan_types())
        self.assertEqual(
            "Dotnet Vulnerable Packages Scan",
            parser.get_label_for_scan_types("Dotnet Vulnerable Packages Scan"),
        )
        self.assertIn(
            "--include-transitive",
            parser.get_description_for_scan_types("Dotnet Vulnerable Packages Scan"),
        )

    def test_no_vuln(self):
        """
        A project with nothing vulnerable omits "frameworks" entirely.

        The projects list is still present, so the parser has to cope with a project that has no
        frameworks key rather than assuming an empty list.
        """
        content = (get_unit_tests_scans_path("dotnet_vulnerable")
                   / "dotnet_vulnerable_no_vuln.json").read_text(encoding="utf-8")
        self.assertIn('"projects"', content)
        self.assertNotIn('"frameworks"', content)

        self.assertEqual(0, len(self.parse("dotnet_vulnerable_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("dotnet_vulnerable_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, from a real `dotnet list package --vulnerable --format json` run."""
        findings = self.parse("dotnet_vulnerable_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual(
            "System.Text.RegularExpressions 4.3.0 has a known high-severity vulnerability",
            finding.title,
        )
        self.assertEqual("High", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("System.Text.RegularExpressions", finding.component_name)
        self.assertEqual("4.3.0", finding.component_version)
        self.assertEqual("GHSA-cmhx-cq75-c4mj", finding.vuln_id_from_tool)
        self.assertEqual(["GHSA-cmhx-cq75-c4mj"], finding.unsaved_vulnerability_ids)
        self.assertEqual(
            "https://github.com/advisories/GHSA-cmhx-cq75-c4mj", finding.references,
        )
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)

        self.assertIn("**Requested version:** 4.3.0", finding.description)
        self.assertIn("**Dependency:** direct", finding.description)
        self.assertIn("**Target framework:** net8.0", finding.description)

    def test_the_ghsa_is_taken_from_the_advisory_url(self):
        """
        The report carries no advisory id of its own, only "advisoryurl".

        The GHSA in that URL is the only public identifier available, so it is parsed out.
        """
        content = (get_unit_tests_scans_path("dotnet_vulnerable")
                   / "dotnet_vulnerable_one_vuln.json").read_text(encoding="utf-8")
        self.assertNotIn('"cve"', content)
        self.assertIn('"advisoryurl"', content)

        self.assertEqual(
            "GHSA-cmhx-cq75-c4mj", self.parse("dotnet_vulnerable_one_vuln.json")[0].vuln_id_from_tool,
        )

    def test_many_vuln_walks_both_direct_and_transitive_packages(self):
        """
        A vulnerable package is very often pulled in by something else, not referenced directly.

        Only "transitivePackages" names those, so both lists have to be walked. This fixture has
        two of each.
        """
        findings = self.parse("dotnet_vulnerable_many_vuln.json")
        self.assertEqual(4, len(findings))

        direct = {f.component_name for f in findings if "**Dependency:** direct" in f.description}
        transitive = {
            f.component_name for f in findings if "**Dependency:** transitive" in f.description
        }
        self.assertEqual({"Newtonsoft.Json", "System.Text.RegularExpressions"}, direct)
        self.assertEqual(
            {"System.Net.Http", "System.Security.Cryptography.X509Certificates"}, transitive,
        )

    def test_a_transitive_package_gets_actionable_mitigation(self):
        """
        A transitive package is not in the project file, so "upgrade it" is not actionable.

        The mitigation has to name the real options instead.
        """
        finding = next(
            f for f in self.parse("dotnet_vulnerable_many_vuln.json")
            if f.component_name == "System.Net.Http"
        )
        self.assertIn("transitive dependency", finding.mitigation)
        self.assertIn("Upgrade whichever direct dependency pulls it in", finding.mitigation)
        # A transitive entry carries no requestedVersion, so the description must not claim one.
        self.assertNotIn("**Requested version:**", finding.description)

    def test_severities_come_from_the_advisory(self):
        """Gate: NuGet advisory severities, never a level the parser picked."""
        severities = {f.severity for f in self.parse("dotnet_vulnerable_many_vuln.json")}
        self.assertEqual({"High"}, severities)
        self.assertNotIn("Info", severities)

    def test_moderate_maps_to_medium(self):
        report = io.StringIO(json.dumps({"projects": [{"path": "/x/s.csproj", "frameworks": [
            {"framework": "net8.0", "topLevelPackages": [{
                "id": "Pkg", "requestedVersion": "1.0.0", "resolvedVersion": "1.0.0",
                "vulnerabilities": [{"severity": "Moderate",
                                     "advisoryurl": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc"}],
            }]}]}]}))
        self.assertEqual("Medium", list(DotnetVulnerableParser().get_findings(report, Test()))[0].severity)

    def test_a_package_under_two_frameworks_is_one_finding(self):
        """Multi-targeting reports the same package once per framework; that is one problem."""
        package = {"id": "Pkg", "resolvedVersion": "1.0.0", "vulnerabilities": [
            {"severity": "High", "advisoryurl": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc"}]}
        report = io.StringIO(json.dumps({"projects": [{"path": "/x/s.csproj", "frameworks": [
            {"framework": "net8.0", "transitivePackages": [package]},
            {"framework": "net9.0", "transitivePackages": [package]},
        ]}]}))
        self.assertEqual(1, len(list(DotnetVulnerableParser().get_findings(report, Test()))))

    def test_an_advisory_url_without_a_ghsa_still_imports(self):
        report = io.StringIO(json.dumps({"projects": [{"frameworks": [
            {"framework": "net8.0", "topLevelPackages": [{
                "id": "Pkg", "resolvedVersion": "1.0.0",
                "vulnerabilities": [{"severity": "Low", "advisoryurl": "https://example.com/advisory/1"}],
            }]}]}]}))
        finding = list(DotnetVulnerableParser().get_findings(report, Test()))[0]
        self.assertIsNone(finding.vuln_id_from_tool)
        self.assertIsNone(finding.unsaved_vulnerability_ids)
        self.assertEqual("https://example.com/advisory/1", finding.references)

    def test_a_json_array_is_rejected_with_a_clear_message(self):
        with self.assertRaises(TypeError) as raised:
            list(DotnetVulnerableParser().get_findings(io.StringIO("[]"), Test()))
        self.assertIn("projects", str(raised.exception))
