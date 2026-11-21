import io
import json

from dojo.models import Finding, Test
from dojo.tools.poutine.parser import PoutineParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path

# The sample reports were produced with poutine 1.1.6, run from the root of a small repository of
# deliberately insecure workflows: poutine analyze_local . --format json --quiet


class TestPoutineParser(DojoTestCase):

    def parse(self, filename):
        with (get_unit_tests_scans_path("poutine") / filename).open(encoding="utf-8") as testfile:
            return PoutineParser().get_findings(testfile, Test())

    def test_parse_no_findings(self):
        findings = self.parse("no_vuln.json")
        self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        findings = self.parse("one_vuln.json")
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("Unverified Script Execution", finding.title)
        self.assertEqual("Info", finding.severity)  # rule level "note"
        self.assertEqual("unverified_script_exec", finding.vuln_id_from_tool)
        self.assertEqual(".github/workflows/build.yml", finding.file_path)
        self.assertEqual(12, finding.line)
        self.assertEqual("https://boostsecurityio.github.io/poutine/rules/unverified_script_exec", finding.references)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        self.assertIsNone(finding.service)
        self.assertEqual([], finding.unsaved_vulnerability_ids or [])
        self.assertTrue(finding.description.startswith("The pipeline executes a script or binary fetched from a remote"))
        self.assertIn("**Rule:** unverified_script_exec", finding.description)
        self.assertIn("**Details:** Command: curl -sSL https://example.com/install.sh | bash", finding.description)
        self.assertIn("**Location:** .github/workflows/build.yml:12", finding.description)
        self.assertIn("**Job:** build", finding.description)
        self.assertIn("**Step:** 0", finding.description)
        self.assertIn("**Event triggers:** push", finding.description)
        self.assertIn("**Documentation and remediation:** https://boostsecurityio.github.io/poutine/rules/unverified_script_exec", finding.description)

    def test_parse_many_findings(self):
        findings = self.parse("many_vulns.json")
        self.assertEqual(13, len(findings))
        for finding in findings:
            with self.subTest(title=finding.title, file_path=finding.file_path, line=finding.line):
                self.assertIn(finding.severity, Finding.SEVERITIES)
                self.assertTrue(finding.vuln_id_from_tool)
                self.assertTrue(finding.file_path.startswith(".github/workflows/"))
        self.assertEqual(
            {"Info": 3, "Medium": 8, "High": 2},
            {severity: sum(1 for f in findings if f.severity == severity) for severity in ("Info", "Medium", "High")},
        )
        # every finding in the report has its own deduplication key
        self.assertEqual(13, len({(f.vuln_id_from_tool, f.file_path, f.line) for f in findings}))

        with self.subTest(i=2):
            finding = findings[2]
            self.assertEqual("Arbitrary Code Execution from Untrusted Code Changes", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual("untrusted_checkout_exec", finding.vuln_id_from_tool)
            self.assertEqual(".github/workflows/pr-title.yml", finding.file_path)
            self.assertEqual(14, finding.line)
            self.assertIn("**Living-off-the-pipeline tool:** make", finding.description)
            self.assertIn("**Living-off-the-pipeline targets:** Makefile", finding.description)
            self.assertIn("**Event triggers:** pull_request_target", finding.description)
        with self.subTest(i=3):
            finding = findings[3]
            self.assertEqual("Build Component with a Known Vulnerability used", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("known_vulnerability_in_build_component", finding.vuln_id_from_tool)
            self.assertEqual(".github/workflows/lint.yml", finding.file_path)
            self.assertEqual(11, finding.line)
            self.assertEqual(["GHSA-mcph-m25j-8j63"], finding.unsaved_vulnerability_ids)
            self.assertEqual(
                "https://boostsecurityio.github.io/poutine/rules/known_vulnerability_in_build_component\nhttps://osv.dev/",
                finding.references,
            )
            self.assertIn("**Advisory:** GHSA-mcph-m25j-8j63", finding.description)
        with self.subTest(i=6):
            finding = findings[6]
            self.assertEqual("injection", finding.vuln_id_from_tool)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(".github/workflows/release.yml", finding.file_path)
            self.assertEqual(16, finding.line)
            self.assertIn("**Injection sources:** github.head_ref", finding.description)
            self.assertIn("**Referenced secrets:** DEPLOY_TOKEN", finding.description)
        with self.subTest(i=9):
            # workflow-level finding: poutine gives no line
            finding = findings[9]
            self.assertEqual("default_permissions_on_risky_events", finding.vuln_id_from_tool)
            self.assertEqual(".github/workflows/comment.yml", finding.file_path)
            self.assertIsNone(finding.line)
            self.assertIn("**Location:** .github/workflows/comment.yml\n", finding.description)
        with self.subTest(i=11):
            finding = findings[11]
            self.assertEqual("If condition always evaluates to true", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual(7, finding.line)

    def test_parse_remote_repository(self):
        # analyze_repo and analyze_org identify each repository by a purl such as pkg:github/owner/repo.
        # The sample is the real one_vuln.json report with its local purl swapped for a remote one.
        with (get_unit_tests_scans_path("poutine") / "one_vuln.json").open(encoding="utf-8") as testfile:
            report = json.load(testfile)
        report["findings"][0]["purl"] = "pkg:github/example-org/example-repo"
        findings = PoutineParser().get_findings(io.StringIO(json.dumps(report)), Test())
        self.assertEqual(1, len(findings))
        self.assertEqual("example-org/example-repo", findings[0].service)
        self.assertIn("**Repository:** pkg:github/example-org/example-repo", findings[0].description)

    def test_parse_lotp_action(self):
        # untrusted_checkout_exec names the living-off-the-pipeline action when the code runs through one
        with (get_unit_tests_scans_path("poutine") / "many_vulns.json").open(encoding="utf-8") as testfile:
            report = json.load(testfile)
        finding = report["findings"][2]
        del finding["meta"]["lotp_tool"]
        finding["meta"]["lotp_action"] = "pre-commit/action"
        report["findings"] = [finding]
        findings = PoutineParser().get_findings(io.StringIO(json.dumps(report)), Test())
        self.assertIn("**Living-off-the-pipeline action:** pre-commit/action", findings[0].description)
        self.assertNotIn("**Living-off-the-pipeline tool:**", findings[0].description)

    def test_parse_unknown_rule(self):
        # a finding whose rule is missing from the rules section still imports, with the rule id as title
        report = {"findings": [{"rule_id": "new_rule", "purl": "pkg:localrepo/localrepo/local?repository_url=.", "meta": {"path": ".github/workflows/ci.yml", "line": 3}}], "rules": {}}
        findings = PoutineParser().get_findings(io.StringIO(json.dumps(report)), Test())
        self.assertEqual(1, len(findings))
        self.assertEqual("new_rule", findings[0].title)
        self.assertEqual("Info", findings[0].severity)
        self.assertEqual(3, findings[0].line)

    def test_parse_invalid_files(self):
        for content in ("not json", "[]", '{"rules": {}}', '{"findings": {}}'):
            with self.subTest(content=content), self.assertRaises(ValueError):
                PoutineParser().get_findings(io.StringIO(content), Test())
