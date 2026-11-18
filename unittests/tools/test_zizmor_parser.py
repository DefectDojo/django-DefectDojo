import io
import json

from dojo.models import Finding, Test
from dojo.tools.zizmor.parser import ZizmorParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path

# The sample reports were produced with zizmor 1.32.0, run from the root of a small repository of
# deliberately insecure workflows:
#   no_vuln.json, one_vuln.json: zizmor --offline --format json .
#   many_vulns.json:             zizmor --offline --persona=auditor --format json .


class TestZizmorParser(DojoTestCase):

    def parse(self, filename):
        with (get_unit_tests_scans_path("zizmor") / filename).open(encoding="utf-8") as testfile:
            return ZizmorParser().get_findings(testfile, Test())

    def test_parse_no_findings(self):
        findings = self.parse("no_vuln.json")
        self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        findings = self.parse("one_vuln.json")
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("Credential persistence through GitHub Actions artifacts", finding.title)
        self.assertEqual("Medium", finding.severity)
        self.assertEqual("artipacked", finding.vuln_id_from_tool)
        self.assertEqual(".github/workflows/ci.yml", finding.file_path)
        self.assertEqual(13, finding.line)
        self.assertEqual("https://docs.zizmor.sh/audits/#artipacked", finding.references)
        self.assertEqual("- set persist-credentials: false", finding.mitigation)
        self.assertTrue(finding.fix_available)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        self.assertIsNone(finding.service)
        self.assertIn("**Audit:** artipacked: credential persistence through GitHub Actions artifacts", finding.description)
        self.assertIn("**Confidence:** Low", finding.description)
        self.assertIn("**Location:** .github/workflows/ci.yml:13 (jobs.test.steps[0])", finding.description)
        self.assertIn("**Detail:** does not set persist-credentials: false", finding.description)
        self.assertIn("uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2", finding.description)
        self.assertIn("**Documentation and remediation:** https://docs.zizmor.sh/audits/#artipacked", finding.description)

    def test_parse_many_findings(self):
        findings = self.parse("many_vulns.json")
        self.assertEqual(35, len(findings))
        for finding in findings:
            with self.subTest(title=finding.title, line=finding.line):
                self.assertIn(finding.severity, Finding.SEVERITIES)
                self.assertTrue(finding.vuln_id_from_tool)
                self.assertTrue(finding.file_path.startswith(".github/workflows/"))
                self.assertIsNotNone(finding.line)
        self.assertEqual(
            {"Info": 4, "Low": 5, "Medium": 13, "High": 13},
            {severity: sum(1 for f in findings if f.severity == severity) for severity in ("Info", "Low", "Medium", "High")},
        )
        # every finding in the report has its own deduplication key
        self.assertEqual(35, len({(f.vuln_id_from_tool, f.file_path, f.line) for f in findings}))

        with self.subTest(i=3):
            finding = findings[3]
            self.assertEqual("Code injection via template expansion", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual("template-injection", finding.vuln_id_from_tool)
            self.assertEqual(".github/workflows/comment.yml", finding.file_path)
            self.assertEqual(13, finding.line)
            self.assertIsNone(finding.mitigation)
            self.assertFalse(finding.fix_available)
            self.assertIn("**Detail:** may expand into attacker-controllable code", finding.description)
            self.assertIn('console.log("${{ github.event.comment.body }}")', finding.description)
            self.assertIn("**Related locations:**", finding.description)
            self.assertIn("- .github/workflows/comment.yml:10 (jobs.respond.steps[0].uses): action accepts arbitrary code", finding.description)
            # hidden locations are not listed
            self.assertNotIn("this step", finding.description)
        with self.subTest(i=5):
            finding = findings[5]
            self.assertEqual("Info", finding.severity)
            self.assertEqual("anonymous-definition", finding.vuln_id_from_tool)
            self.assertIn("**Persona:** Pedantic", finding.description)
        with self.subTest(i=6):
            finding = findings[6]
            self.assertEqual("Low", finding.severity)
            self.assertEqual("concurrency-limits", finding.vuln_id_from_tool)
            self.assertEqual(2, finding.line)
        with self.subTest(i=10):
            finding = findings[10]
            self.assertEqual("Runs on a self-hosted runner", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(".github/workflows/lint.yml", finding.file_path)
            self.assertEqual(6, finding.line)
            self.assertIn("**Persona:** Auditor", finding.description)
        with self.subTest(i=31):
            finding = findings[31]
            self.assertEqual("cache-poisoning", finding.vuln_id_from_tool)
            self.assertEqual("High", finding.severity)
            self.assertEqual(".github/workflows/release.yml", finding.file_path)
            self.assertEqual(11, finding.line)
            self.assertEqual("- Set lookup-only: true to disable caching", finding.mitigation)
            self.assertTrue(finding.fix_available)
            self.assertEqual("https://docs.zizmor.sh/audits/#cache-poisoning", finding.references)

    def test_parse_remote_input(self):
        # "zizmor owner/repo" audits a repository through the GitHub API, and locations then carry a
        # Remote key. The sample is the real one_vuln.json report with its key swapped for the shape
        # zizmor serializes for remote inputs.
        with (get_unit_tests_scans_path("zizmor") / "one_vuln.json").open(encoding="utf-8") as testfile:
            report = json.load(testfile)
        remote_key = {"Remote": {"slug": {"owner": "example-org", "repo": "example-repo", "git_ref": None}, "path": ".github/workflows/ci.yml"}}
        for location in report[0]["locations"]:
            location["symbolic"]["key"] = remote_key
        findings = ZizmorParser().get_findings(io.StringIO(json.dumps(report)), Test())
        self.assertEqual(1, len(findings))
        self.assertEqual(".github/workflows/ci.yml", findings[0].file_path)
        self.assertEqual(13, findings[0].line)
        self.assertEqual("example-org/example-repo", findings[0].service)
        self.assertIn("**Location:** example-org/example-repo: .github/workflows/ci.yml:13", findings[0].description)

    def test_parse_ignored_finding(self):
        # with --no-ignores zizmor also reports findings silenced by an ignore comment, flagged as ignored
        with (get_unit_tests_scans_path("zizmor") / "one_vuln.json").open(encoding="utf-8") as testfile:
            report = json.load(testfile)
        report[0]["ignored"] = True
        findings = ZizmorParser().get_findings(io.StringIO(json.dumps(report)), Test())
        self.assertEqual(1, len(findings))
        self.assertIn("**Ignored:**", findings[0].description)

    def test_parse_invalid_files(self):
        for content in ("not json", '{"findings": []}', '[{"desc": "no ident"}]', "[1, 2]"):
            with self.subTest(content=content), self.assertRaises(ValueError):
                ZizmorParser().get_findings(io.StringIO(content), Test())
