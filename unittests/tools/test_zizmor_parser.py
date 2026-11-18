import io
import json

from dojo.models import Finding, Test, User
from dojo.tools.zizmor.parser import ZizmorParser
from unittests.dojo_test_case import DojoAPITestCase, DojoTestCase, get_unit_tests_scans_path, versioned_fixtures

# The sample reports were produced with zizmor 1.32.0, run from the root of a small repository of
# deliberately insecure workflows:
#   no_vuln.json, one_vuln.json:      zizmor --offline --format json .
#   many_vulns.json, same_line.json:  zizmor --offline --persona=auditor --format json .
# same_line.json has two template-injection results on one line and an undocumented-permissions result
# with two primary locations.


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
        self.assertEqual(1, finding.nb_occurences)
        self.assertEqual(6, finding.scanner_confidence)  # zizmor confidence Low
        self.assertNotIn("**Occurrences:**", finding.description)
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
            self.assertIn("**Flagged expression:** `github.event.comment.body`", finding.description)
            self.assertEqual(2, finding.scanner_confidence)  # zizmor confidence High
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

    def test_parse_same_line(self):
        findings = self.parse("same_line.json")
        # six results; the two template-injection results on line 18 become one finding
        self.assertEqual(5, len(findings))
        self.assertEqual(5, len({(f.vuln_id_from_tool, f.file_path, f.line) for f in findings}))
        self.assertEqual([1, 1, 1, 2, 1], [f.nb_occurences for f in findings])

        with self.subTest(i=3):
            finding = findings[3]
            self.assertEqual("template-injection", finding.vuln_id_from_tool)
            self.assertEqual(".github/workflows/greet.yml", finding.file_path)
            self.assertEqual(18, finding.line)
            self.assertEqual("High", finding.severity)
            self.assertEqual(2, finding.scanner_confidence)
            self.assertEqual("- replace expression with environment variable", finding.mitigation)
            self.assertIn("**Occurrences:** 2", finding.description)
            self.assertIn("**Occurrence 1**", finding.description)
            self.assertIn("**Occurrence 2**", finding.description)
            self.assertIn("**Flagged expression:** `github.event.pull_request.title`", finding.description)
            self.assertIn("**Flagged expression:** `github.event.pull_request.head.ref`", finding.description)
            self.assertEqual(1, finding.description.count("**Documentation and remediation:**"))
        with self.subTest(i=4):
            # every primary location is listed, the first one gives the line
            finding = findings[4]
            self.assertEqual("undocumented-permissions", finding.vuln_id_from_tool)
            self.assertEqual("Low", finding.severity)
            self.assertEqual(7, finding.line)
            self.assertIn("**Location:** .github/workflows/greet.yml:7 (permissions.pull-requests)", finding.description)
            self.assertIn("**Location:** .github/workflows/greet.yml:8 (permissions.issues)", finding.description)
            self.assertEqual(2, finding.description.count("**Detail:** needs an explanatory comment"))

    def test_merged_occurrences_take_highest_severity_and_confidence(self):
        with (get_unit_tests_scans_path("zizmor") / "same_line.json").open(encoding="utf-8") as testfile:
            report = json.load(testfile)
        same_line = [item for item in report if item["ident"] == "template-injection"]
        same_line[0]["determinations"].update({"severity": "Low", "confidence": "Low"})
        findings = ZizmorParser().get_findings(io.StringIO(json.dumps(same_line)), Test())
        self.assertEqual(1, len(findings))
        self.assertEqual("High", findings[0].severity)
        self.assertEqual(2, findings[0].scanner_confidence)
        self.assertIn("**Severity:** Low", findings[0].description)

    def test_code_fence_is_escaped(self):
        with (get_unit_tests_scans_path("zizmor") / "one_vuln.json").open(encoding="utf-8") as testfile:
            report = json.load(testfile)
        report[0]["locations"][0]["concrete"]["feature"] = "run: echo ```"
        findings = ZizmorParser().get_findings(io.StringIO(json.dumps(report)), Test())
        self.assertIn("run: echo \\`\\`\\`", findings[0].description)
        self.assertEqual(2, findings[0].description.count("```"))

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


@versioned_fixtures
class TestZizmorImportReimport(DojoAPITestCase):

    """Import a report with two results on one line and reimport it: nothing may be marked duplicate or closed."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        # run deduplication synchronously, so duplicates are marked before the assertions
        admin = User.objects.get(username="admin")
        admin.usercontactinfo.block_execution = True
        admin.usercontactinfo.save()
        self.login_as_admin()

    def test_reimport_same_report_closes_nothing(self):
        imported = self.import_scan_with_params("scans/zizmor/same_line.json", scan_type="zizmor Scan", minimum_severity="Info")
        test_id = imported["test"]
        findings = Finding.objects.filter(test_id=test_id)
        self.assertEqual(5, findings.count())
        self.assertEqual(0, findings.filter(duplicate=True).count())
        self.assertEqual(5, findings.values("hash_code").distinct().count())

        reimported = self.reimport_scan_with_params(
            test_id, str(get_unit_tests_scans_path("zizmor") / "same_line.json"), scan_type="zizmor Scan", minimum_severity="Info",
        )
        delta = reimported["statistics"]["delta"]
        self.assertEqual(0, delta["created"]["total"]["total"])
        self.assertEqual(0, delta["closed"]["total"]["total"])
        self.assertEqual(5, delta["untouched"]["total"]["total"])
        self.assertEqual(5, Finding.objects.filter(test_id=test_id, active=True, duplicate=False).count())
