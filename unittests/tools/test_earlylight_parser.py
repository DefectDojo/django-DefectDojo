import io
import json

from dojo.models import Finding, Test
from dojo.tools.earlylight.parser import EarlylightParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path

# The sample reports in unittests/scans/earlylight are real `earlylight scan ... --format json`
# output from Early Light main at 19c2e24 (after v0.3.1), trimmed to a few findings each with every
# "skipped" list cut to two entries:
#   no_findings.json   scan fs on a directory with one text file (path renamed to /srv/app)
#   one_vuln.json      scan image php:8.3.0-cli, one finding kept
#   many_vulns.json    scan image php:8.3.0-cli, five of its nine findings kept
#   needs_review.json  scan image --detector php2shell trafex/php-nginx:2.0.1
#   cleared_only.json  scan image --detector php2shell php:8.3.36-cli
#   many_targets.json  scan image --detector php2shell,brotli php:8.3.36-cli trafex/php-nginx:2.0.1 node:20.0.0-slim
#   repo.json          scan repo on a source tree with two Dockerfiles and a Compose file


class TestEarlylightParser(DojoTestCase):

    def parse(self, filename):
        with (get_unit_tests_scans_path("earlylight") / filename).open(encoding="utf-8") as testfile:
            return EarlylightParser().get_findings(testfile, Test())

    def test_scan_type(self):
        parser = EarlylightParser()
        self.assertEqual(["Early Light Scan"], parser.get_scan_types())
        self.assertEqual("Early Light Scan", parser.get_label_for_scan_types("Early Light Scan"))
        self.assertIn("--format json", parser.get_description_for_scan_types("Early Light Scan"))

    def test_no_findings(self):
        self.assertEqual(0, len(self.parse("no_findings.json")))

    def test_cleared_findings_are_skipped(self):
        # four fixed php2shell findings and nothing else
        self.assertEqual(0, len(self.parse("cleared_only.json")))

    def test_one_vuln(self):
        findings = self.parse("one_vuln.json")
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("php2shell/php-runtime-web: PHP 8.3.0 (cgi-fcgi)", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertEqual("php2shell/php-runtime-web", finding.vuln_id_from_tool)
        self.assertEqual(["CVE-2026-109618", "CVE-2026-109619"], finding.unsaved_vulnerability_ids)
        self.assertEqual(["earlylight"], finding.unsaved_tags)
        self.assertEqual("/usr/local/bin/php-cgi", finding.file_path)
        self.assertIsNone(finding.line)
        self.assertEqual(416, finding.cwe)
        self.assertEqual("php", finding.component_name)
        self.assertEqual("8.3.0", finding.component_version)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        self.assertTrue(finding.fix_available)
        self.assertEqual(
            "Rebuild on PHP 8.3.36 or later (for the official Docker image, a php:8.3.36 tag), then redeploy.",
            finding.mitigation,
        )
        self.assertEqual(
            "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w\n"
            "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp",
            finding.references,
        )
        self.assertEqual("fc2cb38cd56257fb9c612aaff9a054e2c21aabd180dd317bdd618e9ec96b240e", finding.unique_id_from_tool)
        self.assertIn("**Verdict:** vulnerable", finding.description)
        self.assertIn("**Target:** php:8.3.0-cli (image, sha256:33b1f2a2edaa92c73b41cbb078e8c1abce9b4ebe41af870415c6361830667da7, linux/amd64)", finding.description)
        self.assertIn("**Path:** /usr/local/bin/php-cgi", finding.description)
        self.assertIn("**Method:** elf-strings", finding.description)
        self.assertIn("- sapi: cgi-fcgi", finding.description)
        self.assertIn("- CVE-2026-109618: vulnerable (PHP 8.3.0 is below the fixed release 8.3.36)", finding.description)
        self.assertNotIn("needs-review", finding.unsaved_tags)

    def test_many_vulns(self):
        findings = self.parse("many_vulns.json")
        self.assertEqual(5, len(findings))
        for finding in findings:
            self.assertIn(finding.severity, Finding.SEVERITIES)
            self.assertEqual(["earlylight"], finding.unsaved_tags)
            self.assertEqual(64, len(finding.unique_id_from_tool))
            self.assertIn("**Target:** php:8.3.0-cli", finding.description)
        self.assertEqual(5, len({f.unique_id_from_tool for f in findings}))

        with self.subTest(kind="brotli/decoder-library"):
            finding = findings[0]
            self.assertEqual("brotli/decoder-library", finding.vuln_id_from_tool)
            self.assertEqual("Critical", finding.severity)  # from the kind's 9.2 score
            self.assertEqual(["CVE-2026-111497"], finding.unsaved_vulnerability_ids)
            self.assertEqual("libbrotlidec", finding.component_name)
            self.assertIsNone(finding.component_version)
            self.assertEqual(252, finding.cwe)
            self.assertEqual("/usr/lib/x86_64-linux-gnu/libbrotlidec.so.1.0.9", finding.file_path)
            self.assertIn("https://github.com/advisories/GHSA-9v8h-qqgm-4m35", finding.references)

        with self.subTest(kind="emudhra/path-root"):
            # two CAs in one bundle: same kind and path, told apart by the certificate
            first, second = findings[1], findings[2]
            for finding in (first, second):
                self.assertEqual("emudhra/path-root", finding.vuln_id_from_tool)
                self.assertEqual("High", finding.severity)  # level error, no score
                self.assertEqual("/etc/ssl/certs/ca-certificates.crt", finding.file_path)
                # the detector names CVE-2026-111943, but the trust finding itself has none
                self.assertIsNone(finding.unsaved_vulnerability_ids)
                self.assertEqual(0, finding.cwe)  # Finding default: no CWE
                self.assertIsNone(finding.mitigation)
                self.assertFalse(finding.fix_available)
                self.assertEqual("https://bugzilla.mozilla.org/show_bug.cgi?id=2083449", finding.references)
            self.assertNotEqual(first.unique_id_from_tool, second.unique_id_from_tool)
            self.assertIn("AAA Certificate Services", first.title)
            self.assertIn("- spki_sha256: BD153ED7B0434F6886B17BCE8BBE84ED340C7132D702A8F4FA318F756ECBD6F3", first.description)

        with self.subTest(kind="php2shell/php-runtime-cli"):
            finding = findings[3]
            self.assertEqual("php2shell/php-runtime-cli", finding.vuln_id_from_tool)
            self.assertEqual("High", finding.severity)  # the finding's own "high"
            self.assertEqual(["CVE-2026-109618", "CVE-2026-109619"], finding.unsaved_vulnerability_ids)
            self.assertEqual("/usr/local/bin/php", finding.file_path)

    def test_unique_id_is_stable(self):
        first = [f.unique_id_from_tool for f in self.parse("many_vulns.json")]
        second = [f.unique_id_from_tool for f in self.parse("many_vulns.json")]
        self.assertEqual(first, second)
        # the same PHP binary found in a report of a different size keeps its id
        one = self.parse("one_vuln.json")[0]
        self.assertIn(one.unique_id_from_tool, first)

    def test_needs_review(self):
        findings = self.parse("needs_review.json")
        self.assertEqual(2, len(findings))
        for finding in findings:
            self.assertEqual(["earlylight", "needs-review"], finding.unsaved_tags)
            self.assertEqual(["CVE-2026-109618", "CVE-2026-109619"], finding.unsaved_vulnerability_ids)
            self.assertIn("**Needs review:** Early Light could not settle this finding.", finding.description)
            self.assertIn(
                "this tool has no fix data for that package stream, and the vendor may have backported the fix",
                finding.description,
            )
            self.assertIn("- CVE-2026-109618: unknown (installed by php8", finding.description)
            self.assertIn("**Target:** trafex/php-nginx:2.0.1 (image,", finding.description)
            self.assertNotIn("**Verdict:** vulnerable", finding.description)
        cli, web = findings
        # severity "review" is not a severity: the kind's table entry decides
        self.assertEqual("High", cli.severity)
        self.assertEqual("Critical", web.severity)
        self.assertEqual("php2shell/php-runtime-web", web.vuln_id_from_tool)
        # the installing OS package is the component
        self.assertEqual("php8-fpm", web.component_name)
        self.assertEqual("8.0.2-r0", web.component_version)
        self.assertEqual(
            "Check the security advisories for php8 on Alpine Linux v3.13 and upgrade the package if a fix is listed.",
            web.mitigation,
        )

    def test_many_targets(self):
        findings = self.parse("many_targets.json")
        # php:8.3.36-cli: five fixed, skipped. trafex/php-nginx:2.0.1: two unknown, one vulnerable.
        # node:20.0.0-slim: one vulnerable.
        self.assertEqual(4, len(findings))
        self.assertEqual(
            ["php2shell/php-runtime-cli", "php2shell/php-runtime-web", "brotli/decoder-library", "brotli/bundled-decoder"],
            [f.vuln_id_from_tool for f in findings],
        )
        self.assertEqual(
            [["earlylight", "needs-review"], ["earlylight", "needs-review"], ["earlylight"], ["earlylight"]],
            [f.unsaved_tags for f in findings],
        )
        node = findings[3]
        self.assertIn("**Target:** node:20.0.0-slim (image,", node.description)
        self.assertEqual("Critical", node.severity)
        self.assertEqual("node", node.component_name)
        self.assertEqual("20.0.0", node.component_version)
        self.assertEqual("/usr/local/bin/node", node.file_path)
        self.assertEqual(["CVE-2026-111497"], node.unsaved_vulnerability_ids)
        self.assertEqual("Node.js 20 has no fixed release: move to 22.23.4, 24.22.1 or 26.12.1.", node.mitigation)
        brotli = findings[2]
        self.assertIn("**Target:** trafex/php-nginx:2.0.1", brotli.description)
        self.assertEqual("/usr/lib/libbrotlidec.so.1.0.9", brotli.file_path)

    def test_repo(self):
        findings = self.parse("repo.json")
        self.assertEqual(2, len(findings))
        node_pin, php_image = findings

        self.assertEqual("brotli/node-pin", node_pin.vuln_id_from_tool)
        self.assertEqual("app/Dockerfile", node_pin.file_path)
        self.assertEqual(1, node_pin.line)
        self.assertEqual("Critical", node_pin.severity)
        self.assertEqual(["CVE-2026-111497"], node_pin.unsaved_vulnerability_ids)
        self.assertIn("**Target:** repo (repository)", node_pin.description)
        self.assertIn("**Path:** app/Dockerfile:1", node_pin.description)
        self.assertIsNone(node_pin.component_name)

        self.assertEqual("php2shell/php-image", php_image.vuln_id_from_tool)
        self.assertEqual("web/Dockerfile", php_image.file_path)
        self.assertEqual(1, php_image.line)
        self.assertEqual("Critical", php_image.severity)
        self.assertEqual("php2shell/php-image: image php:8.3.0-fpm", php_image.title)
        # php-image findings carry no CVE list in the report
        self.assertIsNone(php_image.unsaved_vulnerability_ids)

    def test_severity_rules(self):
        report = {
            "tool": "earlylight",
            "version": "test",
            "detectors": [],
            "targets": [{
                "target": "example.com:443",
                "type": "host",
                "findings": [
                    {"detector": "emudhra", "kind": "unpatched-go", "path": "example.com:443", "verdict": "vulnerable", "message": "m"},
                    {"detector": "brotli", "kind": "go-port", "path": "/app", "verdict": "vulnerable", "message": "m", "severity": "low"},
                    {"detector": "future", "kind": "thing", "path": "/a", "verdict": "vulnerable", "message": "m"},
                    {"detector": "future", "kind": "thing", "path": "/b", "verdict": "unknown", "message": "m", "severity": "review"},
                    {"detector": "future", "kind": "thing", "path": "/c", "verdict": "managed", "message": "m"},
                    {"detector": "future", "kind": "thing", "path": "/d", "verdict": "inactive", "message": "m"},
                ],
            }],
        }
        findings = EarlylightParser().get_findings(io.StringIO(json.dumps(report)), Test())
        self.assertEqual(["Medium", "Low", "High", "Medium"], [f.severity for f in findings])
        self.assertTrue(findings[0].dynamic_finding)
        self.assertFalse(findings[0].static_finding)
        self.assertIsNone(findings[0].references)

    def test_reported_kinds_win_over_the_table(self):
        report = {
            "detectors": [{"id": "brotli", "kinds": [
                {"id": "go-port", "title": "t", "level": "warning", "severity": "7.1"},
                {"id": "not-checked", "title": "t", "level": "note"},
            ]}, {"id": "future", "kinds": [{"id": "thing", "title": "t", "level": "error", "severity": "3.0"}]}],
            "targets": [{"target": "/srv", "type": "filesystem", "findings": [
                {"detector": "brotli", "kind": "go-port", "path": "/a", "verdict": "vulnerable", "message": "m"},
                {"detector": "brotli", "kind": "not-checked", "path": "/b", "verdict": "vulnerable", "message": "m"},
                {"detector": "future", "kind": "thing", "path": "/c", "verdict": "vulnerable", "message": "m"},
                {"detector": "future", "kind": "thing", "path": "/d", "verdict": "vulnerable", "message": "m", "severity": "critical"},
            ]}],
        }
        findings = EarlylightParser().get_findings(io.StringIO(json.dumps(report)), Test())
        self.assertEqual(["High", "Info", "Low", "Critical"], [f.severity for f in findings])
        self.assertEqual(252, findings[0].cwe)

    def test_identical_findings_get_distinct_ids(self):
        item = {"detector": "brotli", "kind": "dependency", "path": "requirements.txt", "verdict": "vulnerable", "message": "m"}
        report = {"detectors": [], "targets": [{"target": "src", "type": "repository", "findings": [item, dict(item, line=9)]}]}
        findings = EarlylightParser().get_findings(io.StringIO(json.dumps(report)), Test())
        self.assertEqual(2, len({f.unique_id_from_tool for f in findings}))

    def test_bytes_input(self):
        with (get_unit_tests_scans_path("earlylight") / "one_vuln.json").open("rb") as testfile:
            findings = EarlylightParser().get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

    def test_invalid_input(self):
        with self.assertRaises(ValueError):
            EarlylightParser().get_findings(io.StringIO("not json"), Test())
        with self.assertRaises(ValueError):
            EarlylightParser().get_findings(io.StringIO('{"runs": []}'), Test())
