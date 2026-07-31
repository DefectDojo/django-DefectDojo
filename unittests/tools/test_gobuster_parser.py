import io

from dojo.models import Finding, Test
from dojo.tools.gobuster.parser import GobusterParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestGobusterParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("gobuster") / filename).open(encoding="utf-8") as file:
            return list(GobusterParser().get_findings(file, Test()))

    def test_scan_type_metadata(self):
        parser = GobusterParser()
        self.assertEqual(["Gobuster Scan"], parser.get_scan_types())
        self.assertEqual("Gobuster Scan", parser.get_label_for_scan_types("Gobuster Scan"))
        self.assertIn("gobuster dir", parser.get_description_for_scan_types("Gobuster Scan"))

    def test_no_vuln(self):
        """Gobuster writes an empty file when nothing is found, which must parse rather than raise."""
        self.assertEqual(0, len(self.parse("gobuster_no_vuln.txt")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("gobuster_one_vuln.txt")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, from a real `gobuster dir -o` run against a local target."""
        findings = self.parse("gobuster_one_vuln.txt")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("HTTP 301: /admin", finding.title)
        self.assertEqual("Info", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertTrue(finding.dynamic_finding)
        self.assertFalse(finding.static_finding)

        self.assertIn("**Path:** /admin", finding.description)
        self.assertIn("**Status:** 301", finding.description)
        self.assertIn("**Response size:** 169", finding.description)
        self.assertIn("**Redirects to:** http://wave3target/admin/", finding.description)

    def test_many_vuln(self):
        findings = self.parse("gobuster_many_vuln.txt")
        self.assertEqual(5, len(findings))
        self.assertEqual(
            [
                "HTTP 200: /index.html",
                "HTTP 200: /robots.txt",
                "HTTP 301: /.git",
                "HTTP 301: /admin",
                "HTTP 301: /backup",
            ],
            sorted(finding.title for finding in findings),
        )

    def test_severity_is_info_because_discovery_is_not_a_weakness(self):
        findings = self.parse("gobuster_many_vuln.txt")
        self.assertEqual({"Info"}, {finding.severity for finding in findings})

    def test_the_scanned_host_is_not_invented(self):
        """
        Gobuster's hit lines carry the path but NOT the host it was scanning.

        A redirect target is the only absolute URL available, so an endpoint is set when a hit
        redirects and not otherwise - guessing a host for the rest would be wrong. The description
        says so rather than leaving a reader to wonder where the host went.
        """
        findings = self.parse("gobuster_many_vuln.txt")
        redirecting = [f for f in findings if f.unsaved_endpoints]
        direct = [f for f in findings if not f.unsaved_endpoints]

        self.assertEqual(3, len(redirecting))  # /.git, /admin, /backup
        self.assertEqual(2, len(direct))       # /robots.txt, /index.html
        for finding in findings:
            self.assertIn("does not record the scanned host", finding.description)

    def test_a_hit_with_no_redirect_has_no_endpoint(self):
        findings = self.parse("gobuster_many_vuln.txt")
        robots = next(f for f in findings if f.title == "HTTP 200: /robots.txt")
        self.assertEqual([], robots.unsaved_endpoints)
        self.assertNotIn("**Redirects to:**", robots.description)

    def test_the_banner_is_not_imported(self):
        """
        Without -q gobuster prints a banner and a progress footer into the same file.

        A user who forgets -q would otherwise import the banner as findings.
        """
        report = io.StringIO(
            "===============================================================\n"
            "Gobuster v3.8.2\n"
            "by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)\n"
            "===============================================================\n"
            "[+] Url:                     http://target.example.com/\n"
            "[+] Method:                  GET\n"
            "[+] Threads:                 10\n"
            "===============================================================\n"
            "Starting gobuster in directory enumeration mode\n"
            "===============================================================\n"
            "admin                (Status: 301) [Size: 169]\n"
            "===============================================================\n"
            "Finished\n"
            "===============================================================\n",
        )
        findings = list(GobusterParser().get_findings(report, Test()))
        self.assertEqual(1, len(findings))
        self.assertEqual("HTTP 301: /admin", findings[0].title)

    def test_dns_and_vhost_mode_output_is_not_imported(self):
        """
        Gobuster's dns and vhost modes write "Found: name" - subdomain and virtual-host inventory.

        A discovered subdomain is not a weakness, so those lines are deliberately skipped and the
        required Status group is what identifies a dir-mode hit. An earlier version accepted them
        and titled the finding "Discovered: Found:", which is worse than not importing them.
        """
        report = io.StringIO(
            "Found: admin.target.example.com\n"
            "Found: staging.target.example.com\n",
        )
        self.assertEqual([], list(GobusterParser().get_findings(report, Test())))

    def test_a_leading_slash_is_not_doubled(self):
        report = io.StringIO("/already-absolute  (Status: 200) [Size: 5]\n")
        finding = list(GobusterParser().get_findings(report, Test()))[0]
        self.assertEqual("HTTP 200: /already-absolute", finding.title)

    def test_duplicate_hits_collapse(self):
        report = io.StringIO(
            "admin                (Status: 301) [Size: 169]\n"
            "admin                (Status: 301) [Size: 169]\n",
        )
        self.assertEqual(1, len(list(GobusterParser().get_findings(report, Test()))))

    def test_bytes_input(self):
        report = io.BytesIO(b"admin                (Status: 301) [Size: 169]\n")
        self.assertEqual(1, len(list(GobusterParser().get_findings(report, Test()))))

    def test_empty_report(self):
        self.assertEqual([], list(GobusterParser().get_findings(io.StringIO(""), Test())))
