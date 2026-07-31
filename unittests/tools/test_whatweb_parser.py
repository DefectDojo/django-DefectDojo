import io
import json

from dojo.models import Finding, Test
from dojo.tools.whatweb.parser import WhatWebParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestWhatWebParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("whatweb") / filename).open(encoding="utf-8") as file:
            return list(WhatWebParser().get_findings(file, Test()))

    def test_scan_type_metadata(self):
        parser = WhatWebParser()
        self.assertEqual(["WhatWeb Scan"], parser.get_scan_types())
        self.assertEqual("WhatWeb Scan", parser.get_label_for_scan_types("WhatWeb Scan"))
        self.assertIn("whatweb --log-json", parser.get_description_for_scan_types("WhatWeb Scan"))

    def test_no_vuln(self):
        """An unreachable target yields an empty array, which is the only clean WhatWeb report."""
        self.assertEqual(0, len(self.parse("whatweb_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("whatweb_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, from a real `whatweb --log-json` run against a local target."""
        findings = self.parse("whatweb_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Technologies identified: http://wave3target/", finding.title)
        self.assertEqual("Info", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertTrue(finding.dynamic_finding)
        self.assertFalse(finding.static_finding)
        self.assertEqual(1, len(finding.unsaved_endpoints))

        self.assertIn("**Status:** 200", finding.description)
        self.assertIn("- HTTPServer: string nginx/1.31.3", finding.description)
        self.assertIn("- nginx: version 1.31.3", finding.description)
        self.assertIn("- MetaGenerator: string generic-app 1.4.2", finding.description)

    def test_one_finding_per_target_not_per_plugin(self):
        """
        WhatWeb fingerprints anything it can reach - even a 404 page yields five plugins.

        A finding per plugin would flood DefectDojo and, worse, would report WhatWeb's own network
        metadata as though the site were running it. The technologies are listed together under the
        URL that has them: three scanned URLs give three findings, not eighteen.
        """
        with (get_unit_tests_scans_path("whatweb") / "whatweb_many_vuln.json").open(
            encoding="utf-8",
        ) as file:
            report = json.load(file)
        self.assertEqual(3, len(report))
        self.assertEqual(18, sum(len(entry["plugins"]) for entry in report))

        self.assertEqual(3, len(self.parse("whatweb_many_vuln.json")))

    def test_network_metadata_is_separated_from_technologies(self):
        """
        IP and Country describe the network WhatWeb reached over, not the technology stack.

        They are still reported, under their own heading, so nobody reads "Country: RESERVED" as
        something the target is running.
        """
        finding = self.parse("whatweb_one_vuln.json")[0]
        self.assertIn("**Technologies (5):**", finding.description)
        self.assertIn("**Network:**", finding.description)

        technologies, network = finding.description.split("**Network:**")
        self.assertNotIn("Country", technologies)
        self.assertNotIn("IP:", technologies)
        self.assertIn("- Country: string RESERVED; module ZZ", network)
        self.assertIn("- IP: string 172.29.0.2", network)

    def test_severity_is_info_because_fingerprinting_is_inventory(self):
        findings = self.parse("whatweb_many_vuln.json")
        self.assertEqual({"Info"}, {finding.severity for finding in findings})

    def test_many_vuln_targets(self):
        findings = self.parse("whatweb_many_vuln.json")
        self.assertEqual(
            [
                "Technologies identified: http://wave3target/",
                "Technologies identified: http://wave3target/admin/",
                "Technologies identified: http://wave3target/robots.txt",
            ],
            sorted(finding.title for finding in findings),
        )

    def test_a_plugin_with_no_matched_fields(self):
        """A bare detection - HTML5 declares no version or string - is still reported."""
        finding = self.parse("whatweb_one_vuln.json")[0]
        self.assertIn("- HTML5\n", finding.description + "\n")

    def test_plugin_fields_are_rendered_in_order(self):
        report = io.StringIO(json.dumps([{
            "target": "http://target.example.com/",
            "http_status": 200,
            "plugins": {"Thing": {"string": ["s"], "version": ["1.2"], "module": ["m"]}},
        }]))
        finding = list(WhatWebParser().get_findings(report, Test()))[0]
        self.assertIn("- Thing: version 1.2; string s; module m", finding.description)

    def test_entry_without_a_target(self):
        report = io.StringIO(json.dumps([{"http_status": 200, "plugins": {}}]))
        finding = list(WhatWebParser().get_findings(report, Test()))[0]
        self.assertEqual("Technologies identified", finding.title)
        self.assertEqual([], finding.unsaved_endpoints)

    def test_entry_without_plugins(self):
        report = io.StringIO(json.dumps([{"target": "http://target.example.com/"}]))
        finding = list(WhatWebParser().get_findings(report, Test()))[0]
        self.assertNotIn("**Technologies", finding.description)
        self.assertNotIn("**Network:**", finding.description)

    def test_wrong_shape_is_rejected(self):
        with self.assertRaises(TypeError):
            list(WhatWebParser().get_findings(io.StringIO('{"targets": []}'), Test()))
        with self.assertRaises(TypeError):
            list(WhatWebParser().get_findings(io.StringIO("[1]"), Test()))
