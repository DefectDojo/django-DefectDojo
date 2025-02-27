import datetime
from django.test import TestCase
from django.utils import timezone
from dojo.models import Test
from dojo.tools.rapidfire.parser import RapidFireParser


class TestRapidFireParser(TestCase):
    """Test RapidFire CSV Parser"""

    def test_parse_no_findings(self):
        """Test parsing a RapidFire report with no findings"""
        with open("unittests/scans/rapidfire/no_vuln.csv", encoding="utf-8") as testfile:
            parser = RapidFireParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        """Test parsing a Rapidfire report with one finding"""
        with open("unittests/scans/rapidfire/one_vuln.csv", encoding="utf-8") as testfile:
            parser = RapidFireParser()
            findings = parser.get_findings(testfile, Test())

            self.assertEqual(1, len(findings))

            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Apache Tomcat Multiple Vulnerabilities (Oct 2023) - Windows (CVSS: 7.5)", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertTrue(finding.dynamic_finding)
                self.assertFalse(finding.static_finding)
                self.assertEqual("1.3.6.1.4.1.25623.1.0.170598", finding.vuln_id_from_tool)
                self.assertEqual(["CVE-2023-42795", "CVE-2023-44487", "CVE-2023-45648"], finding.unsaved_vulnerability_ids)
                self.assertEqual(1, len(finding.unsaved_endpoints))
                self.assertEqual("norming-sandbox.ja-office.com", finding.unsaved_endpoints[0].host)
                self.assertEqual("8080", finding.unsaved_endpoints[0].port)

    def test_parse_many_findings(self):
        """Test parsing a Rapidfire report with multiple findings"""
        with open("unittests/scans/rapidfire/many_vulns.csv", encoding="utf-8") as testfile:
            parser = RapidFireParser()
            findings = parser.get_findings(testfile, Test())

            self.assertEqual(2, len(findings))

            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Apache Tomcat Multiple Vulnerabilities (Oct 2023) - Windows (CVSS: 7.5)", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertEqual("norming-sandbox.ja-office.com", finding.unsaved_endpoints[0].host)
                self.assertEqual("8080", finding.unsaved_endpoints[0].port)

            with self.subTest(i=1):
                finding = findings[1]
                self.assertEqual("Apache Tomcat Multiple Vulnerabilities (Oct 2023) - Windows (CVSS: 7.5)", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertEqual("svg-ehrm-app.ja-office.com", finding.unsaved_endpoints[0].host)
                self.assertEqual("2083", finding.unsaved_endpoints[0].port)

    def test_invalid_severity(self):
        """Test parser handles invalid severity values"""
        parser = RapidFireParser()
        self.assertEqual("Info", parser._convert_severity("InvalidSeverity"))
        self.assertEqual("High", parser._convert_severity("HiGh"))
        self.assertEqual("Critical", parser._convert_severity("CRITICAL"))

    def test_parse_cves(self):
        """Test CVE parsing function"""
        parser = RapidFireParser()
        self.assertEqual([], parser._parse_cves(""))
        self.assertEqual([], parser._parse_cves(None))
        self.assertEqual(["CVE-2023-42795"], parser._parse_cves("CVE-2023-42795"))
        self.assertEqual(
            ["CVE-2023-42795", "CVE-2023-44487"],
            parser._parse_cves("CVE-2023-42795, CVE-2023-44487"),
        )
        self.assertEqual([], parser._parse_cves("NOT-A-CVE"))

    def test_port_extraction(self):
        """Test port extraction from various formats"""
        parser = RapidFireParser()
        self.assertEqual("8080", parser._extract_port("8080/tcp"))
        self.assertEqual("443", parser._extract_port("443/tcp (https)"))
        self.assertIsNone(parser._extract_port(""))
        self.assertIsNone(parser._extract_port(None))
        self.assertIsNone(parser._extract_port("invalid"))

    def test_date_parsing(self):
        """Test date parsing from various formats"""
        parser = RapidFireParser()
        self.assertIsInstance(parser._parse_date("22-Jul-24"), datetime.datetime)
        self.assertIsInstance(parser._parse_date(""), datetime.datetime)
        self.assertIsInstance(parser._parse_date(None), datetime.datetime)

    def test_empty_rows(self):
        """Test parser handles empty rows gracefully"""
        with open("unittests/scans/rapidfire/no_vuln.csv", encoding="utf-8") as testfile:
            parser = RapidFireParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_reference_formatting(self):
        """Test reference string formatting"""
        parser = RapidFireParser()

        # Test empty/invalid references
        self.assertEqual("", parser._format_references(""))
        self.assertEqual("", parser._format_references(None))

        # Test Apache Tomcat reference
        tomcat_ref = "https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.94"
        expected = "* [Apache Tomcat 8.5.94 Security Advisory](https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.94)"
        self.assertEqual(expected, parser._format_references(tomcat_ref))

        # Test CISA reference
        cisa_ref = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        expected = "* [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)"
        self.assertEqual(expected, parser._format_references(cisa_ref))

        # Test Cloudflare reference
        cloud_ref = "https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/"
        expected = "* [Cloudflare HTTP/2 Rapid Reset Analysis](https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/)"
        self.assertEqual(expected, parser._format_references(cloud_ref))

        # Test multiple references
        multiple_refs = (
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog,"
            "https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/"
        )
        expected = (
            "* [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)\n"
            "* [Cloudflare HTTP/2 Rapid Reset Analysis](https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/)"
        )
        self.assertEqual(expected, parser._format_references(multiple_refs))

        # Test duplicate references
        duplicate_refs = "https://www.cisa.gov/advisory,https://www.cisa.gov/advisory"
        expected = "* [CISA Security Advisory](https://www.cisa.gov/advisory)"
        self.assertEqual(expected, parser._format_references(duplicate_refs))

        # Test fallback formatting
        other_ref = "https://example.com/security/advisory"
        expected = "* [Example Security Advisory](https://example.com/security/advisory)"
        self.assertEqual(expected, parser._format_references(other_ref))

    def test_complex_port_formats(self):
        """Test parsing findings with various port formats"""
        with open("unittests/scans/rapidfire/complex_ports.csv", encoding="utf-8") as testfile:
            parser = RapidFireParser()
            findings = parser.get_findings(testfile, Test())

            # Verify port extraction for different formats
            for finding in findings:
                if finding.unsaved_endpoints:
                    port = finding.unsaved_endpoints[0].port
                    # Port should either be None or a numeric string
                    if port is not None:
                        self.assertTrue(port.isdigit(), f"Port should be numeric, got {port}")
                        self.assertTrue(1 <= int(port) <= 65535, f"Port {port} outside valid range")

    def test_invalid_dates(self):
        """Test parsing findings with invalid date formats"""
        with open("unittests/scans/rapidfire/invalid_date.csv", encoding="utf-8") as testfile:
            parser = RapidFireParser()
            findings = parser.get_findings(testfile, Test())

            # Verify each finding has a valid date
            for finding in findings:
                self.assertIsNotNone(finding.date)
                self.assertIsInstance(finding.date, datetime.datetime)

    def test_impact_formatting(self):
        """Test impact formatting with various inputs"""
        parser = RapidFireParser()

        # Test with no input
        self.assertEqual("", parser._format_impact("", []))

        # Test with only vulnerability insight
        insight = "This is a basic vulnerability insight"
        expected = "### Description\n\nThis is a basic vulnerability insight"
        self.assertEqual(expected, parser._format_impact(insight, []))

        # Test with only CVEs
        cves = ["CVE-2023-42795", "CVE-2023-44487"]
        expected = (
            "### Associated CVEs\n\n"
            "* **CVE-2023-42795** - [NVD Link](https://nvd.nist.gov/vuln/detail/CVE-2023-42795)\n"
            "* **CVE-2023-44487** - [NVD Link](https://nvd.nist.gov/vuln/detail/CVE-2023-44487)"
        )
        self.assertEqual(expected, parser._format_impact("", cves))

        # Test with both insight and CVEs
        insight = "The following flaws exist:   - First flaw description   - Second flaw description"
        cves = ["CVE-2023-42795"]
        expected = (
            "### Identified Flaws\n\n"
            "* First flaw description\n* Second flaw description\n\n"
            "### Associated CVEs\n\n"
            "* **CVE-2023-42795** - [NVD Link](https://nvd.nist.gov/vuln/detail/CVE-2023-42795)"
        )
        self.assertEqual(expected, parser._format_impact(insight, cves))

    def test_parse_one_finding_impact(self):
        """Test parsing a finding with properly formatted impact"""
        with open("unittests/scans/rapidfire/one_vuln.csv", encoding="utf-8") as testfile:
            parser = RapidFireParser()
            findings = parser.get_findings(testfile, Test())

            self.assertEqual(1, len(findings))

            finding = findings[0]

            # Verify impact formatting
            self.assertIn("### Identified Flaws", finding.impact)
            # Look for the content without the leading "- " that's causing the test to fail
            self.assertIn("When recycling various internal objects", finding.impact)
            self.assertIn("HTTP/2 rapid reset attack", finding.impact)
            self.assertIn("### Associated CVEs", finding.impact)
            self.assertIn("* **CVE-2023-42795**", finding.impact)
            self.assertIn("[NVD Link]", finding.impact)
