from os import path
from ..dojo_test_case import DojoTestCase
from dojo.tools.tenable.parser import TenableParser
from dojo.models import Finding, Test, Engagement, Product


class TestTenableParser(DojoTestCase):
    def create_test(self):
        test = Test()
        test.engagement = Engagement()
        test.engagement.product = Product()
        return test

    def test_parse_some_findings_nessus_legacy(self):
        testfile = open(path.join(path.dirname(__file__), "../scans/tenable/nessus/nessus_many_vuln.xml"))
        parser = TenableParser()
        findings = parser.get_findings(testfile, self.create_test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(6, len(findings))
        finding = findings[5]
        self.assertEqual("Info", finding.severity)
        self.assertIsNone(finding.cwe)
        endpoint = finding.unsaved_endpoints[0]
        self.assertEqual("https", endpoint.protocol)
        endpoint = finding.unsaved_endpoints[1]
        self.assertEqual("tcp", endpoint.protocol)

    def test_parse_some_findings_csv_nessus_legacy(self):
        """Test one report provided by a user"""
        testfile = open(path.join(path.dirname(__file__), "../scans/tenable/nessus/nessus_many_vuln.csv"))
        parser = TenableParser()
        findings = parser.get_findings(testfile, self.create_test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(4, len(findings))
        for i in [0, 1, 2, 3]:
            finding = findings[i]
            self.assertIn(finding.severity, Finding.SEVERITIES)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(0, finding.cwe)
        # check some data
        finding = findings[0]
        self.assertEqual(1, len(finding.unsaved_endpoints))
        self.assertEqual("10.1.1.1", finding.unsaved_endpoints[0].host)
        self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N/E:P/RL:O/RC:C", finding.cvssv3)
        # TODO work on component attributes for Nessus CSV parser
        self.assertIsNotNone(finding.component_name)
        self.assertEqual("md5", finding.component_name)
        self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2004-2761", finding.unsaved_vulnerability_ids[0])
        # this vuln have 'CVE-2013-2566,CVE-2015-2808' as CVE
        finding = findings[3]
        print(f"finding.unsaved_vulnerability_ids: {finding.unsaved_vulnerability_ids} - {type(finding.unsaved_vulnerability_ids)} - {type(finding.unsaved_vulnerability_ids[0])}")
        self.assertEqual(2, len(finding.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2013-2566", finding.unsaved_vulnerability_ids[0])
        self.assertEqual("CVE-2015-2808", finding.unsaved_vulnerability_ids[1])

    def test_parse_some_findings_csv2_nessus_legacy(self):
        """Test that use default columns of Nessus Pro 8.13.1 (#257)"""
        testfile = open(path.join(path.dirname(__file__), "../scans/tenable/nessus/nessus_many_vuln2-default.csv"))
        parser = TenableParser()
        findings = parser.get_findings(testfile, self.create_test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(29, len(findings))
        finding = findings[0]
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("Info", finding.severity)
        self.assertFalse(finding.unsaved_vulnerability_ids)
        self.assertEqual(0, finding.cwe)
        self.assertEqual("HTTP Server Type and Version", finding.title)
        finding = findings[25]
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("SSL Certificate Signed Using Weak Hashing Algorithm (Known CA)", finding.title)
        self.assertEqual("Info", finding.severity)
        self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2004-2761", finding.unsaved_vulnerability_ids[0])

    def test_parse_some_findings_csv2_all_nessus_legacy(self):
        """Test that use a report with all columns of Nessus Pro 8.13.1 (#257)"""
        testfile = open(path.join(path.dirname(__file__), "../scans/tenable/nessus/nessus_many_vuln2-all.csv"))
        parser = TenableParser()
        findings = parser.get_findings(testfile, self.create_test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(29, len(findings))
        finding = findings[0]
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("Info", finding.severity)
        self.assertFalse(finding.unsaved_vulnerability_ids)
        self.assertEqual(0, finding.cwe)
        self.assertEqual("HTTP Server Type and Version", finding.title)
        finding = findings[25]
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("SSL Certificate Signed Using Weak Hashing Algorithm (Known CA)", finding.title)
        self.assertEqual("Info", finding.severity)
        self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2004-2761", finding.unsaved_vulnerability_ids[0])

    def test_parse_some_findings_csv_bytes_nessus_legacy(self):
        """This tests is designed to test the parser with different read modes"""
        testfile = open(path.join(path.dirname(__file__), "../scans/tenable/nessus/nessus_many_vuln2-all.csv"))
        parser = TenableParser()
        findings = parser.get_findings(testfile, self.create_test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        testfile = open(path.join(path.dirname(__file__), "../scans/tenable/nessus/nessus_many_vuln2-all.csv"), "rt")
        parser = TenableParser()
        findings = parser.get_findings(testfile, self.create_test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        testfile = open(path.join(path.dirname(__file__), "../scans/tenable/nessus/nessus_many_vuln2-all.csv"), "rb")
        parser = TenableParser()
        findings = parser.get_findings(testfile, self.create_test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()

    def test_parse_some_findings_samples_nessus_legacy(self):
        """Test that come from samples repo"""
        testfile = open(path.join(path.dirname(__file__), "../scans/tenable/nessus/nessus_v_unknown.xml"))
        parser = TenableParser()
        findings = parser.get_findings(testfile, self.create_test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(32, len(findings))

        finding = findings[0]
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("Info", finding.severity)
        self.assertFalse(finding.unsaved_vulnerability_ids)
        self.assertEqual("Nessus Scan Information", finding.title)

        finding = findings[25]
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("Nessus SYN scanner", finding.title)
        self.assertEqual("Info", finding.severity)
        self.assertFalse(finding.unsaved_vulnerability_ids)
        endpoint = finding.unsaved_endpoints[26]
        self.assertEqual("http", endpoint.protocol)
        endpoint = finding.unsaved_endpoints[37]
        self.assertEqual("tcp", endpoint.protocol)

        finding = findings[9]
        self.assertEqual(7, len(finding.unsaved_vulnerability_ids))
        for vulnerability_id in finding.unsaved_vulnerability_ids:
            self.assertEqual('CVE-2005-1794', vulnerability_id)

    def test_parse_some_findings_with_cvssv3_nessus_legacy(self):
        """test with cvssv3"""
        testfile = open(path.join(path.dirname(__file__), "../scans/tenable/nessus/nessus_with_cvssv3.nessus"))
        parser = TenableParser()
        findings = parser.get_findings(testfile, self.create_test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(48, len(findings))
        finding = findings[3]
        self.assertEqual("Medium", finding.severity)
        self.assertIsNone(finding.cwe)
        endpoint = finding.unsaved_endpoints[0]
        self.assertEqual("http", endpoint.protocol)
        self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", finding.cvssv3)

    def test_parse_many_findings_xml_nessus_was_legacy(self):
        testfile = open("unittests/scans/tenable/nessus_was/nessus_was_many_vuln.xml")
        parser = TenableParser()
        findings = parser.get_findings(testfile, self.create_test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(5, len(findings))
        for i in [0, 1, 2, 3, 4]:
            finding = findings[i]
            self.assertEqual('http', finding.unsaved_endpoints[0].protocol)
            self.assertIsNone(finding.cwe)
        finding = findings[0]
        self.assertEqual('High', finding.severity)
        self.assertEqual('Cross-Site Scripting (XSS)', finding.title)

    def test_parse_one_findings_xml_nessus_was_legacy(self):
        testfile = open("unittests/scans/tenable/nessus_was/nessus_was_one_vuln.xml")
        parser = TenableParser()
        findings = parser.get_findings(testfile, self.create_test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual('http', finding.unsaved_endpoints[0].protocol)
        self.assertIsNone(finding.cwe)
        self.assertEqual('High', finding.severity)
        self.assertEqual('Cross-Site Scripting (XSS)', finding.title)

    def test_parse_no_findings_xml_nessus_was_legacy(self):
        testfile = open("unittests/scans/tenable/nessus_was/nessus_was_no_vuln.xml")
        parser = TenableParser()
        findings = parser.get_findings(testfile, self.create_test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(0, len(findings))

    def test_parse_many_findings_csv_nessus_was_legacy(self):
        testfile = open("unittests/scans/tenable/nessus_was/nessus_was_many_vuln.csv")
        parser = TenableParser()
        findings = parser.get_findings(testfile, self.create_test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(5, len(findings))
        for i in [0, 1, 2, 3, 4]:
            finding = findings[i]
            self.assertIn(finding.severity, Finding.SEVERITIES)
            self.assertEqual('google.com', finding.unsaved_endpoints[0].host)
            self.assertFalse(finding.unsaved_vulnerability_ids)
        finding = findings[0]
        self.assertEqual('7.1', finding.cvssv3_score)
        self.assertEqual('High', finding.severity)
        self.assertEqual('http', finding.unsaved_endpoints[0].protocol)

    def test_parse_one_findings_csv_nessus_was_legacy(self):
        testfile = open("unittests/scans/tenable/nessus_was/nessus_was_one_vuln.csv")
        parser = TenableParser()
        findings = parser.get_findings(testfile, self.create_test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual('google.com', finding.unsaved_endpoints[0].host)
        self.assertFalse(finding.unsaved_vulnerability_ids)
        self.assertEqual('7.1', finding.cvssv3_score)
        self.assertEqual('High', finding.severity)
        self.assertEqual('http', finding.unsaved_endpoints[0].protocol)

    def test_parse_no_findings_csv_nessus_was_legacy(self):
        testfile = open("unittests/scans/tenable/nessus_was/nessus_was_no_vuln.csv")
        parser = TenableParser()
        findings = parser.get_findings(testfile, self.create_test())
        self.assertEqual(0, len(findings))

    def test_parse_many_tenable_vulns(self):
        testfile = open("unittests/scans/tenable/tenable_many_vuln.csv")
        parser = TenableParser()
        findings = parser.get_findings(testfile, self.create_test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(9, len(findings))
        finding = findings[0]
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual('High', finding.severity)
        self.assertEqual('ip-127-0-0-1.us-west-2.compute.internal', finding.unsaved_endpoints[0].host)
        self.assertEqual('Amazon Linux 2 : kernel (ALAS-2023-2050)', finding.title)
        self.assertEqual('tcp', finding.unsaved_endpoints[0].protocol)
        self.assertEqual(None, finding.unsaved_endpoints[0].port)
        self.assertIn('https://alas.aws.amazon.com/AL2/ALAS-2023-2050.html', finding.references)
        self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
        for vulnerability_id in finding.unsaved_vulnerability_ids:
            self.assertEqual('CVE-2023-32233', vulnerability_id)
