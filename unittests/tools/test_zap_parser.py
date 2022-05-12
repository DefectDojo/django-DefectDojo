from ..dojo_test_case import DojoTestCase
from dojo.models import Test, Finding
from dojo.tools.zap.parser import ZapParser


class TestZapParser(DojoTestCase):
    def test_parse_no_findings(self):
        testfile = open("unittests/scans/zap/empty_2.9.0.xml")
        parser = ZapParser()
        findings = parser.get_findings(testfile, Test())
        self.assertIsInstance(findings, list)
        self.assertEqual(0, len(findings))

    def test_parse_some_findings(self):
        testfile = open("unittests/scans/zap/some_2.9.0.xml")
        parser = ZapParser()
        findings = parser.get_findings(testfile, Test())
        self.assertIsInstance(findings, list)
        self.assertEqual(7, len(findings))
        for finding in findings:
            self.assertIn(finding.severity, Finding.SEVERITIES)
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()

    def test_parse_some_findings_0(self):
        testfile = open("unittests/scans/zap/0_zap_sample.xml")
        parser = ZapParser()
        findings = parser.get_findings(testfile, Test())
        self.assertIsInstance(findings, list)
        self.assertEqual(4, len(findings))
        for finding in findings:
            self.assertIn(finding.severity, Finding.SEVERITIES)
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()

    def test_parse_some_findings_1(self):
        testfile = open("unittests/scans/zap/1_zap_sample_0_and_new_absent.xml")
        parser = ZapParser()
        findings = parser.get_findings(testfile, Test())
        self.assertIsInstance(findings, list)
        self.assertEqual(4, len(findings))
        for finding in findings:
            self.assertIn(finding.severity, Finding.SEVERITIES)
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()

    def test_parse_some_findings_2(self):
        testfile = open("unittests/scans/zap/2_zap_sample_0_and_new_endpoint.xml")
        parser = ZapParser()
        findings = parser.get_findings(testfile, Test())
        self.assertIsInstance(findings, list)
        self.assertEqual(4, len(findings))
        for finding in findings:
            self.assertIn(finding.severity, Finding.SEVERITIES)
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()

    def test_parse_some_findings_3(self):
        testfile = open("unittests/scans/zap/3_zap_sampl_0_and_different_severities.xml")
        parser = ZapParser()
        findings = parser.get_findings(testfile, Test())
        self.assertIsInstance(findings, list)
        self.assertEqual(4, len(findings))
        for finding in findings:
            self.assertIn(finding.severity, Finding.SEVERITIES)
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()

    def test_parse_some_findings_5(self):
        testfile = open("unittests/scans/zap/5_zap_sample_one.xml")
        parser = ZapParser()
        findings = parser.get_findings(testfile, Test())
        self.assertIsInstance(findings, list)
        self.assertEqual(2, len(findings))
        for finding in findings:
            self.assertIn(finding.severity, Finding.SEVERITIES)
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()

    def test_parse_issue4360(self):
        """Report from GitHub issue 4360
        see: https://github.com/DefectDojo/django-DefectDojo/issues/4360
        """
        testfile = open("unittests/scans/zap/dvwa_baseline_dojo.xml")
        parser = ZapParser()
        findings = parser.get_findings(testfile, Test())
        self.assertIsInstance(findings, list)
        self.assertEqual(19, len(findings))
        for finding in findings:
            self.assertIn(finding.severity, Finding.SEVERITIES)
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("X-Frame-Options Header Not Set", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("10020", finding.vuln_id_from_tool)
            self.assertEqual(11, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual("172.17.0.2", endpoint.host)
            self.assertEqual(80, endpoint.port)
            endpoint = finding.unsaved_endpoints[1]
            self.assertEqual("http", endpoint.protocol)
            self.assertEqual("172.17.0.2", endpoint.host)
            self.assertEqual("vulnerabilities/sqli_blind/", endpoint.path)
        with self.subTest(i=18):
            finding = findings[18]
            self.assertEqual("Private IP Disclosure", finding.title)
            self.assertEqual("Low", finding.severity)
            self.assertEqual("2", finding.vuln_id_from_tool)
            self.assertEqual(3, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]

    def test_parse_issue4697(self):
        """Report from GitHub issue 4697
        see: https://github.com/DefectDojo/django-DefectDojo/issues/4697
        """
        testfile = open("unittests/scans/zap/zap-results-first-scan.xml")
        parser = ZapParser()
        findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertIsInstance(findings, list)
        self.assertEqual(15, len(findings))
        for finding in findings:
            self.assertIn(finding.severity, Finding.SEVERITIES)
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()

        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("User Controllable HTML Element Attribute (Potential XSS)", finding.title)
            self.assertEqual("Info", finding.severity)
            self.assertEqual("10031", finding.vuln_id_from_tool)
            self.assertEqual(11, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual("http", endpoint.protocol)
            self.assertEqual("bodgeit.securecodebox-demo.svc", endpoint.host)
            self.assertEqual(8080, endpoint.port)
            endpoint = finding.unsaved_endpoints[1]
            self.assertEqual("http", endpoint.protocol)
            self.assertEqual("bodgeit.securecodebox-demo.svc", endpoint.host)
            self.assertEqual("bodgeit/product.jsp", endpoint.path)
        with self.subTest(i=14):
            finding = findings[14]
            self.assertEqual("PII Disclosure", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual("10062", finding.vuln_id_from_tool)
            self.assertEqual(359, finding.cwe)
            self.assertEqual(1, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual("http", endpoint.protocol)
            self.assertEqual("bodgeit.securecodebox-demo.svc", endpoint.host)
            self.assertEqual("bodgeit/contact.jsp", endpoint.path)

    def test_parse_juicy(self):
        """Generated with OWASP Juicy shop"""
        testfile = open("unittests/scans/zap/juicy2.xml")
        parser = ZapParser()
        findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertIsInstance(findings, list)
        self.assertEqual(6, len(findings))
        for finding in findings:
            self.assertIn(finding.severity, Finding.SEVERITIES)
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()

        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("Incomplete or No Cache-control Header Set", finding.title)
            self.assertEqual("Low", finding.severity)
            self.assertEqual("10015", finding.vuln_id_from_tool)
            self.assertEqual(20, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual("https", endpoint.protocol)
            self.assertEqual("juice-shop.herokuapp.com", endpoint.host)
            self.assertEqual(443, endpoint.port)
            endpoint = finding.unsaved_endpoints[1]
            self.assertEqual("https", endpoint.protocol)
            self.assertEqual("juice-shop.herokuapp.com", endpoint.host)
            self.assertEqual("assets/public/polyfills-es2018.js", endpoint.path)
        with self.subTest(i=5):
            finding = findings[5]
            self.assertEqual("CSP: Wildcard Directive", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("10055", finding.vuln_id_from_tool)
            self.assertEqual(693, finding.cwe)
            self.assertEqual(2, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            self.assertEqual("https", endpoint.protocol)
            self.assertEqual("juice-shop.herokuapp.com", endpoint.host)
            self.assertEqual("assets", endpoint.path)
