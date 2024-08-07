from django.test import TestCase
from dojo.tools.appcheck_web_application_scanner.parser import AppCheckWebApplicationScannerParser
from dojo.models import Test


class TestAppCheckWebApplicationScannerParser(TestCase):

    def test_appcheck_web_application_scanner_parser_with_no_vuln_has_no_findings(self):
        with open("unittests/scans/appcheck_web_application_scanner/appcheck_web_application_scanner_zero_vul.json") as testfile:
            parser = AppCheckWebApplicationScannerParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_appcheck_web_application_scanner_parser_with_one_criticle_vuln_has_one_findings(self):
        with open("unittests/scans/appcheck_web_application_scanner/appcheck_web_application_scanner_one_vul.json") as testfile:
            parser = AppCheckWebApplicationScannerParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

            # OpenVAS engine
            finding = findings[0]
            self.assertEqual("c50f88e969225674a9a62abca23b15ac95a9cdb8", finding.unique_id_from_tool)
            self.assertEqual("FTP Unencrypted Cleartext Login", finding.title)
            self.assertEqual("2020-01-28T14:29:10.173000", finding.date)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(True, finding.active)
            self.assertEqual("[[markup]]Enable FTPS or enforce the connection via the 'AUTH TLS' command. Please see   the manual of the FTP service for more information.", finding.mitigation)
            self.assertIsNone(finding.unsaved_request)
            self.assertIsNone(finding.unsaved_response)
            self.assertIsNone(finding.component_name)
            self.assertIsNone(finding.component_version)
            self.assertIsNone(finding.unsaved_vulnerability_ids)
            self.assertTrue(
                finding.description.startswith(
                    "The remote host is running a FTP service that allows cleartext logins over\n  unencrypted connections."
                )
            )
            for section in ["**Impact**:", "**Detection**:", "**Technical Details**:"]:
                self.assertTrue(section in finding.description)

            self.assertEqual(1, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            endpoint.clean()
            self.assertEqual(21, endpoint.port)
            self.assertEqual("0.0.0.1", endpoint.host)

    def test_appcheck_web_application_scanner_parser_with_many_vuln_has_many_findings(self):
        with open("unittests/scans/appcheck_web_application_scanner/appcheck_web_application_scanner_many_vul.json") as testfile:
            parser = AppCheckWebApplicationScannerParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(5, len(findings))

            # First item is the same as the single-vuln entry (checked above); test the others here

            # NMap engine
            finding = findings[1]
            self.assertEqual("443bdee209aad337f6093e18aeb1532e751171ee", finding.unique_id_from_tool)
            self.assertEqual("Port Scan Report", finding.title)
            self.assertEqual("2020-01-28T14:20:50.887000", finding.date)
            self.assertEqual("Low", finding.severity)
            self.assertEqual(True, finding.active)
            self.assertIsNone(finding.unsaved_request)
            self.assertIsNone(finding.unsaved_response)
            self.assertIsNone(finding.mitigation)
            self.assertIsNone(finding.component_name)
            self.assertIsNone(finding.component_version)
            self.assertIsNone(finding.unsaved_vulnerability_ids)
            self.assertTrue(
                finding.description.startswith(
                    "The dedicated port scanner found open ports on this host, along with other\nhost-specific information, which can be viewed in Technical Details."
                )
            )
            self.assertTrue(
                "Host: 0.0.0.1 (0.0.0.1)\nHost is up, received user-set (0.015s latency).\nScanned at 2020-01-29 15:44:46 UTC for 15763s\nNot shown: 65527 filtered ports, 4 closed ports\nReason: 65527 no-responses and 4 resets\nSome closed ports may be reported as filtered due to --defeat-rst-ratelimit\nPORT      STATE SERVICE     REASON          VERSION\n21/tcp    open  ftp         syn-ack ttl 116 Microsoft ftpd\n45000/tcp open  ssl/asmp?   syn-ack ttl 116\n45010/tcp open  unknown     syn-ack ttl 116\n60001/tcp open  ssl/unknown syn-ack ttl 116\n60011/tcp open  unknown     syn-ack ttl 116\nService Info: OS: Windows; CPE: cpe:/o:microsoft:windows"
                in finding.description
            )

            expected_ports = [21, 45000, 45010, 60001, 60011]
            self.assertEqual(5, len(finding.unsaved_endpoints))
            for idx, endpoint in enumerate(finding.unsaved_endpoints):
                endpoint.clean()
                self.assertEqual("0.0.0.1", endpoint.host)
                self.assertEqual(expected_ports[idx], endpoint.port)

            # AppCheck proprietary (?) engine findings

            finding = findings[2]
            self.assertEqual("a25dae3aff97a06b6923b5fc9cc32826e1fd87ab", finding.unique_id_from_tool)
            self.assertEqual("Apache Tomcat < v9.0.0.M10 - External Control of Assumed-Immutable Web Parameter in JSP Servlet (CVE-2016-6796)", finding.title)
            self.assertEqual("2024-06-26T09:55:43.459000", finding.date)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(True, finding.active)
            self.assertEqual("GET Request ", finding.unsaved_request)
            self.assertEqual("Response", finding.unsaved_response)
            self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", finding.cvssv3)
            self.assertEqual("[[markup]]\n\nUpdate to the latest version.", finding.mitigation)
            self.assertEqual("tomcat", finding.component_name)
            self.assertEqual("8.0.32", finding.component_version)
            self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
            self.assertEqual("CVE-2016-6796", finding.unsaved_vulnerability_ids[0])
            self.assertTrue(finding.description.startswith("[[markup]]\n\n**Product Background**\n\n**Apache Tomcat** is a free and open-source Java web application server. It provides a \"pure Java\" HTTP web server environment in which Java code can also run, implementing the Jakarta Servlet, Jakarta Expression Language, and WebSocket technologies. Tomcat is released with **Catalina** (a servlet and JSP Java Server Pages container), **Coyote** (an HTTP connector), **Coyote JK** (JK protocol proxy connector) and **Jasper** (a JSP engine). Tomcat can optionally be bundled with Java Enterprise Edition (Jakarta EE) as **Apache TomEE** to deliver a complete application server with enterprise features such as distributed computing and web services.\n\n**Vulnerability Summary**\n\nA malicious web application running on Apache Tomcat 9.0.0.M1 to 9.0.0.M9, 8.5.0 to 8.5.4, 8.0.0.RC1 to 8.0.36, 7.0.0 to 7.0.70 and 6.0.0 to 6.0.45 was able to bypass a configured SecurityManager via manipulation of the configuration parameters for the JSP Servlet.\n\n**References**\n\n* [[http://www.securitytracker.com/id/1038757]]\n\n* [[http://www.securitytracker.com/id/1037141]]\n\n* [[http://www.securityfocus.com/bid/93944]]\n\n* [[http://www.debian.org/security/2016/dsa-3720]]\n\n* [[https://access.redhat.com/errata/RHSA-2017:2247]]\n\n* [[https://access.redhat.com/errata/RHSA-2017:1552]]\n\n* [[https://access.redhat.com/errata/RHSA-2017:1550]]\n\n* [[https://access.redhat.com/errata/RHSA-2017:1549]]\n\n* [[https://access.redhat.com/errata/RHSA-2017:1548]]\n\n* [[https://access.redhat.com/errata/RHSA-2017:0456]]\n\n* [[https://access.redhat.com/errata/RHSA-2017:0455]]\n\n* [[http://rhn.redhat.com/errata/RHSA-2017-1551.html]]\n\n* [[http://rhn.redhat.com/errata/RHSA-2017-0457.html]]\n\n* [[https://security.netapp.com/advisory/ntap-20180605-0001/]]\n\n* [[https://usn.ubuntu.com/4557-1/]]\n\n* [[https://www.oracle.com/security-alerts/cpuoct2021.html]]\n\n"))
            for section in ["**Technical Details**:", "**Classifications**:"]:
                self.assertTrue(section in finding.description)

            self.assertEqual(1, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            endpoint.clean()
            self.assertEqual("poes.ppt.services", endpoint.host)
            self.assertEqual(443, endpoint.port)
            self.assertEqual("https", endpoint.protocol)

            finding = findings[3]
            self.assertEqual("02769aa244c456f0aad810354748faaa70d089c1129dc9c5", finding.unique_id_from_tool)
            self.assertEqual("Permitted HTTP Methods", finding.title)
            self.assertEqual("2024-06-27T19:23:24.943000", finding.date)
            self.assertEqual("Low", finding.severity)
            self.assertEqual(True, finding.active)
            self.assertIsNone(finding.unsaved_request)
            self.assertIsNone(finding.unsaved_response)
            self.assertEqual("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", finding.cvssv3)
            self.assertIsNone(finding.mitigation)
            self.assertIsNone(finding.component_name)
            self.assertIsNone(finding.component_version)
            self.assertIsNone(finding.unsaved_vulnerability_ids)
            self.assertTrue(
                finding.description.startswith(
                    "[[markup]]This is simply a report of HTTP request methods supported by the web application."
                )
            )
            for section in ["**Permitted HTTP Methods**:"]:
                self.assertTrue(section in finding.description)

            self.assertEqual(1, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            endpoint.clean()
            self.assertEqual("example.ppt.com", endpoint.host)
            self.assertEqual(443, endpoint.port)
            self.assertEqual("https", endpoint.protocol)

            # Defaults to Unknown engine
            finding = findings[4]
            self.assertEqual("0cb109aaf647451377332c22cbe917b62304aa13", finding.unique_id_from_tool)
            self.assertEqual("SSL/TLS: Report Vulnerable Cipher Suites for HTTPS", finding.title)
            self.assertEqual("2024-06-26T10:41:56.098000", finding.date)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(True, finding.active)
            self.assertIsNone(finding.unsaved_request)
            self.assertIsNone(finding.unsaved_response)
            self.assertEqual("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", finding.cvssv3)
            self.assertEqual(
                "[[markup]]The configuration of this services should be changed so   that it does not accept the listed cipher suites anymore.\n\nPlease see the references for more resources supporting you with this task.",
                finding.mitigation
            )
            self.assertIsNone(finding.component_name)
            self.assertIsNone(finding.component_version)
            self.assertIsNotNone(finding.unsaved_vulnerability_ids)
            self.assertEqual(3, len(finding.unsaved_vulnerability_ids))
            self.assertEqual(
                set(finding.unsaved_vulnerability_ids),
                {"CVE-2016-2183", "CVE-2016-6329", "CVE-2020-12872"}
            )
            self.assertTrue(
                finding.description.startswith(
                    "[[markup]]This routine reports all SSL/TLS cipher suites accepted by a service   where attack vectors exists only on HTTPS services.\n\nThese rules are applied for the evaluation of the vulnerable cipher suites:\n\n- 64-bit block cipher 3DES vulnerable to the SWEET32 attack (CVE-2016-2183)."
                )
            )
            for section in ["**Technical Details**:", "**External Sources**"]:
                self.assertTrue(section in finding.description)

            self.assertEqual(1, len(finding.unsaved_endpoints))
            endpoint = finding.unsaved_endpoints[0]
            endpoint.clean()
            self.assertEqual("poes.ppt.services", endpoint.host)
            self.assertEqual(443, endpoint.port)
            self.assertIsNone(endpoint.protocol)

    def test_appcheck_web_application_scanner_parser_dupes(self):
        with open("unittests/scans/appcheck_web_application_scanner/appcheck_web_application_scanner_dupes.json") as testfile:
            parser = AppCheckWebApplicationScannerParser()
            findings = parser.get_findings(testfile, Test())
            # Test has 5 entries, but we should only return 3 findings.
            self.assertEqual(3, len(findings))
