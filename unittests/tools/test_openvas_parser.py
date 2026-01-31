
from dojo.models import Engagement, Product, Test
from dojo.tools.openvas.parser import OpenVASParser, OpenVASParserV2
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


# V2 Parser tests
def openvas_open(file):
    """Helper to get file handle to openvas test files"""
    return (get_unit_tests_scans_path("openvas") / file).open(encoding="utf-8")


class TestOpenVASParserV2(DojoTestCase):
    def setup_openvas_v2_test(self, f):
        """Setup helper for general openvas_v2 test setup"""
        test = Test()
        test.engagement = Engagement()
        test.engagement.product = Product()
        parser = OpenVASParserV2()
        findings = parser.get_findings(f, test)
        self.validate_locations(findings)
        return findings

    # test empty cases
    def test_openvas_csv_no_vuln(self):
        """Ensure that an empty report does not throw and error and reports 0 findings"""
        with openvas_open("no_vuln.csv") as f:
            findings = self.setup_openvas_v2_test(f)
            self.assertEqual(0, len(findings))

    def test_openvas_xml_no_vuln(self):
        """Ensure that an empty report does not throw and error and reports 0 findings"""
        with openvas_open("no_vuln.xml") as f:
            findings = self.setup_openvas_v2_test(f)
            self.assertEqual(0, len(findings))

    def test_openvas_parser_csv_detail(self):
        """Ensure finding contains report data as expected"""
        with openvas_open("report_detail_v2.csv") as f:
            findings = self.setup_openvas_v2_test(f)

        # ensure single finding
        self.assertEqual(len(findings), 1)
        finding = findings[0]

        # general finding info tests
        self.assertEqual("Microsoft Windows Multiple Vulnerabilities (KB5062557)", finding.title)
        self.assertEqual("High", finding.severity)  # OpenVAS reports Critical findings as High
        self.assertEqual(9.8, finding.cvssv3_score)
        self.assertEqual(0.00143, finding.epss_score)
        self.assertEqual(0.35177, finding.epss_percentile)

        # vulnerability id tests
        self.assertEqual(finding.vuln_id_from_tool, "1.3.6.1.4.1.25623.1.0.836484")
        self.assertEqual(finding.unsaved_vulnerability_ids[1], "CVE-2025-48823")
        self.assertEqual(93, len(finding.unsaved_vulnerability_ids))

        # location tests
        self.assertEqual(1, len(self.get_unsaved_locations(finding)))
        self.assertEqual("server99", self.get_unsaved_locations(finding)[0].host)
        # this is example data normaly tested finding does not include this
        self.assertEqual(42, self.get_unsaved_locations(finding)[0].port)
        self.assertEqual("tcp", self.get_unsaved_locations(finding)[0].protocol)

    def test_openvas_parser_xml_detail(self):
        """Ensure finding contains report data as expected"""
        with openvas_open("report_detail_v2.xml") as f:
            findings = self.setup_openvas_v2_test(f)

        # ensure single finding
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(9.8, finding.cvssv3_score)

    def test_openvas_parser_csv_xml_parity(self):
        """Ensure xml and csv parser parse data that is the same between report in the same way"""
        with openvas_open("report_detail_v2.csv") as f:
            findings_csv = self.setup_openvas_v2_test(f)
        with openvas_open("report_detail_v2.xml") as f:
            findings_xml = self.setup_openvas_v2_test(f)

        f_xml = findings_xml[0]
        f_csv = findings_csv[0]

        # ensure same general finding parsing behaviour
        self.assertEqual(f_xml.title, f_csv.title)
        self.assertEqual(f_xml.severity, f_csv.severity)
        # remove this if future parser versions want different description behaviour
        self.assertEqual(f_xml.description, f_csv.description)

        # ensure same vulnerability id parsing behaviour
        self.assertEqual(f_xml.vuln_id_from_tool, f_csv.vuln_id_from_tool)
        # xml has multiple types of vulnerability ids, change this if a new one is parsed
        self.assertEqual(len(f_xml.unsaved_vulnerability_ids), len(f_csv.unsaved_vulnerability_ids))
        self.assertEqual(f_xml.unsaved_vulnerability_ids, f_csv.unsaved_vulnerability_ids)

        # ensure same location parsing behaviour
        xml_location = self.get_unsaved_locations(f_xml)[0]
        csv_location = self.get_unsaved_locations(f_csv)[0]
        self.assertEqual(xml_location.host, csv_location.host)
        self.assertEqual(xml_location.protocol, csv_location.protocol)
        self.assertEqual(xml_location.port, csv_location.port)

    def test_openvas_csv_report_combined_findings(self):
        """Ensure findings combinding behaviour"""
        with openvas_open("report_combine_v2.csv") as f:
            findings = self.setup_openvas_v2_test(f)
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual(2, finding.nb_occurences)

    def test_openvas_csv_many_findings(self):
        """Ensure findings combinding behaviour"""
        with openvas_open("many_vuln.csv") as f:
            findings = self.setup_openvas_v2_test(f)
            self.assertEqual(4, len(findings))

    def test_openvas_xml_many_findings(self):
        """Ensure findings combinding behaviour"""
        with openvas_open("many_vuln.xml") as f:
            findings = self.setup_openvas_v2_test(f)
            self.assertEqual(44, len(findings))


# V1 Parser tests
class TestOpenVASParser(DojoTestCase):
    def test_openvas_csv_one_vuln(self):
        with (get_unit_tests_scans_path("openvas") / "one_vuln.csv").open(encoding="utf-8") as f:
            test = Test()
            test.engagement = Engagement()
            test.engagement.product = Product()
            parser = OpenVASParser()
            findings = parser.get_findings(f, test)
            self.validate_locations(findings)
            self.assertEqual(1, len(findings))
            # finding
            self.assertEqual("SSH Weak Encryption Algorithms Supported", findings[0].title)
            self.assertEqual("Medium", findings[0].severity)
            # locations
            self.assertEqual(1, len(self.get_unsaved_locations(findings[0])))
            # locations
            self.assertEqual("10.0.0.8", self.get_unsaved_locations(findings[0])[0].host)
            self.assertEqual("tcp", self.get_unsaved_locations(findings[0])[0].protocol)
            self.assertEqual(22, self.get_unsaved_locations(findings[0])[0].port)

    def test_openvas_csv_many_vuln(self):
        with (get_unit_tests_scans_path("openvas") / "many_vuln.csv").open(encoding="utf-8") as f:
            test = Test()
            test.engagement = Engagement()
            test.engagement.product = Product()
            parser = OpenVASParser()
            findings = parser.get_findings(f, test)
            self.validate_locations(findings)
            self.assertEqual(4, len(findings))
            # finding
            finding = findings[3]
            self.assertEqual("HTTP Brute Force Logins With Default Credentials Reporting", finding.title)
            self.assertEqual("High", finding.severity)
            # locations
            self.assertEqual(1, len(self.get_unsaved_locations(finding)))
            # location
            location = self.get_unsaved_locations(finding)[0]
            self.assertEqual("LOGSRV".lower(), location.host.lower())
            self.assertEqual("tcp", location.protocol)
            self.assertEqual(9200, location.port)
            finding = findings[2]
            self.assertEqual(finding.unsaved_vulnerability_ids[0], "CVE-2011-3389")

    def test_openvas_csv_report_usingCVE(self):
        with (get_unit_tests_scans_path("openvas") / "report_using_CVE.csv").open(encoding="utf-8") as f:
            test = Test()
            test.engagement = Engagement()
            test.engagement.product = Product()
            parser = OpenVASParser()
            findings = parser.get_findings(f, test)
            self.validate_locations(findings)
            self.assertEqual(43, len(findings))
            finding = findings[4]
            self.assertEqual("CVE-2014-0117", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(4.3, finding.cvssv3_score)
            self.assertEqual(finding.unsaved_vulnerability_ids[0], "CVE-2014-0117")

    def test_openvas_csv_report_usingOpenVAS(self):
        with (get_unit_tests_scans_path("openvas") / "report_using_openVAS.csv").open(encoding="utf-8") as f:
            test = Test()
            test.engagement = Engagement()
            test.engagement.product = Product()
            parser = OpenVASParser()
            findings = parser.get_findings(f, test)
            self.validate_locations(findings)
            self.assertEqual(13, len(findings))
            finding = findings[2]
            self.assertEqual("Apache HTTP Server Detection Consolidation", finding.title)
            self.assertEqual("Info", finding.severity)
            self.assertEqual(finding.unsaved_vulnerability_ids, [])

    def test_openvas_xml_no_vuln(self):
        with (get_unit_tests_scans_path("openvas") / "no_vuln.xml").open(encoding="utf-8") as f:
            test = Test()
            test.engagement = Engagement()
            test.engagement.product = Product()
            parser = OpenVASParser()
            findings = parser.get_findings(f, test)
            self.assertEqual(0, len(findings))

    def test_openvas_xml_one_vuln(self):
        with (get_unit_tests_scans_path("openvas") / "one_vuln.xml").open(encoding="utf-8") as f:
            test = Test()
            test.engagement = Engagement()
            test.engagement.product = Product()
            parser = OpenVASParser()
            findings = parser.get_findings(f, test)
            self.validate_locations(findings)
            self.assertEqual(1, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual(
                    "Mozilla Firefox Security Update (mfsa_2023-32_2023-36) - Windows_10.0.101.2_general/tcp",
                    finding.title,
                )
                self.assertEqual("High", finding.severity)

    def test_openvas_xml_many_vuln(self):
        with (get_unit_tests_scans_path("openvas") / "many_vuln.xml").open(encoding="utf-8") as f:
            test = Test()
            test.engagement = Engagement()
            test.engagement.product = Product()
            parser = OpenVASParser()
            findings = parser.get_findings(f, test)
            self.assertEqual(44, len(findings))
            self.assertEqual(44, len([location for finding in findings for location in self.get_unsaved_locations(finding)]))
            self.validate_locations(findings)
            self.assertEqual("tcp://192.168.1.1001:512", str(self.get_unsaved_locations(findings[0])[0]))
