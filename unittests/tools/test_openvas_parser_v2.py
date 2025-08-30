import io

from dojo.models import Engagement, Product, Test
from dojo.tools.openvas_v2.parser import OpenVASParserV2
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


def openvas_open(file):
    """Helper to get file handle to openvas test files"""
    return (get_unit_tests_scans_path("openvas") / file).open(encoding="utf-8")


def setup_openvas_v2_test(f):
    """Setup helper for general openvas_v2 test setup"""
    test = Test()
    test.engagement = Engagement()
    test.engagement.product = Product()
    parser = OpenVASParserV2()
    findings = parser.get_findings(f, test)
    for finding in findings:
        for endpoint in finding.unsaved_endpoints:
            endpoint.clean()
    return findings


class TestOpenVASParserV2(DojoTestCase):
    # test empty cases
    def test_openvas_csv_no_vuln(self):
        """Ensure that an empty report does not throw and error and reports 0 findings"""
        with openvas_open("no_vuln.csv") as f:
            findings = setup_openvas_v2_test(f)
            self.assertEqual(0, len(findings))

    def test_openvas_xml_no_vuln(self):
        """Ensure that an empty report does not throw and error and reports 0 findings"""
        with openvas_open("no_vuln.xml") as f:
            findings = setup_openvas_v2_test(f)
            self.assertEqual(0, len(findings))

    def test_openvas_parser_csv_detail(self):
        """Ensure finding contains report data as expected"""
        with openvas_open("report_detail_v2.csv") as f:
            findings = setup_openvas_v2_test(f)

        # ensure single finding
        self.assertEqual(len(findings), 1)
        finding = findings[0]

        # general finding info tests
        self.assertEqual("Microsoft Windows Multiple Vulnerabilities (KB5062557)", finding.title)
        self.assertEqual("High", finding.severity)  # OpenVAS report Critical findings as High
        self.assertEqual(9.8, finding.cvssv3_score)

        # vulnerability id tests
        self.assertEqual(finding.vuln_id_from_tool, "1.3.6.1.4.1.25623.1.0.836484")
        self.assertEqual(finding.unsaved_vulnerability_ids[1], "CVE-2025-48823")
        self.assertEqual(93, len(finding.unsaved_vulnerability_ids))

        # endpoint tests
        self.assertEqual(1, len(finding.unsaved_endpoints))
        self.assertEqual("server99", finding.unsaved_endpoints[0].host)
        # this is example data normaly tested finding does not include this
        self.assertEqual(42, finding.unsaved_endpoints[0].port)
        self.assertEqual("tcp", finding.unsaved_endpoints[0].protocol)

    def test_openvas_parser_csv_xml_parity(self):
        """Ensure xml and csv parser parse data that is the same between report in the same way"""
        with openvas_open("report_detail_v2.csv") as f:
            findings_csv = setup_openvas_v2_test(f)
        with openvas_open("report_detail_v2.xml") as f:
            findings_xml = setup_openvas_v2_test(f)

        f_xml = findings_xml[0]
        f_csv = findings_csv[0]

        # ensure same general finding parsing behaviour
        self.assertEqual(f_xml.title, f_csv.title)
        self.assertEqual(f_xml.severity, f_csv.severity)
        self.assertEqual(f_xml.cvssv3_score, f_csv.cvssv3_score)
        # remove this if future parser versions want different description behaviour
        self.assertEqual(f_xml.description, f_csv.description)

        # ensure same vulnerability id parsing behaviour
        self.assertEqual(f_xml.vuln_id_from_tool, f_csv.vuln_id_from_tool)
        # xml has multiple types of vulnerability ids, change this if a new one is parsed
        self.assertEqual(len(f_xml.unsaved_vulnerability_ids), len(f_csv.unsaved_vulnerability_ids))
        self.assertEqual(f_xml.unsaved_vulnerability_ids, f_csv.unsaved_vulnerability_ids)

        # ensure same endpoint parsing behaviour
        self.assertEqual(f_xml.unsaved_endpoints[0].host, f_csv.unsaved_endpoints[0].host)
        self.assertEqual(f_xml.unsaved_endpoints[0].protocol, f_csv.unsaved_endpoints[0].protocol)
        self.assertEqual(f_xml.unsaved_endpoints[0].port, f_csv.unsaved_endpoints[0].port)

    def test_openvas_csv_report_combined_findings(self):
        """Ensure findings combinding behaviour"""
        with openvas_open("report_combine_v2.csv") as f:
            findings = setup_openvas_v2_test(f)
            self.assertEqual(1, len(findings))

    def test_openvas_csv_many_findings(self):
        """Ensure findings combinding behaviour"""
        with openvas_open("many_vuln.csv") as f:
            findings = setup_openvas_v2_test(f)
            self.assertEqual(4, len(findings))

    def test_openvas_xml_many_findings(self):
        """Ensure findings combinding behaviour"""
        with openvas_open("many_vuln.xml") as f:
            findings = setup_openvas_v2_test(f)
            self.assertEqual(44, len(findings))
