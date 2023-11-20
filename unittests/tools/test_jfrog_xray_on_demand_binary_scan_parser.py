from ..dojo_test_case import DojoTestCase
from dojo.models import Test, Finding
from dojo.tools.jfrog_xray_on_demand_binary_scan.parser import \
    JfrogXrayOnDemandBinaryScanParser, get_component_name_version, clean_title


class TestJfrogXrayOnDemandBinaryScanParser(DojoTestCase):

    def test_parse_file_with_one_vuln(self):
        testfile = open("unittests/scans/jfrog_xray_on_demand_binary_scan/one_vuln.json")
        parser = JfrogXrayOnDemandBinaryScanParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))
        item: Finding = findings[0]
        self.assertEqual("gav://test", item.component_name)
        self.assertEqual("CVE-2014-0114", item.unsaved_vulnerability_ids[0])
        self.assertEqual("High", item.severity)

    def test_parse_file_with_many_vulns(self):
        testfile = open("unittests/scans/jfrog_xray_on_demand_binary_scan/many_vulns.json")
        parser = JfrogXrayOnDemandBinaryScanParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(3, len(findings))

    def test_component_name_version(self):
        with self.subTest(""):
            self.assertEqual(("", ""), get_component_name_version(""))
        with self.subTest("gav://org.yaml:snakeyaml:1.16"):
            self.assertEqual(("gav://org.yaml:snakeyaml", "1.16"), get_component_name_version("gav://org.yaml:snakeyaml:1.16"))
        with self.subTest("npm://desopmo:1.33.7"):
            self.assertEqual(("npm://desopmo", "1.33.7"), get_component_name_version("npm://desopmo:1.33.7"))
        with self.subTest("pypi://django:4.1.4"):
            self.assertEqual(("pypi://django", "4.1.4"), get_component_name_version("pypi://django:4.1.4"))
        with self.subTest("alpine://3.18:libcrypto3:3.1.1-r1"):
            self.assertEqual(("alpine://3.18:libcrypto3", "3.1.1-r1"), get_component_name_version("alpine://3.18:libcrypto3:3.1.1-r1"))
        with self.subTest("npm://desopmo"):
            self.assertEqual(("npm://desopmo", ""), get_component_name_version("npm://desopmo"))

    def test_clean_title(self):
        with self.subTest(""):
            self.assertEqual("", clean_title(""))
        with self.subTest("ABC"):
            self.assertEqual("ABC", clean_title("ABC"))
        with self.subTest("Garbage"):
            self.assertEqual("Processing some specially crafted ASN.1 object identifiers or", clean_title("Issue summary: Processing some specially crafted ASN.1 object identifiers or\ndata containing them may be very slow."))

    def test_parse_file_with_many_vulns_docker(self):
        testfile = open("unittests/scans/jfrog_xray_on_demand_binary_scan/many_vulns_docker.json")
        parser = JfrogXrayOnDemandBinaryScanParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(4, len(findings))

    def test_parse_file_with_many_vulns_pypi(self):
        testfile = open("unittests/scans/jfrog_xray_on_demand_binary_scan/many_vulns_pypi.json")
        parser = JfrogXrayOnDemandBinaryScanParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(99, len(findings))
