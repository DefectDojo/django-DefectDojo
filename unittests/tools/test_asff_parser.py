import os.path
import json
from datetime import datetime
from dojo.models import Test, Endpoint
from dojo.tools.asff.parser import AsffParser
from ..dojo_test_case import DojoTestCase, get_unit_tests_path

def sample_path(file_name):
    return os.path.join(get_unit_tests_path(), "scans/asff", file_name)

class TestAsffParser(DojoTestCase):

    def load_sample_json(self, file_name):
        with open(sample_path(file_name), "r") as file:
            return json.load(file)

    def common_check_finding(self, finding, data, index):
        self.assertEqual(finding.title, data["Findings"][index]["Title"])
        self.assertEqual(finding.description, data["Findings"][index]["Description"])
        self.assertEqual(finding.date.date(), datetime.strptime(data["Findings"][index]["CreatedAt"], '%Y-%m-%dT%H:%M:%S.%fZ').date())
        self.assertEqual(finding.severity, data["Findings"][index]["Product"]["Name"])
        self.assertTrue(finding.active)
        # Test endpoint creation
        expected_ipv4s = data["Findings"][index]["Details"]["AwsEc2Instance"]["IpV4Addresses"]
        if finding.endpoints:
            for endpoint in finding.endpoints.all():
                self.assertTrue(isinstance(endpoint, Endpoint))
                self.assertIn(endpoint.host, expected_ipv4s)

    def test_asff_one_vuln(self):
        data = self.load_sample_json('one_vuln.json')
        with open(sample_path('one_vuln.json'), "r") as file:
            parser = AsffParser()
            findings = parser.get_findings(file, Test())
            self.assertEqual(1, len(findings))
            self.common_check_finding(findings[0], data, 0)

    def test_asff_many_vulns(self):
        data = self.load_sample_json('many_vulns.json')
        with open(sample_path('many_vulns.json'), "r") as file:
            parser = AsffParser()
            findings = parser.get_findings(file, Test())
            self.assertGreater(len(findings), 1)
            for index, finding in enumerate(findings):
                self.common_check_finding(finding, data, index)
