from ..dojo_test_case import DojoTestCase
from dojo.models import Test
from dojo.tools.jfrog_xray_api_summary_artifact.parser import JFrogXrayApiSummaryArtifactParser


class TestJFrogXrayApiSummaryArtifactParser(DojoTestCase):

    def test_parse_file_with_no_vuln(self):
        testfile = open("unittests/scans/jfrog_xray_api_summary_artifact/no_vuln.json")
        parser = JFrogXrayApiSummaryArtifactParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln(self):
        testfile = open("unittests/scans/jfrog_xray_api_summary_artifact/one_vuln.json")
        parser = JFrogXrayApiSummaryArtifactParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))
        item = findings[0]
        self.assertEqual("OpenSSL crypto", item.title[:14])
        self.assertEqual(1, len(item.unsaved_vulnerability_ids))
        self.assertEqual("XRAY-124116", item.unsaved_vulnerability_ids[0])
        self.assertEqual("Critical", item.severity)
        self.assertEqual("OpenSSL contains an overflow", item.description[:28])
        self.assertEqual(" code.", item.description[-6:])
        self.assertIsNone(item.mitigation)
        self.assertEqual("3.12:openssl", item.component_name)
        self.assertIsNotNone(item.tags)
        print(item.tags)
        self.assertEqual("1.1.1k-r0", item.component_version)
        self.assertEqual("default/component/open-liberty/21.0.0.3-1-full-alpine-java8-openj9", item.file_path[:66])
        self.assertIsNone(item.severity_justification)
        self.assertIsNone(item.references)
        self.assertIsNone(item.impact)
        self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", item.cvssv3)

    def test_parse_file_with_many_vulns(self):
        testfile = open("unittests/scans/jfrog_xray_api_summary_artifact/many_vulns.json")
        parser = JFrogXrayApiSummaryArtifactParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(15, len(findings))
