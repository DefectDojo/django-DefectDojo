from ..dojo_test_case import DojoTestCase
from dojo.models import Test
from dojo.tools.snyk.parser import SnykParser


class TestSnykParser(DojoTestCase):

    def test_snykParser_single_has_no_finding(self):
        testfile = open("unittests/scans/snyk/single_project_no_vulns.json")
        parser = SnykParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))
        testfile.close()

    def test_snykParser_allprojects_has_no_finding(self):
        testfile = open("unittests/scans/snyk/all-projects_no_vulns.json")
        parser = SnykParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))
        testfile.close()

    def test_snykParser_single_has_one_finding(self):
        testfile = open("unittests/scans/snyk/single_project_one_vuln.json")
        parser = SnykParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        testfile.close()

    def test_snykParser_allprojects_has_one_finding(self):
        testfile = open("unittests/scans/snyk/all-projects_one_vuln.json")
        parser = SnykParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))

    def test_snykParser_single_has_many_findings(self):
        testfile = open("unittests/scans/snyk/single_project_many_vulns.json")
        parser = SnykParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(41, len(findings))

    def test_snykParser_allprojects_has_many_findings(self):
        testfile = open("unittests/scans/snyk/all-projects_many_vulns.json")
        parser = SnykParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(4, len(findings))

    def test_snykParser_finding_has_fields(self):
        testfile = open("unittests/scans/snyk/single_project_one_vuln.json")
        parser = SnykParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        finding = findings[0]
        self.assertEqual(
            "com.test:myframework@1.0.0-SNAPSHOT: XML External Entity (XXE) Injection",
            finding.title,
        )
        self.assertEqual("Medium", finding.severity)
        self.assertEqual(
            "Issue severity of: **Medium** from a base CVSS score of: **6.5**",
            finding.severity_justification,
        )
        self.assertEqual(
            "SNYK-JAVA-ORGAPACHESANTUARIO-460281", finding.vuln_id_from_tool
        )
        self.assertEqual("CVE-2019-12400", finding.cve)
        self.assertEqual(611, finding.cwe)
        self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L", finding.cvssv3)
        self.assertEqual(
            "## Remediation\nUpgrade `org.apache.santuario:xmlsec` to version 2.1.4 or higher.\n",
            finding.mitigation,
        )
        self.assertEqual(
            "**SNYK ID**: https://app.snyk.io/vuln/SNYK-JAVA-ORGAPACHESANTUARIO-460281\n\n**GitHub " +
            "Commit**: https://github.com/apache/santuario-java/commit/52ae824cf5f5c873a0e37bb33fedcc3b387" +
            "cdba6\n**GitHub Commit**: https://github.com/apache/santuario-java/commit/c5210f77a77105fba81" +
            "311d16c07ceacc21f39d5\n**Possible Jira Issue**: https://issues.apache.org/jira/browse/SANTUARIO-" +
            "504?jql=project%20%3D%20SANTUARIO\n**Security Release**: http://santuario.apache.org/secadv.data/" +
            "CVE-2019-12400.asc?version=1&modificationDate=1566573083000&api=v2\n",
            finding.references,
        )
        self.assertEqual(
            "com.test:myframework > org.apache.santuario:xmlsec", finding.file_path
        )

    def test_snykParser_file_path_with_ampersand_is_preserved(self):
        testfile = open("unittests/scans/snyk/single_project_one_vuln_with_ampersands.json")
        parser = SnykParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual(
            "myproject > @angular/localize > @babel/core > lodash",
            finding.file_path
        )

    def test_snykParser_allprojects_issue4277(self):
        """Report to linked to issue 4277"""
        testfile = open("unittests/scans/snyk/all_projects_issue4277.json")
        parser = SnykParser()
        findings = list(parser.get_findings(testfile, Test()))
        testfile.close()
        self.assertEqual(82, len(findings))
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("High", finding.severity)
            self.assertEqual("Microsoft.AspNetCore", finding.component_name)
            self.assertEqual("2.2.0", finding.component_version)
            self.assertEqual("SNYK-DOTNET-MICROSOFTASPNETCORE-174184", finding.vuln_id_from_tool)
            self.assertEqual("CVE-2019-0815", finding.cve)
            self.assertEqual(200, finding.cwe)
            self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", finding.cvssv3)
        with self.subTest(i=40):
            finding = findings[40]
            self.assertEqual("High", finding.severity)
            self.assertEqual("lodash", finding.component_name)
            self.assertEqual("4.17.11", finding.component_version)
            self.assertEqual("SNYK-JS-LODASH-1040724", finding.vuln_id_from_tool)
            self.assertEqual("CVE-2021-23337", finding.cve)
            self.assertEqual(78, finding.cwe)
            self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H/E:P/RL:U/RC:C", finding.cvssv3)
        with self.subTest(i=81):
            finding = findings[81]
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("yargs-parser", finding.component_name)
            self.assertEqual("5.0.0", finding.component_version)
            self.assertEqual("SNYK-JS-YARGSPARSER-560381", finding.vuln_id_from_tool)
            self.assertEqual("CVE-2020-7608", finding.cve)
            self.assertEqual(400, finding.cwe)
            self.assertEqual("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L/E:P/RL:O/RC:C", finding.cvssv3)
