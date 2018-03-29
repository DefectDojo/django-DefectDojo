from defusedxml import ElementTree
from django.test import TestCase

from dojo.models import Test
from dojo.tools.dependencycheck.parser import DependencyCheckParser


class TestFile(object):

    def read(self):
        return self.content

    def __init__(self, name, content):
        self.name = name
        self.content = content


class TestDependencyCheckParser(TestCase):

    def test_parse_without_file_has_no_findings(self):
        parser = DependencyCheckParser(None, Test())
        self.assertEqual(0, len(parser.items))

    def test_parse_file_with_no_vulnerabilities_has_no_findings(self):
        content = """<?xml version="1.0"?>
<analysis xmlns="https://jeremylong.github.io/DependencyCheck/dependency-check.1.3.xsd">
    <scanInfo>
    </scanInfo>
    <projectInfo>
        <name>Test Project</name>
        <reportDate>2016-11-05T14:52:15.748-0400</reportDate>
        <credits>This report contains data retrieved from the National Vulnerability Database: http://nvd.nist.gov</credits>
    </projectInfo>
    <dependencies>
        <dependency>
            <fileName>component1.dll</fileName>
            <filePath>C:\Projects\testproject\libraries\component1.dll</filePath>
            <md5>ba5a6a10bae6ce2abbabec9facae23a4</md5>
            <sha1>ae917bbce68733468b1972113e0e1fc5dc7444a0</sha1>
            <evidenceCollected>
                <evidence type="vendor" confidence="HIGH">
                    <source>file</source>
                    <name>name</name>
                    <value>component1.dll</value>
                </evidence>
                <evidence type="product" confidence="HIGH">
                    <source>file</source>
                    <name>name</name>
                    <value>component1</value>
                </evidence>
                <evidence type="version" confidence="MEDIUM">
                    <source>file</source>
                    <name>name</name>
                    <value>component1</value>
                </evidence>
                <evidence type="version" confidence="MEDIUM">
                    <source>file</source>
                    <name>version</name>
                    <value>1</value>
                </evidence>
            </evidenceCollected>
        </dependency>
        <dependency>
            <fileName>component2.dll</fileName>
            <filePath>C:\Projects\testproject\libraries\component2.dll</filePath>
            <md5>21b24bc199530e07cb15d93c7f929f04</md5>
            <sha1>a29f196740ab608199488c574f536529b5c21242</sha1>
            <evidenceCollected>
                <evidence type="vendor" confidence="HIGH">
                    <source>file</source>
                    <name>name</name>
                    <value>component2</value>
                </evidence>
                <evidence type="product" confidence="HIGH">
                    <source>file</source>
                    <name>name</name>
                    <value>component2</value>
                </evidence>
            </evidenceCollected>
        </dependency>
        </dependencies>
</analysis>
 """
        testfile = TestFile("dependency-check-report.xml", content)
        parser = DependencyCheckParser(testfile, Test())
        self.assertEqual(0, len(parser.items))

    def test_parse_file_with_single_vulnerability_has_single_finding(self):
        content = """<?xml version="1.0"?>
<analysis xmlns="https://jeremylong.github.io/DependencyCheck/dependency-check.1.3.xsd">
    <scanInfo>
    </scanInfo>
    <projectInfo>
        <name>Test Project</name>
        <reportDate>2016-11-05T14:52:15.748-0400</reportDate>
        <credits>This report contains data retrieved from the National Vulnerability Database: http://nvd.nist.gov</credits>
    </projectInfo>
    <dependencies>
        <dependency>
            <fileName>component1.dll</fileName>
            <filePath>C:\Projects\testproject\libraries\component1.dll</filePath>
            <md5>ba5a6a10bae6ce2abbabec9facae23a4</md5>
            <sha1>ae917bbce68733468b1972113e0e1fc5dc7444a0</sha1>
            <evidenceCollected>
                <evidence type="vendor" confidence="HIGH">
                    <source>file</source>
                    <name>name</name>
                    <value>component1.dll</value>
                </evidence>
                <evidence type="product" confidence="HIGH">
                    <source>file</source>
                    <name>name</name>
                    <value>component1</value>
                </evidence>
                <evidence type="version" confidence="MEDIUM">
                    <source>file</source>
                    <name>name</name>
                    <value>component1</value>
                </evidence>
                <evidence type="version" confidence="MEDIUM">
                    <source>file</source>
                    <name>version</name>
                    <value>1</value>
                </evidence>
            </evidenceCollected>
        </dependency>
        <dependency>
            <fileName>component2.dll</fileName>
            <filePath>C:\Projects\testproject\libraries\component2.dll</filePath>
            <md5>21b24bc199530e07cb15d93c7f929f04</md5>
            <sha1>a29f196740ab608199488c574f536529b5c21242</sha1>
            <evidenceCollected>
                <evidence type="vendor" confidence="HIGH">
                    <source>file</source>
                    <name>name</name>
                    <value>component2</value>
                </evidence>
                <evidence type="product" confidence="HIGH">
                    <source>file</source>
                    <name>name</name>
                    <value>component2</value>
                </evidence>
            </evidenceCollected>
            <identifiers>
                <identifier type="cpe" confidence="LOW">
                    <name>(cpe:/a:component2:component2:-)</name>
                </identifier>
            </identifiers>
            <vulnerabilities>
                <vulnerability>
                    <name>CVE-0000-0001</name>
                    <cvssScore>7.5</cvssScore>
                    <cvssAccessVector>NETWORK</cvssAccessVector>
                    <cvssAccessComplexity>LOW</cvssAccessComplexity>
                    <cvssAuthenticationr>NONE</cvssAuthenticationr>
                    <cvssConfidentialImpact>PARTIAL</cvssConfidentialImpact>
                    <cvssIntegrityImpact>PARTIAL</cvssIntegrityImpact>
                    <cvssAvailabilityImpact>PARTIAL</cvssAvailabilityImpact>
                    <severity>High</severity>
                    <cwe>CWE-00 Bad Vulnerability</cwe>
                    <description>Description of a bad vulnerability.</description>
                    <references>
                        <reference>
                            <source>Reference1</source>
                            <url>http://localhost/badvulnerability.htm</url>
                            <name>Reference Name</name>
                        </reference>
                        <reference>
                            <source>MISC</source>
                            <url>http://localhost2/reference_for_badvulnerability.pdf</url>
                            <name>Reference for a bad vulnerability</name>
                        </reference>
                    </references>
                    <vulnerableSoftware>
                        <software>cpe:/a:component2:component2:1.0</software>
                    </vulnerableSoftware>
                </vulnerability>
            </vulnerabilities>
        </dependency>
        </dependencies>
</analysis>
 """
        testfile = TestFile("dependency-check-report.xml", content)
        parser = DependencyCheckParser(testfile, Test())
        self.assertEqual(1, len(parser.items))

    def test_parse_file_with_multiple_vulnerabilities_has_multiple_findings(
            self):
        content = """<?xml version="1.0"?>
<analysis xmlns="https://jeremylong.github.io/DependencyCheck/dependency-check.1.3.xsd">
    <scanInfo>
    </scanInfo>
    <projectInfo>
        <name>Test Project</name>
        <reportDate>2016-11-05T14:52:15.748-0400</reportDate>
        <credits>This report contains data retrieved from the National Vulnerability Database: http://nvd.nist.gov</credits>
    </projectInfo>
    <dependencies>
        <dependency>
            <fileName>component1.dll</fileName>
            <filePath>C:\Projects\testproject\libraries\component1.dll</filePath>
            <md5>ba5a6a10bae6ce2abbabec9facae23a4</md5>
            <sha1>ae917bbce68733468b1972113e0e1fc5dc7444a0</sha1>
            <evidenceCollected>
                <evidence type="vendor" confidence="HIGH">
                    <source>file</source>
                    <name>name</name>
                    <value>component1.dll</value>
                </evidence>
                <evidence type="product" confidence="HIGH">
                    <source>file</source>
                    <name>name</name>
                    <value>component1</value>
                </evidence>
                <evidence type="version" confidence="MEDIUM">
                    <source>file</source>
                    <name>name</name>
                    <value>component1</value>
                </evidence>
                <evidence type="version" confidence="MEDIUM">
                    <source>file</source>
                    <name>version</name>
                    <value>1</value>
                </evidence>
            </evidenceCollected>
        </dependency>
        <dependency>
            <fileName>component2.dll</fileName>
            <filePath>C:\Projects\testproject\libraries\component2.dll</filePath>
            <md5>21b24bc199530e07cb15d93c7f929f04</md5>
            <sha1>a29f196740ab608199488c574f536529b5c21242</sha1>
            <evidenceCollected>
                <evidence type="vendor" confidence="HIGH">
                    <source>file</source>
                    <name>name</name>
                    <value>component2</value>
                </evidence>
                <evidence type="product" confidence="HIGH">
                    <source>file</source>
                    <name>name</name>
                    <value>component2</value>
                </evidence>
            </evidenceCollected>
            <identifiers>
                <identifier type="cpe" confidence="LOW">
                    <name>(cpe:/a:component2:component2:-)</name>
                </identifier>
            </identifiers>
            <vulnerabilities>
                <vulnerability>
                    <name>CVE-0000-0001</name>
                    <cvssScore>7.5</cvssScore>
                    <cvssAccessVector>NETWORK</cvssAccessVector>
                    <cvssAccessComplexity>LOW</cvssAccessComplexity>
                    <cvssAuthenticationr>NONE</cvssAuthenticationr>
                    <cvssConfidentialImpact>PARTIAL</cvssConfidentialImpact>
                    <cvssIntegrityImpact>PARTIAL</cvssIntegrityImpact>
                    <cvssAvailabilityImpact>PARTIAL</cvssAvailabilityImpact>
                    <severity>High</severity>
                    <cwe>CWE-00 Bad Vulnerability</cwe>
                    <description>Description of a bad vulnerability.</description>
                    <references>
                        <reference>
                            <source>Reference1</source>
                            <url>http://localhost/badvulnerability.htm</url>
                            <name>Reference Name</name>
                        </reference>
                        <reference>
                            <source>MISC</source>
                            <url>http://localhost2/reference_for_badvulnerability.pdf</url>
                            <name>Reference for a bad vulnerability</name>
                        </reference>
                    </references>
                    <vulnerableSoftware>
                        <software>cpe:/a:component2:component2:1.0</software>
                    </vulnerableSoftware>
                </vulnerability>
            </vulnerabilities>
        </dependency>
        <dependency>
            <fileName>component3.dll</fileName>
            <filePath>C:\Projects\testproject\libraries\component3.dll</filePath>
            <md5>21b24bc199530e07cb15d93c7f929f03</md5>
            <sha1>a29f196740ab608199488c574f536529b5c21243</sha1>
            <evidenceCollected>
                <evidence type="vendor" confidence="HIGH">
                    <source>file</source>
                    <name>name</name>
                    <value>component3</value>
                </evidence>
                <evidence type="product" confidence="HIGH">
                    <source>file</source>
                    <name>name</name>
                    <value>component3</value>
                </evidence>
            </evidenceCollected>
            <identifiers>
                <identifier type="cpe" confidence="LOW">
                    <name>(cpe:/a:component3:component3:-)</name>
                </identifier>
            </identifiers>
            <vulnerabilities>
                <vulnerability>
                    <name>CVE-0000-0001</name>
                    <cvssScore>7.5</cvssScore>
                    <cvssAccessVector>NETWORK</cvssAccessVector>
                    <cvssAccessComplexity>LOW</cvssAccessComplexity>
                    <cvssAuthenticationr>NONE</cvssAuthenticationr>
                    <cvssConfidentialImpact>PARTIAL</cvssConfidentialImpact>
                    <cvssIntegrityImpact>PARTIAL</cvssIntegrityImpact>
                    <cvssAvailabilityImpact>PARTIAL</cvssAvailabilityImpact>
                    <severity>High</severity>
                    <cwe>CWE-00 Bad Vulnerability</cwe>
                    <description>Description of a bad vulnerability.</description>
                    <references>
                        <reference>
                            <source>Reference1</source>
                            <url>http://localhost/badvulnerability.htm</url>
                            <name>Reference Name</name>
                        </reference>
                        <reference>
                            <source>MISC</source>
                            <url>http://localhost2/reference_for_badvulnerability.pdf</url>
                            <name>Reference for a bad vulnerability</name>
                        </reference>
                    </references>
                    <vulnerableSoftware>
                        <software>cpe:/a:component3:component3:1.0</software>
                    </vulnerableSoftware>
                </vulnerability>
            </vulnerabilities>
        </dependency>
        </dependencies>
</analysis>
 """
        testfile = TestFile("dependency-check-report.xml", content)
        parser = DependencyCheckParser(testfile, Test())
        self.assertEqual(2, len(parser.items))

    def test_parse_finding(self):
        finding_xml = """<vulnerability xmlns="https://jeremylong.github.io/DependencyCheck/dependency-check.1.3.xsd">
<name>CVE-0000-0001</name>
<cvssScore>7.5</cvssScore>
<cvssAccessVector>NETWORK</cvssAccessVector>
<cvssAccessComplexity>LOW</cvssAccessComplexity>
<cvssAuthenticationr>NONE</cvssAuthenticationr>
<cvssConfidentialImpact>PARTIAL</cvssConfidentialImpact>
<cvssIntegrityImpact>PARTIAL</cvssIntegrityImpact>
<cvssAvailabilityImpact>PARTIAL</cvssAvailabilityImpact>
<severity>High</severity>
<cwe>CWE-00 Bad Vulnerability</cwe>
<description>Description of a bad vulnerability.</description>
<references>
<reference>
<source>Reference1</source>
<url>http://localhost/badvulnerability.htm</url>
<name>Reference Name</name>
</reference>
<reference>
<source>MISC</source>
<url>http://localhost2/reference_for_badvulnerability.pdf</url>
<name>Reference for a bad vulnerability</name>
</reference>
</references>
<vulnerableSoftware>
<software>cpe:/a:component2:component2:1.0</software>
</vulnerableSoftware>
</vulnerability>"""

        vulnerability = ElementTree.fromstring(finding_xml)

        expected_references = 'name: Reference Name\nsource: Reference1\nurl: http://localhost/badvulnerability.htm\n\n'
        expected_references += 'name: Reference for a bad vulnerability\nsource: MISC\n'
        expected_references += 'url: http://localhost2/reference_for_badvulnerability.pdf\n\n'

        testfile = TestFile('dp_finding.xml', finding_xml)
        parser = DependencyCheckParser(testfile, Test())
        finding = parser.get_finding_from_vulnerability(vulnerability,
                                                        'testfile.jar', Test())
        self.assertEqual('testfile.jar | CVE-0000-0001', finding.title)
        self.assertEqual('High', finding.severity)
        self.assertEqual(
                'CWE-00 Bad Vulnerability\n\nDescription of a bad vulnerability.',
                finding.description)
        self.assertEqual(expected_references, finding.references)