from django.test import TestCase

from dojo.models import Test, Engagement, Product
from dojo.tools.sonarqube.parser import SonarQubeHtmlParser


class TestSonarQubeParser(TestCase):

    def test_parse_file_with_no_vulnerabilities_has_no_findings(self):
        my_file_handle = open("dojo/unittests/scans/sonarqube/sonar-no-finding.html")
        product = Product()
        engagement = Engagement()
        test = Test()
        engagement.product = product
        test.engagement = engagement
        self.parser = SonarQubeHtmlParser(my_file_handle, test)
        my_file_handle.close()
        self.assertEqual(0, len(self.parser.items))

    def test_parse_file_with_single_vulnerability_has_single_finding(self):
        my_file_handle = open("dojo/unittests/scans/sonarqube/sonar-single-finding.html")
        product = Product()
        engagement = Engagement()
        test = Test()
        engagement.product = product
        test.engagement = engagement
        self.parser = SonarQubeHtmlParser(my_file_handle, test)
        my_file_handle.close()
        self.assertEqual(1, len(self.parser.items))

        # check content
        item = self.parser.items[0]
        self.assertEqual(str, type(self.parser.items[0].title))
        self.assertEqual("Credentials should not be hard-coded", item.title)
        self.assertEqual(int, type(item.cwe))
        # This is only the first CWE in the list!
        self.assertEqual(798, item.cwe)
        self.assertEqual(bool, type(item.active))
        self.assertEqual(False, item.active)
        self.assertEqual(bool, type(item.verified))
        self.assertEqual(False, item.verified)
        self.assertEqual(str, type(item.description))
        self.assertMultiLineEqual("Because it is easy to extract strings from a compiled application, credentials should never be hard-coded. Do so, and they're almost guaranteed to\n"
            "end up in the hands of an attacker. This is particularly true for applications that are distributed.\n"
            "Credentials should be stored outside of the code in a strongly-protected encrypted configuration file or database.\n"
            "It's recommended to customize the configuration of this rule with additional credential words such as \"oauthToken\", \"secret\", ...\n"
            "**Noncompliant Code Example**\n"
            "\n"
            "Connection conn = null;\n"
            "try {\n"
            "  conn = DriverManager.getConnection(\"jdbc:mysql://localhost/test?\" +\n"
            "        \"user=steve&amp;password=blue\"); // Noncompliant\n"
            "  String uname = \"steve\";\n"
            "  String password = \"blue\";\n"
            "  conn = DriverManager.getConnection(\"jdbc:mysql://localhost/test?\" +\n"
            "        \"user=\" + uname + \"&amp;password=\" + password); // Noncompliant\n"
            "\n"
            "  java.net.PasswordAuthentication pa = new java.net.PasswordAuthentication(\"userName\", \"1234\".toCharArray());  // Noncompliant\n"
            "\n"
            "**Compliant Solution**\n"
            "\n"
            "Connection conn = null;\n"
            "try {\n"
            "  String uname = getEncryptedUser();\n"
            "  String password = getEncryptedPass();\n"
            "  conn = DriverManager.getConnection(\"jdbc:mysql://localhost/test?\" +\n"
            "        \"user=\" + uname + \"&amp;password=\" + password);",
            item.description)

        self.assertEqual(str, type(item.severity))
        self.assertEqual("Critical", item.severity)
        self.assertEqual(str, type(item.numerical_severity))
        self.assertEqual("S0", item.numerical_severity)
        self.assertEqual(str, type(item.mitigation))
        self.assertEqual("'PASSWORD' detected in this expression, review this potentially hardcoded credential.", item.mitigation)
        self.assertEqual(str, type(item.references))
        self.assertMultiLineEqual("OWASP Top 10 2017 Category A2\n"
            "MITRE, CWE-798\n"
            "MITRE, CWE-259\n"
            "CERT, MSC03-J.\n"
            "SANS Top 25\n"
            "Hard Coded Password\n",
            item.references)
        self.assertEqual(str, type(item.file_path))
        self.assertEqual("tomcat_180410:modules/jdbc-pool/src/main/java/org/apache/tomcat/jdbc/pool/DataSourceFactory.java", item.file_path)
        self.assertEqual(str, type(item.line))
        self.assertEqual("66", item.line)
        self.assertEqual(bool, type(item.static_finding))
        self.assertEqual(True, item.static_finding)
        self.assertEqual(bool, type(item.dynamic_finding))
        self.assertEqual(False, item.dynamic_finding)


    def test_parse_file_with_multiple_vulnerabilities_has_multiple_findings(self):
        my_file_handle = open("dojo/unittests/scans/sonarqube/sonar-6-findings.html")
        product = Product()
        engagement = Engagement()
        test = Test()
        engagement.product = product
        test.engagement = engagement
        self.parser = SonarQubeHtmlParser(my_file_handle, test)
        my_file_handle.close()
        self.assertEqual(6, len(self.parser.items))
