from django.test import TestCase

from dojo.models import Test, Engagement, Product
from dojo.tools.sonarqube.parser import SonarQubeHtmlParser


class TestSonarQubeParser(TestCase):
    # comment out to get full diff with big reports
    # maxDiff = None

    def init(self, reportFilename):
        my_file_handle = open(reportFilename)
        product = Product()
        engagement = Engagement()
        test = Test()
        engagement.product = product
        test.engagement = engagement
        return my_file_handle, product, engagement, test

    def teardown(self, my_file_handle):
        my_file_handle.close()

    # SonarQube Scan - no finding
    def test_file_name_aggregated_parse_file_with_no_vulnerabilities_has_no_findings(self):
        my_file_handle, product, engagement, test = self.init("dojo/unittests/scans/sonarqube/sonar-no-finding.html")
        self.parser = SonarQubeHtmlParser(my_file_handle, test)
        self.teardown(my_file_handle)
        self.check_parse_file_with_no_vulnerabilities_has_no_findings()

    # SonarQube Scan detailed - no finding
    def test_detailed_parse_file_with_no_vulnerabilities_has_no_findings(self):
        my_file_handle, product, engagement, test = self.init("dojo/unittests/scans/sonarqube/sonar-no-finding.html")
        self.parser = SonarQubeHtmlParser(my_file_handle, test, 'detailed')
        self.teardown(my_file_handle)
        self.check_parse_file_with_no_vulnerabilities_has_no_findings()

    # common verifications
    def check_parse_file_with_no_vulnerabilities_has_no_findings(self):
        self.assertEqual(0, len(self.parser.items))

    # SonarQube Scan - report with one vuln
    def test_file_name_aggregated_parse_file_with_single_vulnerability_has_single_finding(self):
        my_file_handle, product, engagement, test = self.init("dojo/unittests/scans/sonarqube/sonar-single-finding.html")
        self.parser = SonarQubeHtmlParser(my_file_handle, test)
        self.teardown(my_file_handle)
        # common verifications
        self.check_parse_file_with_single_vulnerability_has_single_finding()
        # specific verifications
        item = self.parser.items[0]
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
            "        \"user=\" + uname + \"&amp;password=\" + password);\n"
            "\n"
            "-----\n"
            "Occurences:\n"
            "Line: 66",
            item.description)
        self.assertIsNone(item.line)
        self.assertIsNone(item.unique_id_from_tool)
        self.assertEqual(int, type(item.nb_occurences))
        self.assertEqual(1, item.nb_occurences)

    def test_detailed_parse_file_with_single_vulnerability_has_single_finding(self):
        my_file_handle, product, engagement, test = self.init("dojo/unittests/scans/sonarqube/sonar-single-finding.html")
        self.parser = SonarQubeHtmlParser(my_file_handle, test, 'detailed')
        self.teardown(my_file_handle)
        # common verifications
        self.check_parse_file_with_single_vulnerability_has_single_finding()
        # specific verifications
        item = self.parser.items[0]
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
        self.assertEqual(str, type(item.line))
        self.assertEqual("66", item.line)
        self.assertEqual(str, type(item.unique_id_from_tool))
        self.assertEqual("AWK40IMu-pl6AHs22MnV", item.unique_id_from_tool)

    def check_parse_file_with_single_vulnerability_has_single_finding(self):
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
        self.assertEqual(str, type(item.severity))
        self.assertEqual("Critical", item.severity)
        self.assertEqual(str, type(item.numerical_severity))
        self.assertEqual("S0", item.numerical_severity)
        self.assertEqual(str, type(item.mitigation))
        self.assertEqual("'PASSWORD' detected in this expression, review this potentially hardcoded credential.", item.mitigation)
        self.assertEqual(str, type(item.references))
        self.assertMultiLineEqual(
            "squid:S2068\n"
            "OWASP Top 10 2017 Category A2\n"
            "MITRE, CWE-798\n"
            "MITRE, CWE-259\n"
            "CERT, MSC03-J.\n"
            "SANS Top 25\n"
            "Hard Coded Password",
            item.references)
        self.assertEqual(str, type(item.file_path))
        self.assertEqual("modules/jdbc-pool/src/main/java/org/apache/tomcat/jdbc/pool/DataSourceFactory.java", item.file_path)
        self.assertEqual(bool, type(item.static_finding))
        self.assertEqual(True, item.static_finding)
        self.assertEqual(bool, type(item.dynamic_finding))
        self.assertEqual(False, item.dynamic_finding)

    def test_detailed_parse_file_with_multiple_vulnerabilities_has_multiple_findings(self):
        my_file_handle, product, engagement, test = self.init("dojo/unittests/scans/sonarqube/sonar-6-findings.html")
        self.parser = SonarQubeHtmlParser(my_file_handle, test, 'detailed')
        self.teardown(my_file_handle)
        # common verifications
        self.check_parse_file_with_multiple_vulnerabilities_has_multiple_findings()

    def test_file_name_aggregated_parse_file_with_multiple_vulnerabilities_has_multiple_findings(self):
        my_file_handle, product, engagement, test = self.init("dojo/unittests/scans/sonarqube/sonar-6-findings.html")
        self.parser = SonarQubeHtmlParser(my_file_handle, test, 'detailed')
        self.teardown(my_file_handle)
        # common verifications
        # (there is no aggregation to be done here)
        self.check_parse_file_with_multiple_vulnerabilities_has_multiple_findings()

    def check_parse_file_with_multiple_vulnerabilities_has_multiple_findings(self):
        self.assertEqual(6, len(self.parser.items))

    # Test parsing when the vulnerability details include a table, with tr and td that should be ignored when looking for list of rules
    def test_detailed_parse_file_with_table_in_table(self):
        my_file_handle, product, engagement, test = self.init("dojo/unittests/scans/sonarqube/sonar-table-in-table.html")
        self.parser = SonarQubeHtmlParser(my_file_handle, test, 'detailed')
        self.teardown(my_file_handle)
        self.assertEqual(1, len(self.parser.items))

        # check content
        item = self.parser.items[0]
        self.assertEqual(str, type(self.parser.items[0].title))
        self.assertEqual("\"clone\" should not be overridden", item.title)
        self.assertEqual(int, type(item.cwe))
        self.assertEqual(0, item.cwe)
        self.assertEqual(bool, type(item.active))
        self.assertEqual(False, item.active)
        self.assertEqual(bool, type(item.verified))
        self.assertEqual(False, item.verified)
        self.assertEqual(str, type(item.description))
        self.assertMultiLineEqual("Many consider clone and Cloneable broken in Java, largely because the rules for overriding clone are tricky\n"
            "and difficult to get right, according to Joshua Bloch:\n"
            "\n"
            "  Object's clone method is very tricky. It's based on field copies, and it's \"extra-linguistic.\" It creates an object without calling a constructor.\n"
            "  There are no guarantees that it preserves the invariants established by the constructors. There have been lots of bugs over the years, both in and\n"
            "  outside Sun, stemming from the fact that if you just call super.clone repeatedly up the chain until you have cloned an object, you have a shallow\n"
            "  copy of the object. The clone generally shares state with the object being cloned. If that state is mutable, you don't have two independent objects.\n"
            "  If you modify one, the other changes as well. And all of a sudden, you get random behavior.\n"
            "\n"
            "A copy constructor or copy factory should be used instead.\n"
            "This rule raises an issue when clone is overridden, whether or not Cloneable is implemented.\n"
            "**Noncompliant Code Example**\n"
            "\n"
            "public class MyClass {\n"
            "  // ...\n"
            "\n"
            "  public Object clone() { // Noncompliant\n"
            "    //...\n"
            "  }\n"
            "}\n"
            "\n"
            "**Compliant Solution**\n"
            "\n"
            "public class MyClass {\n"
            "  // ...\n"
            "\n"
            "  MyClass (MyClass source) {\n"
            "    //...\n"
            "  }\n"
            "}",
            item.description)
        self.assertEqual(str, type(item.severity))
        self.assertEqual("Critical", item.severity)
        self.assertEqual(str, type(item.numerical_severity))
        self.assertEqual("S0", item.numerical_severity)
        self.assertEqual(str, type(item.mitigation))
        self.assertEqual("Remove this \"clone\" implementation; use a copy constructor or copy factory instead.", item.mitigation)
        self.assertEqual(str, type(item.references))
        self.assertMultiLineEqual(
            "squid:S2975\n"
            "Copy Constructor versus Cloning\n"
            "S2157\n"
            "S1182",
            item.references)
        self.assertEqual(str, type(item.file_path))
        self.assertEqual("java/org/apache/catalina/util/URLEncoder.java", item.file_path)
        self.assertEqual(str, type(item.line))
        self.assertEqual("190", item.line)
        self.assertEqual(str, type(item.unique_id_from_tool))
        self.assertEqual("AWK40IMu-pl6AHs22MnV", item.unique_id_from_tool)
        self.assertEqual(bool, type(item.static_finding))
        self.assertEqual(True, item.static_finding)
        self.assertEqual(bool, type(item.dynamic_finding))
        self.assertEqual(False, item.dynamic_finding)

    # the vulnerability's rule is not in the list of rules
    def test_detailed_parse_file_with_rule_undefined(self):
        my_file_handle, product, engagement, test = self.init("dojo/unittests/scans/sonarqube/sonar-rule-undefined.html")
        self.parser = SonarQubeHtmlParser(my_file_handle, test, 'detailed')
        self.teardown(my_file_handle)
        self.assertEqual(1, len(self.parser.items))

        # check content
        item = self.parser.items[0]
        self.assertEqual(str, type(self.parser.items[0].title))
        self.assertEqual("\"clone\" should not be overridden", item.title)
        self.assertEqual(int, type(item.cwe))
        # no rule found -> 0
        self.assertEqual(0, item.cwe)
        self.assertEqual(bool, type(item.active))
        self.assertEqual(False, item.active)
        self.assertEqual(bool, type(item.verified))
        self.assertEqual(False, item.verified)
        self.assertEqual(str, type(item.description))
        self.assertEqual("No description provided", item.description)
        self.assertEqual(str, type(item.severity))
        self.assertEqual("Critical", item.severity)
        self.assertEqual(str, type(item.numerical_severity))
        self.assertEqual("S0", item.numerical_severity)
        self.assertEqual(str, type(item.mitigation))
        self.assertEqual("Remove this \"clone\" implementation; use a copy constructor or copy factory instead.", item.mitigation)
        self.assertEqual(str, type(item.references))
        self.assertEqual("", item.references)
        self.assertEqual(str, type(item.file_path))
        self.assertEqual("java/org/apache/catalina/util/URLEncoder.java", item.file_path)
        self.assertEqual(str, type(item.line))
        self.assertEqual("190", item.line)
        self.assertEqual(str, type(item.unique_id_from_tool))
        self.assertEqual("AWK40IMu-pl6AHs22MnV", item.unique_id_from_tool)
        self.assertEqual(bool, type(item.static_finding))
        self.assertEqual(True, item.static_finding)
        self.assertEqual(bool, type(item.dynamic_finding))
        self.assertEqual(False, item.dynamic_finding)

    # SonarQube Scan - report with aggregations to be made
    def test_file_name_aggregated_parse_file_with_vuln_on_same_filename(self):
        my_file_handle, product, engagement, test = self.init("dojo/unittests/scans/sonarqube/sonar-4-findings-3-to-aggregate.html")
        self.parser = SonarQubeHtmlParser(my_file_handle, test)
        self.teardown(my_file_handle)
        # specific verifications
        self.assertEqual(2, len(self.parser.items))
        # checking both items because they aren't always in the same order
        item1 = self.parser.items[0]
        item2 = self.parser.items[1]
        if item1.nb_occurences == 3:
            aggregatedItem = item1
            # there is nothing to aggregate on the other finding
            self.assertEqual(int, type(item2.nb_occurences))
            self.assertEqual(1, item2.nb_occurences)
        elif item2.nb_occurences == 3:
            aggregatedItem = item2
            # there is nothing to aggregate on the other finding
            self.assertEqual(int, type(item1.nb_occurences))
            self.assertEqual(1, item1.nb_occurences)
        else:
            self.fail("cannot find aggregated item")
        self.assertEqual(str, type(aggregatedItem.description))
        self.assertMultiLineEqual("Because it is easy to extract strings from a compiled application, credentials should never be hard-coded. Do so, and they're almost guaranteed to\n"
            "end up in the hands of an attacker. This is particularly true for applications that are distributed.\n"
            "Credentials should be stored outside of the code in a strongly-protected encrypted configuration file or database.\n"
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
            "        \"user=\" + uname + \"&amp;password=\" + password);\n"
            "\n"
            "-----\n"
            "Occurences:\n"
            "Line: 12\n"
            "Line: 13\n"
            "Line: 14",
            aggregatedItem.description)
        self.assertIsNone(aggregatedItem.line)
        self.assertIsNone(aggregatedItem.unique_id_from_tool)
        self.assertEqual(int, type(aggregatedItem.nb_occurences))

    # SonarQube Scan detailed - report with aggregations to be made
    def test_detailed_parse_file_with_vuln_on_same_filename(self):
        my_file_handle, product, engagement, test = self.init("dojo/unittests/scans/sonarqube/sonar-4-findings-3-to-aggregate.html")
        self.parser = SonarQubeHtmlParser(my_file_handle, test, 'detailed')
        self.teardown(my_file_handle)
        # specific verifications
        self.assertEqual(4, len(self.parser.items))
