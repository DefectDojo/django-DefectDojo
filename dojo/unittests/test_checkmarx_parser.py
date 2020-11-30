from django.test import TestCase

from dojo.models import Test, Engagement, Product
from dojo.tools.checkmarx.parser import CheckmarxXMLParser
import datetime


class TestCheckmarxParser(TestCase):
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

# ----------------------------------------------------------------------------
# no_finding
# ----------------------------------------------------------------------------
    # Default checkmarx scanner, aggregated by sink file_path
    def test_file_name_aggregated_parse_file_with_no_vulnerabilities_has_no_findings(self):
        my_file_handle, product, engagement, test = self.init('dojo/unittests/scans/checkmarx/no_finding.xml')
        self.parser = CheckmarxXMLParser(my_file_handle, test)
        self.teardown(my_file_handle)
        self.check_parse_file_with_no_vulnerabilities_has_no_findings(self.parser)

    # Checkmarx detailed scanner, with all vulnerabilities from checkmarx
    def test_detailed_parse_file_with_no_vulnerabilities_has_no_findings(self):
        my_file_handle, product, engagement, test = self.init("dojo/unittests/scans/checkmarx/no_finding.xml")
        self.parser = CheckmarxXMLParser(my_file_handle, test, 'detailed')
        self.teardown(my_file_handle)
        self.check_parse_file_with_no_vulnerabilities_has_no_findings(self.parser)

# ----------------------------------------------------------------------------
# single finding and verify all findings fields
# ----------------------------------------------------------------------------
    def check_parse_file_with_no_vulnerabilities_has_no_findings(self, parser):
        self.assertEqual(0, len(parser.items))

    def test_file_name_aggregated_parse_file_with_single_vulnerability_has_single_finding(self):
        my_file_handle, product, engagement, test = self.init("dojo/unittests/scans/checkmarx/single_finding.xml")
        self.parser = CheckmarxXMLParser(my_file_handle, test)
        self.teardown(my_file_handle)
        # Verifications common to both parsers
        self.check_parse_file_with_single_vulnerability_has_single_finding(self.parser)
        # Fields that differ from detailed scanner
        item = self.parser.items[0]
        self.assertEqual(str, type(item.description))
        self.assertMultiLineEqual("**Category:** PCI DSS v3.2;PCI DSS (3.2) - 6.5.7 - Cross-site scripting (XSS),OWASP Top 10 2013;A3-Cross-Site Scripting (XSS),FISMA 2014;System And Information Integrity,NIST SP 800-53;SI-15 Information Output Filtering (P0),OWASP Top 10 2017;A7-Cross-Site Scripting (XSS)\n"
            "**Language:** Java\n"
            "**Group:** Java High Risk\n"
            "**Status:** New\n"
            "**Finding Link:** [https://checkmarxserver.com/CxWebClient/ViewerMain.aspx?scanid=1000227&projectid=121&pathid=28](https://checkmarxserver.com/CxWebClient/ViewerMain.aspx?scanid=1000227&projectid=121&pathid=28)\n"
            "\n"
            "-----\n"
            "<b>Source filename: </b>WebGoat/webgoat-lessons/missing-function-ac/src/main/java/org/owasp/webgoat/plugin/Users.java\n"
            "<b>Source line number: </b> 39\n"
            "<b>Source object: </b> executeQuery\n"
            "\n"
            "<b>Sink filename: </b>WebGoat/webgoat-lessons/missing-function-ac/src/main/java/org/owasp/webgoat/plugin/Users.java\n"
            "<b>Sink line number: </b> 58\n"
            "<b>Sink object: </b> allUsersMap",
            item.description)
        self.assertEqual(1, item.nb_occurences)

    def test_detailed_parse_file_with_single_vulnerability_has_single_finding(self):
        my_file_handle, product, engagement, test = self.init("dojo/unittests/scans/checkmarx/single_finding.xml")
        self.parser = CheckmarxXMLParser(my_file_handle, test, 'detailed')
        self.teardown(my_file_handle)
        # Verifications common to both parsers
        self.check_parse_file_with_single_vulnerability_has_single_finding(self.parser)
        # Fields that differ from aggregated scanner
        item = self.parser.items[0]
        self.assertEqual(str, type(item.description))
        self.assertMultiLineEqual("**Category:** PCI DSS v3.2;PCI DSS (3.2) - 6.5.7 - Cross-site scripting (XSS),OWASP Top 10 2013;A3-Cross-Site Scripting (XSS),FISMA 2014;System And Information Integrity,NIST SP 800-53;SI-15 Information Output Filtering (P0),OWASP Top 10 2017;A7-Cross-Site Scripting (XSS)\n"
            "**Language:** Java\n"
            "**Group:** Java High Risk\n"
            "**Status:** New\n"
            "**Finding Link:** [https://checkmarxserver.com/CxWebClient/ViewerMain.aspx?scanid=1000227&projectid=121&pathid=28](https://checkmarxserver.com/CxWebClient/ViewerMain.aspx?scanid=1000227&projectid=121&pathid=28)\n"
            "\n"
            "-----\n"
            "**Line Number:** 39\n"
            "**Column:** 59\n"
            "**Source Object:** executeQuery\n"
            "**Number:** 39\n"
            "**Code:** ResultSet results = statement.executeQuery(query);\n"
            "-----\n"
            "**Line Number:** 39\n"
            "**Column:** 27\n"
            "**Source Object:** results\n"
            "**Number:** 39\n"
            "**Code:** ResultSet results = statement.executeQuery(query);\n"
            "-----\n"
            "**Line Number:** 46\n"
            "**Column:** 28\n"
            "**Source Object:** results\n"
            "**Number:** 46\n"
            "**Code:** while (results.next()) {\n"
            "-----\n"
            "**Line Number:** 47\n"
            "**Column:** 34\n"
            "**Source Object:** results\n"
            "**Number:** 47\n"
            "**Code:** int id = results.getInt(0);\n"
            "-----\n"
            "**Line Number:** 53\n"
            "**Column:** 64\n"
            "**Source Object:** getString\n"
            "**Number:** 53\n"
            "**Code:** userMap.put(\"cookie\", results.getString(5));\n"
            "-----\n"
            "**Line Number:** 53\n"
            "**Column:** 36\n"
            "**Source Object:** put\n"
            "**Number:** 53\n"
            "**Code:** userMap.put(\"cookie\", results.getString(5));\n"
            "-----\n"
            "**Line Number:** 54\n"
            "**Column:** 25\n"
            "**Source Object:** userMap\n"
            "**Number:** 54\n"
            "**Code:** userMap.put(\"loginCOunt\",Integer.toString(results.getInt(6)));\n"
            "-----\n"
            "**Line Number:** 55\n"
            "**Column:** 44\n"
            "**Source Object:** userMap\n"
            "**Number:** 55\n"
            "**Code:** allUsersMap.put(id,userMap);\n"
            "-----\n"
            "**Line Number:** 55\n"
            "**Column:** 40\n"
            "**Source Object:** put\n"
            "**Number:** 55\n"
            "**Code:** allUsersMap.put(id,userMap);\n"
            "-----\n"
            "**Line Number:** 58\n"
            "**Column:** 28\n"
            "**Source Object:** allUsersMap\n"
            "**Number:** 58\n"
            "**Code:** return allUsersMap;\n"
            "-----\n",
            item.description)
        self.assertEqual(str, type(item.line))
        self.assertEqual("58", item.line)
        # Added field for detailed scanner
        self.assertEqual(str, type(item.unique_id_from_tool))
        # unique_id_from_tool update from PathId to SimilarityId+PathId
        self.assertEqual("157422106028", item.unique_id_from_tool)
        self.assertEqual(str, type(item.sast_source_object))
        self.assertEqual("executeQuery", item.sast_source_object)
        self.assertEqual(str, type(item.sast_sink_object))
        self.assertEqual("allUsersMap", item.sast_sink_object)
        self.assertEqual(str, type(item.sast_source_line))
        self.assertEqual("39", item.sast_source_line)
        self.assertEqual(str, type(item.sast_source_file_path))
        self.assertEqual("WebGoat/webgoat-lessons/missing-function-ac/src/main/java/org/owasp/webgoat/plugin/Users.java", item.sast_source_file_path)
        self.assertIsNone(item.nb_occurences)

    def check_parse_file_with_single_vulnerability_has_single_finding(self, parser):
        self.assertEqual(1, len(self.parser.items))
        # check content
        item = self.parser.items[0]
        self.assertEqual(str, type(self.parser.items[0].title))
        self.assertEqual("Stored XSS (Users.java)", item.title)
        self.assertEqual(int, type(item.cwe))
        self.assertEqual(79, item.cwe)
        self.assertEqual(bool, type(item.active))
        self.assertEqual(False, item.active)
        self.assertEqual(bool, type(item.verified))
        self.assertEqual(False, item.verified)
        self.assertEqual(bool, type(item.false_p))
        self.assertEqual(False, item.false_p)
        self.assertEqual(str, type(item.severity))
        self.assertEqual("High", item.severity)
        self.assertEqual(str, type(item.numerical_severity))
        self.assertEqual("S1", item.numerical_severity)
        self.assertEqual(str, type(item.mitigation))
        self.assertEqual("N/A", item.mitigation)
        self.assertEqual(str, type(item.references))
        self.assertEqual("", item.references)
        self.assertEqual(str, type(item.file_path))
        self.assertEqual("WebGoat/webgoat-lessons/missing-function-ac/src/main/java/org/owasp/webgoat/plugin/Users.java", item.file_path)
        self.assertEqual(str, type(item.url))
        self.assertEqual("N/A", item.url)
        # ScanStart
        self.assertEqual(datetime.datetime, type(item.date))
        self.assertEqual(datetime.datetime(2018, 2, 25, 11, 35, 52), item.date)
        self.assertEqual(bool, type(item.static_finding))
        self.assertEqual(True, item.static_finding)

# ----------------------------------------------------------------------------
# single finding false positive
# ----------------------------------------------------------------------------
    def test_file_name_aggregated_parse_file_with_false_positive_is_false_positive(self):
        my_file_handle, product, engagement, test = self.init("dojo/unittests/scans/checkmarx/single_finding_false_positive.xml")
        self.parser = CheckmarxXMLParser(my_file_handle, test)
        self.teardown(my_file_handle)
        # Verifications common to both parsers
        self.check_parse_file_with_false_positive_is_false_positive(self.parser)

    def test_detailed_parse_file_with_false_positive_is_false_positive(self):
        my_file_handle, product, engagement, test = self.init("dojo/unittests/scans/checkmarx/single_finding_false_positive.xml")
        self.parser = CheckmarxXMLParser(my_file_handle, test, 'detailed')
        self.teardown(my_file_handle)
        # Verifications common to both parsers
        self.check_parse_file_with_false_positive_is_false_positive(self.parser)

    def check_parse_file_with_false_positive_is_false_positive(self, parser):
        self.assertEqual(1, len(self.parser.items))
        # check content
        item = self.parser.items[0]
        self.assertEqual(bool, type(item.active))
        self.assertEqual(False, item.active)
        self.assertEqual(bool, type(item.verified))
        self.assertEqual(False, item.verified)
        self.assertEqual(bool, type(item.false_p))
        self.assertEqual(True, item.false_p)

# ----------------------------------------------------------------------------
# two findings with the same aggregate keys, but one is false positive
# the result should be one exploitable finding, even though the first one found was false positive
# ----------------------------------------------------------------------------

    def test_file_name_aggregated_parse_file_with_two_aggregated_findings_one_is_false_p(self):
        my_file_handle, product, engagement, test = self.init("dojo/unittests/scans/checkmarx/two_aggregated_findings_one_is_false_positive.xml")
        self.parser = CheckmarxXMLParser(my_file_handle, test)
        self.teardown(my_file_handle)
        self.assertEqual(1, len(self.parser.items))
        # check content for aggregated finding
        item = self.parser.items[0]
        # finding is never active/verified yet at this time
        self.assertEqual(bool, type(item.active))
        self.assertEqual(False, item.active)
        self.assertEqual(bool, type(item.verified))
        self.assertEqual(False, item.verified)
        self.assertEqual(bool, type(item.false_p))
        self.assertEqual(False, item.false_p)

# ----------------------------------------------------------------------------
# multiple_findings : source filename = sink filename.
# ----------------------------------------------------------------------------

    def test_file_name_aggregated_parse_file_with_multiple_vulnerabilities_has_multiple_findings(self):
        my_file_handle, product, engagement, test = self.init("dojo/unittests/scans/checkmarx/multiple_findings.xml")
        self.parser = CheckmarxXMLParser(my_file_handle, test)
        self.teardown(my_file_handle)
        # checkmarx says 3 but we're down to 2 due to the aggregation on sink filename rather than source filename + source line number + sink filename + sink line number
        self.assertEqual(2, len(self.parser.items))

    def test_detailed_parse_file_with_multiple_vulnerabilities_has_multiple_findings(self):
        my_file_handle, product, engagement, test = self.init("dojo/unittests/scans/checkmarx/multiple_findings.xml")
        self.parser = CheckmarxXMLParser(my_file_handle, test, 'detailed')
        self.teardown(my_file_handle)
        self.assertEqual(3, len(self.parser.items))

# ----------------------------------------------------------------------------
# multiple_findings : different sourceFilename but same sinkFilename
# ----------------------------------------------------------------------------
    def test_file_name_aggregated_parse_file_with_different_sourceFilename_same_sinkFilename_is_aggregated(self):
        my_file_handle, product, engagement, test = self.init("dojo/unittests/scans/checkmarx/multiple_findings_different_sourceFilename_same_sinkFilename.xml")
        self.parser = CheckmarxXMLParser(my_file_handle, test)
        self.teardown(my_file_handle)
        # aggregation is on sink filename so all vuln with different source filenames are aggregated
        self.assertEqual(1, len(self.parser.items))
        item = self.parser.items[0]
        # nb_occurences counts the number of aggregated vulnerabilities from tool
        self.assertEqual(2, self.parser.items[0].nb_occurences)

    def test_detailed_parse_file_with_different_sourceFilename_same_sinkFilename_is_not_aggregated(self):
        my_file_handle, product, engagement, test = self.init("dojo/unittests/scans/checkmarx/multiple_findings_different_sourceFilename_same_sinkFilename.xml")
        self.parser = CheckmarxXMLParser(my_file_handle, test, 'detailed')
        self.teardown(my_file_handle)
        self.assertEqual(2, len(self.parser.items))
        self.assertIsNone(self.parser.items[0].nb_occurences)
        self.assertIsNone(self.parser.items[1].nb_occurences)

# ----------------------------------------------------------------------------
# multiple_findings : same sourceFilename but different sinkFilename
# ----------------------------------------------------------------------------
    def test_file_name_aggregated_parse_file_with_same_sourceFilename_different_sinkFilename_is_not_aggregated(self):
        my_file_handle, product, engagement, test = self.init("dojo/unittests/scans/checkmarx/multiple_findings_same_sourceFilename_different_sinkFilename.xml")
        self.parser = CheckmarxXMLParser(my_file_handle, test)
        self.teardown(my_file_handle)
        # aggregation is on sink filename but sink filename differ -> not aggregated
        self.assertEqual(2, len(self.parser.items))

    def test_detailed_parse_file_with_same_sourceFilename_different_sinkFilename_is_not_aggregated(self):
        my_file_handle, product, engagement, test = self.init("dojo/unittests/scans/checkmarx/multiple_findings_same_sourceFilename_different_sinkFilename.xml")
        self.parser = CheckmarxXMLParser(my_file_handle, test, 'detailed')
        self.teardown(my_file_handle)
        self.assertEqual(2, len(self.parser.items))

# ----------------------------------------------------------------------------
# utf-8 replacement char in various fields of the report. check all finding elements
# ----------------------------------------------------------------------------
    def test_file_name_aggregated_parse_file_with_utf8_replacement_char(self):
        my_file_handle, product, engagement, test = self.init("dojo/unittests/scans/checkmarx/utf8_replacement_char.xml")
        self.parser = CheckmarxXMLParser(my_file_handle, test)
        self.teardown(my_file_handle)
        # Verifications common to both parsers
        self.check_parse_file_with_utf8_replacement_char(self.parser)
        # Fields that differ from detailed scanner
        item = self.parser.items[0]
        self.assertEqual(str, type(item.description))
        self.assertMultiLineEqual("**Category:** PCI DSS v3.2;PCI DSS (3.2) - 6.5.7 - Cross-site scripting (XSS),OWASP Top 10 2013;A3-Cross-Site Scripting (XSS),FISMA 2014;System And Information Integrity,NIST SP 800-53;SI-15 Information Output Filtering (P0),OWASP Top 10 2017;A7-Cross-Site Scripting (XSS)\n"
            "**Language:** Java\n"
            "**Group:** Java High Risk\n"
            "**Status:** New\n"
            "**Finding Link:** [https://checkmarxserver.com/CxWebClient/ViewerMain.aspx?scanid=1000227&projectid=121&pathid=28](https://checkmarxserver.com/CxWebClient/ViewerMain.aspx?scanid=1000227&projectid=121&pathid=28)\n"
            "\n"
            "-----\n"
            "<b>Source filename: </b>WebGoat/webgoat-lessons/missing-function-ac/src/main/java/org/owasp/webgoat/plugin/Users.java�\n"
            "<b>Source line number: </b> 39\n"
            "<b>Source object: </b> executeQuery�\n"
            "\n"
            "<b>Sink filename: </b>WebGoat/webgoat-lessons/missing-function-ac/src/main/java/org/owasp/webgoat/plugin/Users.java�\n"
            "<b>Sink line number: </b> 58\n"
            "<b>Sink object: </b> allUsersMap�",
            item.description)
        self.assertIsNone(item.line)

    def test_detailed_parse_file_with_utf8_replacement_char(self):
        my_file_handle, product, engagement, test = self.init("dojo/unittests/scans/checkmarx/utf8_replacement_char.xml")
        self.parser = CheckmarxXMLParser(my_file_handle, test, 'detailed')
        self.teardown(my_file_handle)
        # Verifications common to both parsers
        self.check_parse_file_with_utf8_replacement_char(self.parser)
        # Fields that differ from aggregated scanner
        item = self.parser.items[0]
        self.assertEqual(str, type(item.description))
        self.assertMultiLineEqual("**Category:** PCI DSS v3.2;PCI DSS (3.2) - 6.5.7 - Cross-site scripting (XSS),OWASP Top 10 2013;A3-Cross-Site Scripting (XSS),FISMA 2014;System And Information Integrity,NIST SP 800-53;SI-15 Information Output Filtering (P0),OWASP Top 10 2017;A7-Cross-Site Scripting (XSS)\n"
            "**Language:** Java\n"
            "**Group:** Java High Risk\n"
            "**Status:** New\n"
            "**Finding Link:** [https://checkmarxserver.com/CxWebClient/ViewerMain.aspx?scanid=1000227&projectid=121&pathid=28](https://checkmarxserver.com/CxWebClient/ViewerMain.aspx?scanid=1000227&projectid=121&pathid=28)\n"
            "\n"
            "-----\n"
            "**Line Number:** 39\n"
            "**Column:** 59\n"
            "**Source Object:** executeQuery�\n"
            "**Number:** 39\n"
            "**Code:** ResultSet results = statement.executeQuery(query);//�\n"
            "-----\n"
            "**Line Number:** 39\n"
            "**Column:** 27\n"
            "**Source Object:** results\n"
            "**Number:** 39\n"
            "**Code:** ResultSet results = statement.executeQuery(query);\n"
            "-----\n"
            "**Line Number:** 46\n"
            "**Column:** 28\n"
            "**Source Object:** results\n"
            "**Number:** 46\n"
            "**Code:** while (results.next()) {\n"
            "-----\n"
            "**Line Number:** 47\n"
            "**Column:** 34\n"
            "**Source Object:** results\n"
            "**Number:** 47\n"
            "**Code:** int id = results.getInt(0);\n"
            "-----\n"
            "**Line Number:** 53\n"
            "**Column:** 64\n"
            "**Source Object:** getString\n"
            "**Number:** 53\n"
            "**Code:** userMap.put(\"cookie\", results.getString(5));\n"
            "-----\n"
            "**Line Number:** 53\n"
            "**Column:** 36\n"
            "**Source Object:** put\n"
            "**Number:** 53\n"
            "**Code:** userMap.put(\"cookie\", results.getString(5));\n"
            "-----\n"
            "**Line Number:** 54\n"
            "**Column:** 25\n"
            "**Source Object:** userMap\n"
            "**Number:** 54\n"
            "**Code:** userMap.put(\"loginCOunt\",Integer.toString(results.getInt(6)));\n"
            "-----\n"
            "**Line Number:** 55\n"
            "**Column:** 44\n"
            "**Source Object:** userMap\n"
            "**Number:** 55\n"
            "**Code:** allUsersMap.put(id,userMap);\n"
            "-----\n"
            "**Line Number:** 55\n"
            "**Column:** 40\n"
            "**Source Object:** put\n"
            "**Number:** 55\n"
            "**Code:** allUsersMap.put(id,userMap);\n"
            "-----\n"
            "**Line Number:** 58\n"
            "**Column:** 28\n"
            "**Source Object:** allUsersMap�\n"
            "**Number:** 58\n"
            "**Code:** return allUsersMap;\n"
            "-----\n",
            item.description)
        self.assertEqual(str, type(item.line))
        self.assertEqual("58", item.line)

    def check_parse_file_with_utf8_replacement_char(self, parser):
        self.assertEqual(1, len(self.parser.items))
        # check content
        item = self.parser.items[0]
        self.assertEqual(str, type(self.parser.items[0].title))
        self.assertEqual("Stored XSS (Users.java�)", item.title)
        self.assertEqual(int, type(item.cwe))
        self.assertEqual(79, item.cwe)
        self.assertEqual(bool, type(item.active))
        self.assertEqual(False, item.active)
        self.assertEqual(bool, type(item.verified))
        self.assertEqual(False, item.verified)
        self.assertEqual(bool, type(item.false_p))
        self.assertEqual(False, item.false_p)
        self.assertEqual(str, type(item.severity))
        self.assertEqual("High", item.severity)
        self.assertEqual(str, type(item.numerical_severity))
        self.assertEqual("S1", item.numerical_severity)
        self.assertEqual(str, type(item.mitigation))
        self.assertEqual("N/A", item.mitigation)
        self.assertEqual(str, type(item.references))
        self.assertEqual("", item.references)
        self.assertEqual(str, type(item.file_path))
        self.assertEqual("WebGoat/webgoat-lessons/missing-function-ac/src/main/java/org/owasp/webgoat/plugin/Users.java�", item.file_path)
        self.assertEqual(str, type(item.url))
        self.assertEqual("N/A", item.url)
        # ScanStart
        self.assertEqual(datetime.datetime, type(item.date))
        self.assertEqual(datetime.datetime(2018, 2, 25, 11, 35, 52), item.date)
        self.assertEqual(bool, type(item.static_finding))
        self.assertEqual(True, item.static_finding)

# ----------------------------------------------------------------------------
# more utf-8 non-ascii chars.
# ----------------------------------------------------------------------------
    def test_file_name_aggregated_parse_file_with_utf8_various_non_ascii_char(self):
        my_file_handle, product, engagement, test = self.init("dojo/unittests/scans/checkmarx/utf8_various_non_ascii_char.xml")
        self.parser = CheckmarxXMLParser(my_file_handle, test)
        self.teardown(my_file_handle)
        # Verifications common to both parsers
        self.check_parse_file_with_utf8_various_non_ascii_char(self.parser)
        # Fields that differ from detailed scanner
        item = self.parser.items[0]
        self.assertEqual(str, type(item.description))
        self.assertMultiLineEqual("**Category:** PCI DSS v3.2;PCI DSS (3.2) - 6.5.7 - Cross-site scripting (XSS),OWASP Top 10 2013;A3-Cross-Site Scripting (XSS),FISMA 2014;System And Information Integrity,NIST SP 800-53;SI-15 Information Output Filtering (P0),OWASP Top 10 2017;A7-Cross-Site Scripting (XSS)\n"
            "**Language:** Java\n"
            "**Group:** Java High Risk\n"
            "**Status:** New\n"
            "**Finding Link:** [https://checkmarxserver.com/CxWebClient/ViewerMain.aspx?scanid=1000227&projectid=121&pathid=28](https://checkmarxserver.com/CxWebClient/ViewerMain.aspx?scanid=1000227&projectid=121&pathid=28)\n"
            "\n"
            "-----\n"
            "<b>Source filename: </b>WebGoat/webgoat-lessons/missing-function-ac/src/main/java/org/owasp/webgoat/plugin/¡¢£¤¥¦§¨©ª«¬®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿĀāĂăĄąĆćĈĉĊċČčĎďĐđĒēĔĕĖėĘęĚěĜĝĞğĠġĢģĤĥĦħĨĩĪīĬĭĮįİıĲĳĴĵĶķĸĹĺĻļĽľĿŀŁłŃńŅņŇňŉŊŋŌōŎŏŐőŒœŔŕŖŗŘřŚśŜŝŞşŠšŢţŤťŦŧŨũŪūŬŭŮůŰűŲųŴŵŶŷŸŹźŻżŽžſUsers.java\n"
            "<b>Source line number: </b> 39\n"
            "<b>Source object: </b> executeQuery¡¢£¤¥¦§¨©ª«¬®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿĀāĂăĄąĆćĈĉĊċČčĎďĐđĒēĔĕĖėĘęĚěĜĝĞğĠġĢģĤĥĦħĨĩĪīĬĭĮįİıĲĳĴĵĶķĸĹĺĻļĽľĿŀŁłŃńŅņŇňŉŊŋŌōŎŏŐőŒœŔŕŖŗŘřŚśŜŝŞşŠšŢţŤťŦŧŨũŪūŬŭŮůŰűŲųŴŵŶŷŸŹźŻżŽžſ\n"
            "\n"
            "<b>Sink filename: </b>WebGoat/webgoat-lessons/missing-function-ac/src/main/java/org/owasp/webgoat/plugin/¡¢£¤¥¦§¨©ª«¬®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿĀāĂăĄąĆćĈĉĊċČčĎďĐđĒēĔĕĖėĘęĚěĜĝĞğĠġĢģĤĥĦħĨĩĪīĬĭĮįİıĲĳĴĵĶķĸĹĺĻļĽľĿŀŁłŃńŅņŇňŉŊŋŌōŎŏŐőŒœŔŕŖŗŘřŚśŜŝŞşŠšŢţŤťŦŧŨũŪūŬŭŮůŰűŲųŴŵŶŷŸŹźŻżŽžſUsers.java\n"
            "<b>Sink line number: </b> 58\n"
            "<b>Sink object: </b> allUsersMap¡¢£¤¥¦§¨©ª«¬®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿĀāĂăĄąĆćĈĉĊċČčĎďĐđĒēĔĕĖėĘęĚěĜĝĞğĠġĢģĤĥĦħĨĩĪīĬĭĮįİıĲĳĴĵĶķĸĹĺĻļĽľĿŀŁłŃńŅņŇňŉŊŋŌōŎŏŐőŒœŔŕŖŗŘřŚśŜŝŞşŠšŢţŤťŦŧŨũŪūŬŭŮůŰűŲųŴŵŶŷŸŹźŻżŽžſ",
            item.description)
        self.assertIsNone(item.line)

    def test_detailed_parse_file_with_utf8_various_non_ascii_char(self):
        my_file_handle, product, engagement, test = self.init("dojo/unittests/scans/checkmarx/utf8_various_non_ascii_char.xml")
        self.parser = CheckmarxXMLParser(my_file_handle, test, 'detailed')
        self.teardown(my_file_handle)
        # Verifications common to both parsers
        self.check_parse_file_with_utf8_various_non_ascii_char(self.parser)
        # Fields that differ from aggregated scanner
        item = self.parser.items[0]
        self.assertEqual(str, type(item.description))
        self.assertMultiLineEqual("**Category:** PCI DSS v3.2;PCI DSS (3.2) - 6.5.7 - Cross-site scripting (XSS),OWASP Top 10 2013;A3-Cross-Site Scripting (XSS),FISMA 2014;System And Information Integrity,NIST SP 800-53;SI-15 Information Output Filtering (P0),OWASP Top 10 2017;A7-Cross-Site Scripting (XSS)\n"
            "**Language:** Java\n"
            "**Group:** Java High Risk\n"
            "**Status:** New\n"
            "**Finding Link:** [https://checkmarxserver.com/CxWebClient/ViewerMain.aspx?scanid=1000227&projectid=121&pathid=28](https://checkmarxserver.com/CxWebClient/ViewerMain.aspx?scanid=1000227&projectid=121&pathid=28)\n"
            "\n"
            "-----\n"
            "**Line Number:** 39\n"
            "**Column:** 59\n"
            "**Source Object:** executeQuery¡¢£¤¥¦§¨©ª«¬®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿĀāĂăĄąĆćĈĉĊċČčĎďĐđĒēĔĕĖėĘęĚěĜĝĞğĠġĢģĤĥĦħĨĩĪīĬĭĮįİıĲĳĴĵĶķĸĹĺĻļĽľĿŀŁłŃńŅņŇňŉŊŋŌōŎŏŐőŒœŔŕŖŗŘřŚśŜŝŞşŠšŢţŤťŦŧŨũŪūŬŭŮůŰűŲųŴŵŶŷŸŹźŻżŽžſ\n"
            "**Number:** 39\n"
            "**Code:** ResultSet results = statement.executeQuery(query);\n"
            "-----\n"
            "**Line Number:** 39\n"
            "**Column:** 27\n"
            "**Source Object:** results\n"
            "**Number:** 39\n"
            "**Code:** ResultSet results = statement.executeQuery(query);//all latins non ascii with extended: U+00A1   to U+017F  (ref https://www.utf8-chartable.de/unicode-utf8-table.pl): ¡¢£¤¥¦§¨©ª«¬®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿĀāĂăĄąĆćĈĉĊċČčĎďĐđĒēĔĕĖėĘęĚěĜĝĞğĠġĢģĤĥĦħĨĩĪīĬĭĮįİıĲĳĴĵĶķĸĹĺĻļĽľĿŀŁłŃńŅņŇňŉŊŋŌōŎŏŐőŒœŔŕŖŗŘřŚśŜŝŞşŠšŢţŤťŦŧŨũŪūŬŭŮůŰűŲųŴŵŶŷŸŹźŻżŽžſ\n"
            "-----\n"
            "**Line Number:** 46\n"
            "**Column:** 28\n"
            "**Source Object:** results\n"
            "**Number:** 46\n"
            "**Code:** while (results.next()) { // other: ƒ\n"
            "-----\n"
            "**Line Number:** 47\n"
            "**Column:** 34\n"
            "**Source Object:** results\n"
            "**Number:** 47\n"
            "**Code:** int id = results.getInt(0);\n"
            "-----\n"
            "**Line Number:** 53\n"
            "**Column:** 64\n"
            "**Source Object:** getString\n"
            "**Number:** 53\n"
            "**Code:** userMap.put(\"cookie\", results.getString(5));\n"
            "-----\n"
            "**Line Number:** 53\n"
            "**Column:** 36\n"
            "**Source Object:** put\n"
            "**Number:** 53\n"
            "**Code:** userMap.put(\"cookie\", results.getString(5));\n"
            "-----\n"
            "**Line Number:** 54\n"
            "**Column:** 25\n"
            "**Source Object:** userMap\n"
            "**Number:** 54\n"
            "**Code:** userMap.put(\"loginCOunt\",Integer.toString(results.getInt(6)));\n"
            "-----\n"
            "**Line Number:** 55\n"
            "**Column:** 44\n"
            "**Source Object:** userMap\n"
            "**Number:** 55\n"
            "**Code:** allUsersMap.put(id,userMap);\n"
            "-----\n"
            "**Line Number:** 55\n"
            "**Column:** 40\n"
            "**Source Object:** put\n"
            "**Number:** 55\n"
            "**Code:** allUsersMap.put(id,userMap);\n"
            "-----\n"
            "**Line Number:** 58\n"
            "**Column:** 28\n"
            "**Source Object:** allUsersMap¡¢£¤¥¦§¨©ª«¬®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿĀāĂăĄąĆćĈĉĊċČčĎďĐđĒēĔĕĖėĘęĚěĜĝĞğĠġĢģĤĥĦħĨĩĪīĬĭĮįİıĲĳĴĵĶķĸĹĺĻļĽľĿŀŁłŃńŅņŇňŉŊŋŌōŎŏŐőŒœŔŕŖŗŘřŚśŜŝŞşŠšŢţŤťŦŧŨũŪūŬŭŮůŰűŲųŴŵŶŷŸŹźŻżŽžſ\n"
            "**Number:** 58\n"
            "**Code:** return allUsersMap;\n"
            "-----\n",
            item.description)
        self.assertEqual(str, type(item.line))
        self.assertEqual("58", item.line)

    def check_parse_file_with_utf8_various_non_ascii_char(self, parser):
        self.assertEqual(1, len(self.parser.items))
        # check content
        item = self.parser.items[0]
        self.assertEqual(str, type(self.parser.items[0].title))
        self.assertEqual("Stored XSS (¡¢£¤¥¦§¨©ª«¬®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿĀāĂăĄąĆćĈĉĊċČčĎďĐđĒēĔĕĖėĘęĚěĜĝĞğĠġĢģĤĥĦħĨĩĪīĬĭĮįİıĲĳĴĵĶķĸĹĺĻļĽľĿŀŁłŃńŅņŇňŉŊŋŌōŎŏŐőŒœŔŕŖŗŘřŚśŜŝŞşŠšŢţŤťŦŧŨũŪūŬŭŮůŰűŲųŴŵŶŷŸŹźŻżŽžſUsers.java)", item.title)
        self.assertEqual(int, type(item.cwe))
        self.assertEqual(79, item.cwe)
        self.assertEqual(bool, type(item.active))
        self.assertEqual(False, item.active)
        self.assertEqual(bool, type(item.verified))
        self.assertEqual(False, item.verified)
        self.assertEqual(bool, type(item.false_p))
        self.assertEqual(False, item.false_p)
        self.assertEqual(str, type(item.severity))
        self.assertEqual("High", item.severity)
        self.assertEqual(str, type(item.numerical_severity))
        self.assertEqual("S1", item.numerical_severity)
        self.assertEqual(str, type(item.mitigation))
        self.assertEqual("N/A", item.mitigation)
        self.assertEqual(str, type(item.references))
        self.assertEqual("", item.references)
        self.assertEqual(str, type(item.file_path))
        self.assertEqual("WebGoat/webgoat-lessons/missing-function-ac/src/main/java/org/owasp/webgoat/plugin/¡¢£¤¥¦§¨©ª«¬®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿĀāĂăĄąĆćĈĉĊċČčĎďĐđĒēĔĕĖėĘęĚěĜĝĞğĠġĢģĤĥĦħĨĩĪīĬĭĮįİıĲĳĴĵĶķĸĹĺĻļĽľĿŀŁłŃńŅņŇňŉŊŋŌōŎŏŐőŒœŔŕŖŗŘřŚśŜŝŞşŠšŢţŤťŦŧŨũŪūŬŭŮůŰűŲųŴŵŶŷŸŹźŻżŽžſUsers.java", item.file_path)
        self.assertEqual(str, type(item.url))
        self.assertEqual("N/A", item.url)
        # ScanStart
        self.assertEqual(datetime.datetime, type(item.date))
        self.assertEqual(datetime.datetime(2018, 2, 25, 11, 35, 52), item.date)
        self.assertEqual(bool, type(item.static_finding))
        self.assertEqual(True, item.static_finding)
