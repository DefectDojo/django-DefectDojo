from django.test import TestCase

from dojo.models import Test, Engagement, Product
from dojo.tools.checkmarx.parser import CheckmarxXMLParser
import datetime


class TestCheckmarxParser(TestCase):

    def test_parse_file_with_no_vulnerabilities_has_no_findings(self):
        my_file_handle = open("dojo/unittests/scans/checkmarx/no_finding.xml")
        product = Product()
        engagement = Engagement()
        test = Test()
        engagement.product = product
        test.engagement = engagement
        self.parser = CheckmarxXMLParser(my_file_handle, test)
        my_file_handle.close()
        self.assertEqual(0, len(self.parser.items))

    def test_parse_file_with_single_vulnerability_has_single_finding(self):
        my_file_handle = open("dojo/unittests/scans/checkmarx/single_finding.xml")
        product = Product()
        engagement = Engagement()
        test = Test()
        engagement.product = product
        test.engagement = engagement
        self.parser = CheckmarxXMLParser(my_file_handle, test)
        my_file_handle.close()
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
        self.assertEqual(str, type(item.description))
        self.assertMultiLineEqual("**Category:** PCI DSS v3.2;PCI DSS (3.2) - 6.5.7 - Cross-site scripting (XSS),OWASP Top 10 2013;A3-Cross-Site Scripting (XSS),FISMA 2014;System And Information Integrity,NIST SP 800-53;SI-15 Information Output Filtering (P0),OWASP Top 10 2017;A7-Cross-Site Scripting (XSS)\n"
            "**Language:** Java\n"
            "**Group:** Java High Risk\n"
            "**Status:** New\n"
            "**Finding Link:** [https://checkmarxserver.com/CxWebClient/ViewerMain.aspx?scanid=1000227&projectid=121&pathid=28](https://checkmarxserver.com/CxWebClient/ViewerMain.aspx?scanid=1000227&projectid=121&pathid=28)\n"
            "\n"
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
        self.assertEqual(str, type(item.line))
        self.assertEqual("58", item.line)
        self.assertEqual(str, type(item.url))
        self.assertEqual("N/A", item.url)
        # ScanStart
        self.assertEqual(datetime.datetime, type(item.date))
        self.assertEqual(datetime.datetime(2018, 2, 25, 11, 35, 52), item.date)
        self.assertEqual(bool, type(item.static_finding))
        self.assertEqual(True, item.static_finding)

    def test_parse_file_with_multiple_vulnerabilities_has_multiple_findings(self):
        my_file_handle = open("dojo/unittests/scans/checkmarx/multiple_findings.xml")
        product = Product()
        engagement = Engagement()
        test = Test()
        engagement.product = product
        test.engagement = engagement
        self.parser = CheckmarxXMLParser(my_file_handle, test)
        my_file_handle.close()
        # checkmarx says 3 but we're down to 2 due to the aggregation on sink filename rather than source filename + source line number + sink filename + sink line number
        self.assertEqual(2, len(self.parser.items))

    def test_parse_file_with_utf8_replacement_char(self):
        my_file_handle = open("dojo/unittests/scans/checkmarx/utf8_replacement_char.xml")
        product = Product()
        engagement = Engagement()
        test = Test()
        engagement.product = product
        test.engagement = engagement
        self.parser = CheckmarxXMLParser(my_file_handle, test)
        my_file_handle.close()
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
        self.assertEqual(str, type(item.description))
        self.assertMultiLineEqual("**Category:** PCI DSS v3.2;PCI DSS (3.2) - 6.5.7 - Cross-site scripting (XSS),OWASP Top 10 2013;A3-Cross-Site Scripting (XSS),FISMA 2014;System And Information Integrity,NIST SP 800-53;SI-15 Information Output Filtering (P0),OWASP Top 10 2017;A7-Cross-Site Scripting (XSS)\n"
            "**Language:** Java\n"
            "**Group:** Java High Risk\n"
            "**Status:** New\n"
            "**Finding Link:** [https://checkmarxserver.com/CxWebClient/ViewerMain.aspx?scanid=1000227&projectid=121&pathid=28](https://checkmarxserver.com/CxWebClient/ViewerMain.aspx?scanid=1000227&projectid=121&pathid=28)\n"
            "\n"
            "**Line Number:** 39\n"
            "**Column:** 59\n"
            "**Source Object:** executeQuery\n"
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
            "**Source Object:** allUsersMap\n"
            "**Number:** 58\n"
            "**Code:** return allUsersMap;\n"
            "-----\n",
            item.description)
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
        self.assertEqual(str, type(item.line))
        self.assertEqual("58", item.line)
        self.assertEqual(str, type(item.url))
        self.assertEqual("N/A", item.url)
        # ScanStart
        self.assertEqual(datetime.datetime, type(item.date))
        self.assertEqual(datetime.datetime(2018, 2, 25, 11, 35, 52), item.date)
        self.assertEqual(bool, type(item.static_finding))
        self.assertEqual(True, item.static_finding)

    def test_parse_file_with_utf8_various_non_ascii_char(self):
        my_file_handle = open("dojo/unittests/scans/checkmarx/utf8_various_non_ascii_char.xml")
        product = Product()
        engagement = Engagement()
        test = Test()
        engagement.product = product
        test.engagement = engagement
        self.parser = CheckmarxXMLParser(my_file_handle, test)
        my_file_handle.close()
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
        self.assertEqual(str, type(item.description))
        self.assertMultiLineEqual("**Category:** PCI DSS v3.2;PCI DSS (3.2) - 6.5.7 - Cross-site scripting (XSS),OWASP Top 10 2013;A3-Cross-Site Scripting (XSS),FISMA 2014;System And Information Integrity,NIST SP 800-53;SI-15 Information Output Filtering (P0),OWASP Top 10 2017;A7-Cross-Site Scripting (XSS)\n"
            "**Language:** Java\n"
            "**Group:** Java High Risk\n"
            "**Status:** New\n"
            "**Finding Link:** [https://checkmarxserver.com/CxWebClient/ViewerMain.aspx?scanid=1000227&projectid=121&pathid=28](https://checkmarxserver.com/CxWebClient/ViewerMain.aspx?scanid=1000227&projectid=121&pathid=28)\n"
            "\n"
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
            "**Source Object:** allUsersMap\n"
            "**Number:** 58\n"
            "**Code:** return allUsersMap;\n"
            "-----\n",
            item.description)
        self.assertEqual(str, type(item.severity))
        self.assertEqual("High", item.severity)
        self.assertEqual(str, type(item.numerical_severity))
        self.assertEqual("S1", item.numerical_severity)
        self.assertEqual(str, type(item.mitigation))
        self.assertEqual("N/A", item.mitigation)
        self.assertEqual(str, type(item.references))
        self.assertEqual("", item.references)
        self.assertEqual(str, type(item.file_path))
        self.assertEqual("WebGoat/webgoat-lessons/missing-function-ac/src/main/java/org/owasp/webgoat/plugin/¡¢£¤¥¦§¨©ª«¬®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿĀāĂăĄąĆćĈĉĊċČčĎďĐđĒēĔĕĖėĘęĚěĜĝĞğĠġĢģĤĥĦħĨĩĪīĬĭĮįİıĲĳĴĵĶķĸĹĺĻļĽľĿŀŁłŃńŅņŇňŉŊŋŌōŎŏŐőŒœŔŕŖŗŘřŚśŜŝŞşŠšŢţŤťŦŧŨũŪūŬŭŮůŰűŲųŴŵŶŷŸŹźŻżŽžſ/Users.java", item.file_path)
        self.assertEqual(str, type(item.line))
        self.assertEqual("58", item.line)
        self.assertEqual(str, type(item.url))
        self.assertEqual("N/A", item.url)
        # ScanStart
        self.assertEqual(datetime.datetime, type(item.date))
        self.assertEqual(datetime.datetime(2018, 2, 25, 11, 35, 52), item.date)
        self.assertEqual(bool, type(item.static_finding))
        self.assertEqual(True, item.static_finding)
