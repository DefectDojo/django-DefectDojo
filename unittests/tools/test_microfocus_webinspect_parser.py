from dojo.models import Engagement, Product, Test
from dojo.tools.microfocus_webinspect.parser import MicrofocusWebinspectParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestMicrofocusWebinspectParser(DojoTestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        test = Test()
        test.engagement = Engagement()
        test.engagement.product = Product()
        with (
            get_unit_tests_scans_path("microfocus_webinspect") / "Webinspect_no_vuln.xml").open(encoding="utf-8",
        ) as testfile:
            parser = MicrofocusWebinspectParser()
            findings = parser.get_findings(testfile, test)
            self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_findings(self):
        test = Test()
        test.engagement = Engagement()
        test.engagement.product = Product()
        with (
            get_unit_tests_scans_path("microfocus_webinspect") / "Webinspect_one_vuln.xml").open(encoding="utf-8",
        ) as testfile:
            parser = MicrofocusWebinspectParser()
            findings = parser.get_findings(testfile, test)
            self.validate_locations(findings)
            self.assertEqual(1, len(findings))
            item = findings[0]
            self.assertEqual(200, item.cwe)
            self.assertEqual(1, len(self.get_unsaved_locations(item)))
            location = self.get_unsaved_locations(item)[0]
            self.assertEqual("www.microfocus.com", location.host)
            self.assertEqual(443, location.port)
            self.assertFalse(location.path)  # path begins with '/' but Locations store "root-less" path

    def test_parse_file_with_multiple_vuln_has_multiple_finding(self):
        test = Test()
        test.engagement = Engagement()
        test.engagement.product = Product()
        with (
            get_unit_tests_scans_path("microfocus_webinspect") / "Webinspect_many_vuln.xml").open(encoding="utf-8",
        )as testfile:
            parser = MicrofocusWebinspectParser()
            findings = parser.get_findings(testfile, test)
            self.validate_locations(findings)
            self.assertEqual(8, len(findings))
            item = findings[1]
            self.assertEqual(525, item.cwe)
            self.assertIsNotNone(item.references)
            self.assertEqual(
                "1cfe38ee-89f7-4110-ad7c-8fca476b2f04", item.unique_id_from_tool,
            )
            self.assertEqual(1, len(self.get_unsaved_locations(item)))
            location = self.get_unsaved_locations(item)[0]
            self.assertEqual("php.vulnweb.com", location.host)
            self.assertEqual(80, location.port)
            self.assertFalse(location.path)  # path begins with '/' but Locations store "root-less" path

    def test_convert_severity(self):
        with self.subTest("convert info", val="0"):
            self.assertEqual(
                "Info", MicrofocusWebinspectParser.convert_severity("0"),
            )
        with self.subTest("convert medium", val="2"):
            self.assertEqual(
                "Medium", MicrofocusWebinspectParser.convert_severity("2"),
            )

    def test_parse_file_version_18_20(self):
        with (get_unit_tests_scans_path("microfocus_webinspect") / "Webinspect_V18_20.xml").open(encoding="utf-8") as testfile:
            parser = MicrofocusWebinspectParser()
            findings = parser.get_findings(testfile, Test())
            self.validate_locations(findings)
            self.assertEqual(4, len(findings))
            item = findings[0]
            self.assertEqual("Cache Management: Headers", item.title)
            self.assertEqual("Info", item.severity)
            self.assertEqual(200, item.cwe)
            self.assertEqual(2, item.nb_occurences)
            self.assertEqual(2, len(self.get_unsaved_locations(item)))
            location = self.get_unsaved_locations(item)[0]
            self.assertEqual("www.microfocus.com", location.host)
            self.assertEqual(443, location.port)
            self.assertFalse(location.path)  # path begins with '/' but Locations store "root-less" path
            location = self.get_unsaved_locations(item)[1]
            self.assertEqual("www.microfocus.com", location.host)
            self.assertEqual(443, location.port)
            self.assertEqual("en-us/home", location.path)  # path begins with '/' but Locations store "root-less" path
            item = findings[1]
            self.assertEqual(525, item.cwe)
            self.assertEqual(1, item.nb_occurences)
            self.assertEqual(1, len(self.get_unsaved_locations(item)))
            location = self.get_unsaved_locations(item)[0]
            self.assertEqual("www.microfocus.com", location.host)
            self.assertEqual(443, location.port)
            item = findings[2]
            self.assertEqual(200, item.cwe)
            self.assertEqual(1, item.nb_occurences)
            self.assertEqual(1, len(self.get_unsaved_locations(item)))
            location = self.get_unsaved_locations(item)[0]
            self.assertEqual("www.microfocus.com", location.host)
            self.assertEqual(443, location.port)
            item = findings[3]
            self.assertEqual(613, item.cwe)
            self.assertEqual(1, item.nb_occurences)
            self.assertEqual(1, len(self.get_unsaved_locations(item)))
            location = self.get_unsaved_locations(item)[0]
            self.assertEqual("www.microfocus.com", location.host)
            self.assertEqual(443, location.port)

    def test_parse_file_issue7690(self):
        test = Test()
        test.engagement = Engagement()
        test.engagement.product = Product()
        with (get_unit_tests_scans_path("microfocus_webinspect") / "issue_7690.xml").open(encoding="utf-8") as testfile:
            parser = MicrofocusWebinspectParser()
            findings = parser.get_findings(testfile, test)
            self.assertEqual(30, len(findings))
