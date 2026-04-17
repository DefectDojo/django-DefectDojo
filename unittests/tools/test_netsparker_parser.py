
from django.test import override_settings

from dojo.models import Test
from dojo.tools.netsparker.parser import NetsparkerParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestNetsparkerParser(DojoTestCase):

    def test_parse_file_with_one_finding(self):
        """With USE_FIRST_SEEN=False (default), date should come from Generated (scan date)."""
        with (get_unit_tests_scans_path("netsparker") / "netsparker_one_finding.json").open(encoding="utf-8") as testfile:
            parser = NetsparkerParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            self.validate_locations(findings)
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(16, finding.cwe)
                # Generated date is "25/06/2021 09:59 AM"
                self.assertEqual("25/06/2021", finding.date.strftime("%d/%m/%Y"))
                self.assertIsNotNone(finding.description)
                self.assertGreater(len(finding.description), 0)
                self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N/E:H/RL:O/RC:C", finding.cvssv3)
                self.assertEqual(1, len(self.get_unsaved_locations(finding)))
                location = self.get_unsaved_locations(finding)[0]
                self.assertEqual(str(location), "http://php.testsparker.com/auth/login.php")

    @override_settings(USE_FIRST_SEEN=True)
    def test_parse_file_with_one_finding_first_seen(self):
        """With USE_FIRST_SEEN=True, date should come from FirstSeenDate."""
        with (get_unit_tests_scans_path("netsparker") / "netsparker_one_finding.json").open(encoding="utf-8") as testfile:
            parser = NetsparkerParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            self.validate_locations(findings)
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(16, finding.cwe)
                # FirstSeenDate is "16/06/2021 12:30 PM"
                self.assertEqual("16/06/2021", finding.date.strftime("%d/%m/%Y"))

    def test_parse_file_with_multiple_finding(self):
        """With USE_FIRST_SEEN=False (default), dates should come from Generated (scan date)."""
        with (get_unit_tests_scans_path("netsparker") / "netsparker_many_findings.json").open(encoding="utf-8") as testfile:
            parser = NetsparkerParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(16, len(findings))
            self.validate_locations(findings)
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(16, finding.cwe)
                # Generated date is "25/06/2021 10:00 AM"
                self.assertEqual("25/06/2021", finding.date.strftime("%d/%m/%Y"))
                self.assertIsNotNone(finding.description)
                self.assertGreater(len(finding.description), 0)
                self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N/E:H/RL:O/RC:C", finding.cvssv3)
                self.assertEqual(1, len(self.get_unsaved_locations(finding)))
                location = self.get_unsaved_locations(finding)[0]
                self.assertEqual(str(location), "http://php.testsparker.com/auth/login.php")

            with self.subTest(i=1):
                finding = findings[1]
                self.assertEqual("Critical", finding.severity)
                self.assertEqual(89, finding.cwe)
                self.assertEqual("25/06/2021", finding.date.strftime("%d/%m/%Y"))
                self.assertIsNotNone(finding.description)
                self.assertGreater(len(finding.description), 0)
                self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", finding.cvssv3)
                self.assertEqual(1, len(self.get_unsaved_locations(finding)))
                location = self.get_unsaved_locations(finding)[0]
                self.assertEqual(str(location), "http://php.testsparker.com/artist.php?id=-1%20OR%2017-7=10")

            with self.subTest(i=2):
                finding = findings[2]
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(205, finding.cwe)
                self.assertEqual("25/06/2021", finding.date.strftime("%d/%m/%Y"))
                self.assertIsNotNone(finding.description)
                self.assertGreater(len(finding.description), 0)
                self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N/E:H/RL:O/RC:C", finding.cvssv3)
                self.assertEqual(1, len(self.get_unsaved_locations(finding)))
                location = self.get_unsaved_locations(finding)[0]
                self.assertEqual(str(location), "http://php.testsparker.com")

    @override_settings(USE_FIRST_SEEN=True)
    def test_parse_file_with_multiple_finding_first_seen(self):
        """With USE_FIRST_SEEN=True, dates should come from FirstSeenDate."""
        with (get_unit_tests_scans_path("netsparker") / "netsparker_many_findings.json").open(encoding="utf-8") as testfile:
            parser = NetsparkerParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(16, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                # FirstSeenDate is "16/06/2021 12:30 PM"
                self.assertEqual("16/06/2021", finding.date.strftime("%d/%m/%Y"))
            with self.subTest(i=2):
                finding = findings[2]
                # FirstSeenDate is "15/06/2021 01:44 PM"
                self.assertEqual("15/06/2021", finding.date.strftime("%d/%m/%Y"))

    def test_parse_file_issue_9816(self):
        with (get_unit_tests_scans_path("netsparker") / "issue_9816.json").open(encoding="utf-8") as testfile:
            parser = NetsparkerParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))
            self.validate_locations(findings)
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("High", finding.severity)
                self.assertEqual(614, finding.cwe)
                self.assertEqual("03/02/2019", finding.date.strftime("%d/%m/%Y"))

    def test_parse_file_issue_10311(self):
        with (get_unit_tests_scans_path("netsparker") / "issue_10311.json").open(encoding="utf-8") as testfile:
            parser = NetsparkerParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))
            self.validate_locations(findings)
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("High", finding.severity)
                self.assertEqual(614, finding.cwe)
                self.assertEqual("03/02/2019", finding.date.strftime("%d/%m/%Y"))

    def test_parse_file_issue_11020(self):
        """With USE_FIRST_SEEN=False (default), date should come from Generated (scan date)."""
        with (get_unit_tests_scans_path("netsparker") / "issue_11020.json").open(encoding="utf-8") as testfile:
            parser = NetsparkerParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))
            self.validate_locations(findings)
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Low", finding.severity)
                self.assertEqual(205, finding.cwe)
                # Generated date is "2024-10-08 02:33 PM"
                self.assertEqual("08/10/2024", finding.date.strftime("%d/%m/%Y"))

    @override_settings(USE_FIRST_SEEN=True)
    def test_parse_file_issue_11020_first_seen(self):
        """With USE_FIRST_SEEN=True, date should come from FirstSeenDate."""
        with (get_unit_tests_scans_path("netsparker") / "issue_11020.json").open(encoding="utf-8") as testfile:
            parser = NetsparkerParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                # FirstSeenDate is "2024-07-23 05:32 PM"
                self.assertEqual("23/07/2024", finding.date.strftime("%d/%m/%Y"))
