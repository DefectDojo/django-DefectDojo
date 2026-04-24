import datetime

from dojo.models import Test
from dojo.tools.coverity_api.parser import CoverityApiParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestZapParser(DojoTestCase):
    def test_parse_wrong_file(self):
        with self.assertRaises(ValueError), \
          (get_unit_tests_scans_path("coverity_api") / "wrong.json").open(encoding="utf-8") as testfile:
            parser = CoverityApiParser()
            parser.get_findings(testfile, Test())

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("coverity_api") / "empty.json").open(encoding="utf-8") as testfile:
            parser = CoverityApiParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_only_quality(self):
        """Non-RESOURCE_LEAK quality findings are excluded"""
        with (get_unit_tests_scans_path("coverity_api") / "only_non_resource_leak_quality.json").open(encoding="utf-8") as testfile:
            parser = CoverityApiParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_some_findings(self):
        with (get_unit_tests_scans_path("coverity_api") / "few_findings.json").open(encoding="utf-8") as testfile:
            parser = CoverityApiParser()
            findings = parser.get_findings(testfile, Test())
            self.assertIsInstance(findings, list)
            self.assertEqual(6, len(findings))
            with self.subTest(i=0):
                finding = findings[0]  # first RESOURCE_LEAK finding
                self.assertTrue(finding.active)
                self.assertFalse(finding.verified)
                self.assertEqual("Resource leak", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertEqual(404, finding.cwe)
                self.assertEqual("Wdkrtgthhl/Llwfzgphzw/Fashvkaxzx/Okkfacqsxw.rs", finding.file_path)
                self.assertEqual(datetime.date(2021, 3, 23), finding.date)
                self.assertEqual(22480, finding.unique_id_from_tool)
            with self.subTest(i=4):
                finding = findings[4]  # security finding
                self.assertTrue(finding.active)
                self.assertFalse(finding.verified)
                self.assertEqual("Risky cryptographic hashing function", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(328, finding.cwe)
                self.assertEqual("Ugmeekucai/Axoqomhsti/Ydyvpiogyn/Rpzlfzjvra.rs", finding.file_path)
                self.assertEqual(datetime.date(2021, 3, 23), finding.date)
                self.assertEqual(22463, finding.unique_id_from_tool)

    def test_parse_few_findings_triaged_as_bug(self):
        with (get_unit_tests_scans_path("coverity_api") / "few_findings_triaged_as_bug.json").open(encoding="utf-8") as testfile:
            parser = CoverityApiParser()
            findings = parser.get_findings(testfile, Test())
            self.assertIsInstance(findings, list)
            self.assertEqual(13, len(findings))
            with self.subTest(i=1):
                finding = findings[1]  # security finding (triaged as bug)
                self.assertTrue(finding.active)
                self.assertTrue(finding.verified)
                self.assertEqual("HTTP header injection", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(610, finding.cwe)
                self.assertEqual("Fhfzusraaf/Ktvntamjop/Azkpvexkuw/Mvibflzawx.rs", finding.file_path)
                self.assertEqual(datetime.date(2020, 11, 19), finding.date)
                self.assertEqual(22248, finding.unique_id_from_tool)

    def test_parse_some_findings_mitigated(self):
        with (get_unit_tests_scans_path("coverity_api") / "few_findings_mitigated.json").open(encoding="utf-8") as testfile:
            parser = CoverityApiParser()
            findings = parser.get_findings(testfile, Test())
            self.assertIsInstance(findings, list)
            self.assertEqual(25, len(findings))
            with self.subTest(i=0):
                finding = findings[0]  # RESOURCE_LEAK finding (active, status New)
                self.assertTrue(finding.active)
                self.assertFalse(finding.verified)
                self.assertEqual("Resource leak", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertEqual(404, finding.cwe)
                self.assertEqual("Vzfkposilb/Ejgmugyeam/Ekcbsjzuiq/Isjhjabnfe.rs", finding.file_path)
                self.assertEqual(datetime.date(2021, 3, 31), finding.date)
                self.assertEqual(22496, finding.unique_id_from_tool)
            with self.subTest(i=2):
                finding = findings[2]  # this one is dismissed as a false positive
                self.assertFalse(finding.active)
                self.assertTrue(finding.verified)
                self.assertTrue(finding.false_p)
                self.assertEqual("Cross-site scripting", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertEqual(79, finding.cwe)
                self.assertEqual("Pfozpmtueo/Vtoqmbvmzf/Noxacjclcz/Aymctwefbi.rs", finding.file_path)
                self.assertEqual(datetime.date(2021, 3, 26), finding.date)
                self.assertEqual(22486, finding.unique_id_from_tool)
            with self.subTest(i=12):
                finding = findings[12]
                self.assertFalse(finding.active)
                self.assertTrue(finding.verified)
                self.assertEqual("Use of hard-coded password", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertEqual(259, finding.cwe)
                self.assertEqual("Hvsilgzkwz/Lhmxrchybr/Edcoanzncg/Oowieyoxvn.rs", finding.file_path)
                self.assertEqual(datetime.date(2021, 3, 15), finding.date)
                self.assertEqual(22421, finding.unique_id_from_tool)
            with self.subTest(i=23):
                finding = findings[23]
                self.assertFalse(finding.active)
                self.assertTrue(finding.verified)
                self.assertEqual("Cross-site scripting", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertEqual(79, finding.cwe)
                self.assertEqual("Pyqqbarxuc/Eiiecgivyo/Yurhlwgjpa/Fitpbdjidn.rs", finding.file_path)
                self.assertEqual(datetime.date(2020, 1, 22), finding.date)
                self.assertEqual(18828, finding.unique_id_from_tool)
