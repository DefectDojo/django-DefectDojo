
from dojo.models import Test
from dojo.tools.outpost24.parser import Outpost24Parser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestOutpost24Parser(DojoTestCase):
    def assert_file_has_n_items(self, filename, item_count):
        with (filename).open(encoding="utf-8") as file:
            parser = Outpost24Parser()
            findings = parser.get_findings(file, Test())
            self.validate_locations(findings)
            self.assertEqual(item_count, len(findings))
            if item_count > 0:
                for item in findings:
                    location_count = len(self.get_unsaved_locations(item))
                    self.assertGreater(location_count, 0)
            if item_count == 1:
                self.assertEqual(1, len(findings[0].unsaved_vulnerability_ids))
                self.assertEqual("CVE-2019-9315", findings[0].unsaved_vulnerability_ids[0])

    def test_parser_no_items(self):
        self.assert_file_has_n_items(get_unit_tests_scans_path("outpost24") / "none.xml", 0)

    def test_parser_one_item(self):
        self.assert_file_has_n_items(get_unit_tests_scans_path("outpost24") / "one.xml", 1)

    def test_parser_sample_items(self):
        self.assert_file_has_n_items(get_unit_tests_scans_path("outpost24") / "sample.xml", 24)
