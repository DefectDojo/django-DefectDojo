
from dojo.tools.wiz.parser import WizParser
from ..dojo_test_case import DojoTestCase, get_unit_tests_path


class TestWizParser(DojoTestCase):
  
    def test_file_name_aggregated_parse_file_with_single_vulnerability_has_single_finding(self, mock):
        my_file_handle, product, engagement, test = self.init(
            get_unit_tests_path() + "/scans/wiz/multiple_findings.csv"
        )
        parser = WizParser()
        findings = parser.get_findings(my_file_handle, test)
        item = findings[0]
        self.assertEqual(str, type(item.description))