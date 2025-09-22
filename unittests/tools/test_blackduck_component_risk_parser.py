
from dojo.models import Test
from dojo.tools.blackduck_component_risk.parser import BlackduckComponentRiskParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestBlackduckComponentRiskParser(DojoTestCase):
    def test_blackduck_enhanced_zip_upload(self):
        with (get_unit_tests_scans_path("blackduck_component_risk") / "blackduck_hub_component_risk.zip").open(mode="rb") as testfile:
            parser = BlackduckComponentRiskParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(12, len(findings))
            findings = list(findings)
            self.assertEqual("License Risk: xmldom:0.1.21", findings[0].title)
            self.assertEqual(True, findings[0].fix_available)
            self.assertEqual("Package has a license that is In Violation and should not be used: xmldom:0.1.21.  Please use another component with an acceptable license.", findings[0].mitigation)
            self.assertEqual("High", findings[0].severity)
            self.assertEqual("N/A", findings[0].impact)
            self.assertEqual("**Project:** foo-project ID-355b2cb252662e07153802b82041e8322ccef144-1.0.0\n", findings[0].references)
            self.assertEqual(None, findings[0].file_path)
