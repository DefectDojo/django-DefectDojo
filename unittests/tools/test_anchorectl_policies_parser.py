from dojo.models import Test
from dojo.tools.anchorectl_policies.parser import AnchoreCTLPoliciesParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestAnchoreCTLPoliciesParser(DojoTestCase):
    def test_anchore_engine_parser_has_no_finding(self):
        with (get_unit_tests_scans_path("anchorectl_policies") / "no_violation.json").open(encoding="utf-8") as testfile:
            parser = AnchoreCTLPoliciesParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_anchore_engine_parser_has_one_finding_and_it_is_correctly_parsed(self):
        with (get_unit_tests_scans_path("anchorectl_policies") / "one_violation.json").open(encoding="utf-8") as testfile:
            parser = AnchoreCTLPoliciesParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            singleFinding = findings[0]
            self.assertEqual(singleFinding.severity, "Medium")
            self.assertEqual(singleFinding.title, "RootUser - gate|dockerfile - trigger|b2605c2ddbdb02b8e2365c9248dada5a")
            self.assertEqual(singleFinding.description, "User root found as effective user, which is not on the allowed list")

    def test_anchore_engine_parser_has_many_findings(self):
        with (get_unit_tests_scans_path("anchorectl_policies") / "many_violations.json").open(encoding="utf-8") as testfile:
            parser = AnchoreCTLPoliciesParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))

    def test_anchore_engine_parser_has_one_finding_and_description_has_severity(self):
        with (get_unit_tests_scans_path("anchorectl_policies") / "one_violation_description_severity.json").open(encoding="utf-8") as testfile:
            parser = AnchoreCTLPoliciesParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            singleFinding = findings[0]
            self.assertEqual(singleFinding.severity, "Critical")
            self.assertEqual(singleFinding.title, "RootUser - gate|dockerfile - trigger|b2605c2ddbdb02b8e2365c9248dada5a")
            self.assertEqual(singleFinding.description, "CRITICAL User root found as effective user, which is not on the allowed list")
            
    # Tests for the new AnchoreCTL format
    def test_new_format_anchore_engine_parser_has_no_finding(self):
        with (get_unit_tests_scans_path("anchorectl_policies") / "new_format_no_violation.json").open(encoding="utf-8") as testfile:
            parser = AnchoreCTLPoliciesParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_new_format_anchore_engine_parser_has_one_finding_and_it_is_correctly_parsed(self):
        with (get_unit_tests_scans_path("anchorectl_policies") / "new_format_one_violation.json").open(encoding="utf-8") as testfile:
            parser = AnchoreCTLPoliciesParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            singleFinding = findings[0]
            self.assertEqual(singleFinding.severity, "Medium")
            self.assertEqual(singleFinding.title, "RootUser - gate|dockerfile - trigger|b2605c2ddbdb02b8e2365c9248dada5a")
            self.assertEqual(singleFinding.description, "User root found as effective user, which is not on the allowed list")

    def test_new_format_anchore_engine_parser_has_many_findings(self):
        with (get_unit_tests_scans_path("anchorectl_policies") / "new_format_many_violations.json").open(encoding="utf-8") as testfile:
            parser = AnchoreCTLPoliciesParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))

    def test_new_format_anchore_engine_parser_has_one_finding_and_description_has_severity(self):
        with (get_unit_tests_scans_path("anchorectl_policies") / "new_format_one_violation_description_severity.json").open(encoding="utf-8") as testfile:
            parser = AnchoreCTLPoliciesParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            singleFinding = findings[0]
            self.assertEqual(singleFinding.severity, "Critical")
            self.assertEqual(singleFinding.title, "RootUser - gate|dockerfile - trigger|b2605c2ddbdb02b8e2365c9248dada5a")
            self.assertEqual(singleFinding.description, "CRITICAL User root found as effective user, which is not on the allowed list")
