from ..dojo_test_case import DojoTestCase
from dojo.tools.anchorectl_policies.parser import AnchoreCTLPoliciesParser
from dojo.models import Test


class TestAnchoreCTLPoliciesParser(DojoTestCase):
    def test_anchore_engine_parser_has_no_finding(self):
        testfile = open("unittests/scans/anchoreCTL_policies/no_violation.json")
        parser = AnchoreCTLPoliciesParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_anchore_engine_parser_has_one_finding_and_it_is_correctly_parsed(self):
        testfile = open("unittests/scans/anchoreCTL_policies/one_violation.json")
        parser = AnchoreCTLPoliciesParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))
        singleFinding = findings[0]
        self.assertEqual(singleFinding.severity, 'Medium')
        self.assertEqual(singleFinding.title, 'RootUser - gate|dockerfile - trigger|b2605c2ddbdb02b8e2365c9248dada5a')
        self.assertEqual(singleFinding.description, 'User root found as effective user, which is not on the allowed list')

    def test_anchore_engine_parser_has_many_findings(self):
        testfile = open("unittests/scans/anchoreCTL_policies/many_violations.json")
        parser = AnchoreCTLPoliciesParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(3, len(findings))
