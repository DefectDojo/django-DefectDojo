import re

from dojo.tools.sarif.parser import SarifParser

# Ruff's flake8-bandit rules are numbered S1xx-S7xx, and its SARIF rule objects label them
# `"kind": "flake8-bandit"`. Everything else Ruff reports - naming, imports, formatting, complexity -
# is style, and importing it would bury real findings under thousands of lint opinions.
SECURITY_RULE = re.compile(r"^S\d+$")


class RuffParser(SarifParser):

    """
    Ruff is a Python linter. Most of what it reports is style, so this parser imports ONLY its
    `S` rules - the flake8-bandit family: hardcoded credentials, `eval`, `pickle.loads`,
    `subprocess(..., shell=True)`, SQL built by string concatenation, weak hashes, disabled TLS
    verification and similar.

    Ruff emits SARIF natively, so the SARIF logic is reused and only the scan type and the rule
    filter are added. Findings from every other Ruff rule family are dropped, which is what keeps
    this a security scan rather than a lint dump.

    Note that Ruff reports every rule at SARIF level "error" and sets no `security-severity`
    property, so all imported findings land at High. Ruff draws no distinction between, say, a
    hardcoded password and a weak hash - that judgement belongs to whoever triages them.

    https://docs.astral.sh/ruff/rules/#flake8-bandit-s
    """

    def get_scan_types(self):
        return ["Ruff Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Ruff Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import the SARIF report of `ruff check --output-format sarif`. Only Ruff's `S` "
            "(flake8-bandit) security rules are imported; every other rule family is ignored."
        )

    def get_findings(self, filehandle, test):
        return self.filter_to_security_rules(super().get_findings(filehandle, test))

    def get_tests(self, scan_type, handle):
        # SarifParser exposes get_tests as well as get_findings, and it builds its findings by a
        # separate path. Filtering in only one of the two would let the whole style ruleset through
        # whenever DefectDojo took the other.
        tests = super().get_tests(scan_type, handle)
        for parser_test in tests:
            parser_test.findings = self.filter_to_security_rules(parser_test.findings)
        return tests

    def filter_to_security_rules(self, findings):
        """Keep only the flake8-bandit findings, identified by Ruff's `S<number>` rule id."""
        return [
            finding for finding in findings
            if SECURITY_RULE.match(finding.vuln_id_from_tool or "")
        ]
