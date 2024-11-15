"""Parser for Aquasecurity trivy-operator (https://github.com/aquasecurity/trivy-operator)"""

import json

from dojo.tools.trivy_operator.checks_handler import TrivyChecksHandler
from dojo.tools.trivy_operator.compliance_handler import TrivyComplianceHandler
from dojo.tools.trivy_operator.secrets_handler import TrivySecretsHandler
from dojo.tools.trivy_operator.vulnerability_handler import TrivyVulnerabilityHandler


class TrivyOperatorParser:
    def get_scan_types(self):
        return ["Trivy Operator Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Trivy Operator Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import trivy-operator JSON scan report."

    def get_findings(self, scan_file, test):
        scan_data = scan_file.read()

        try:
            data = json.loads(str(scan_data, "utf-8"))
        except Exception:
            data = json.loads(scan_data)
        findings = []
        if type(data) is list:
            for listitems in data:
                findings += self.output_findings(listitems, test)
        else:
            findings += self.output_findings(data, test)
        return findings

    def output_findings(self, data, test):
        if data is None:
            return []
        metadata = data.get("metadata", None)
        if metadata is None:
            return []
        labels = metadata.get("labels", None)
        if labels is None:
            return []
        report = data.get("report", None)
        benchmark = data.get("status", None)
        if benchmark is not None:
            benchmarkreport = benchmark.get("detailReport", None)
        findings = []
        if report is not None:
            vulnerabilities = report.get("vulnerabilities", None)
            if vulnerabilities is not None:
                findings += TrivyVulnerabilityHandler().handle_vulns(labels, vulnerabilities, test)
            checks = report.get("checks", None)
            if checks is not None:
                findings += TrivyChecksHandler().handle_checks(labels, checks, test)
            secrets = report.get("secrets", None)
            if secrets is not None:
                findings += TrivySecretsHandler().handle_secrets(labels, secrets, test)
        elif benchmarkreport is not None:
            findings += TrivyComplianceHandler().handle_compliance(benchmarkreport, test)
        return findings
