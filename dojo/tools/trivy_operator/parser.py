"""
Parser for Aquasecurity trivy-operator (https://github.com/aquasecurity/trivy-operator)
"""

import json
from dojo.tools.trivy_operator.vulnerability_handler import TrivyVulnerabilityHandler
from dojo.tools.trivy_operator.checks_handler import TrivyChecksHandler
from dojo.tools.trivy_operator.secrets_handler import TrivySecretsHandler
from dojo.tools.trivy_operator.compliance_handler import TrivyComplianceHandler


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

        if data is None:
            return list()
        metadata = data.get("metadata", None)
        if metadata is None:
            return list()
        labels = metadata.get("labels", None)
        if labels is None:
            return list()
        report = data.get("report", None)
        benchmark = data.get("status", None)
        if benchmark is not None:
            benchmarkreport = benchmark.get("detailReport", None)
        findings = list()
        if report is not None:
            resource_namespace = labels.get(
                "trivy-operator.resource.namespace", ""
            )
            resource_kind = labels.get("trivy-operator.resource.kind", "")
            resource_name = labels.get("trivy-operator.resource.name", "")
            container_name = labels.get("trivy-operator.container.name", "")
            service = f"{resource_namespace}/{resource_kind}/{resource_name}"
            if container_name != "":
                service = f"{service}/{container_name}"
            vulnerabilities = report.get("vulnerabilities", None)
            if vulnerabilities is not None:
                findings += TrivyVulnerabilityHandler().handle_vulns(service, vulnerabilities, test)
            checks = report.get("checks", None)
            if checks is not None:
                findings += TrivyChecksHandler().handle_checks(service, checks, test)
            secrets = report.get("secrets", None)
            if secrets is not None:
                findings += TrivySecretsHandler().handle_secrets(service, secrets, test)
        elif benchmarkreport is not None:
            findings += TrivyComplianceHandler().handle_compliance(benchmarkreport, test)
        return findings
