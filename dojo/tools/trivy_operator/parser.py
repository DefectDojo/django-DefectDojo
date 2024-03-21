"""
Parser for Aquasecurity trivy-operator (https://github.com/aquasecurity/trivy-operator)
"""

import json
import logging

from dojo.models import Finding
from dojo.tools.trivy_operator.vulnerability_handler import TrivyVulnerabilityHandler
from dojo.tools.trivy_operator.checks_handler import TrivyChecksHandler
logger = logging.getLogger(__name__)

TRIVY_SEVERITIES = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "UNKNOWN": "Info",
}


SECRET_DESCRIPTION_TEMPLATE = """{title}
**Category:** {category}
**Match:** {match}
"""


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
        resource_namespace = labels.get(
            "trivy-operator.resource.namespace", ""
        )
        resource_kind = labels.get("trivy-operator.resource.kind", "")
        resource_name = labels.get("trivy-operator.resource.name", "")
        container_name = labels.get("trivy-operator.container.name", "")
        service = "/".join([resource_namespace, resource_kind, resource_name])
        if container_name != "":
            service = "/".join([service, container_name])

        report = data.get("report", None)
        if report is None:
            return list()

        findings = list()
        vulnerabilities = report.get("vulnerabilities", None)
        if vulnerabilities is not None:
            findings += TrivyVulnerabilityHandler().handle_vulns(service, vulnerabilities, test)
        checks = report.get("checks", None)
        if checks is not None:
            findings += TrivyChecksHandler().handle_checks(service, checks, test)
        secrets = report.get("secrets", None)
        if secrets is not None:
            for secret in secrets:
                secret_title = secret.get("title")
                secret_category = secret.get("category")
                secret_match = secret.get("match", "")
                secret_severity = TRIVY_SEVERITIES[secret.get("severity")]
                secret_rule_id = secret.get("ruleID", "0")
                secret_target = secret.get("target", "")
                secret_references = secret.get("ruleID", "")
                title = f"Secret detected in {secret_target} - {secret_title}"
                secret_description = SECRET_DESCRIPTION_TEMPLATE.format(
                    title=secret_title,
                    category=secret_category,
                    match=secret_match,
                )

                finding = Finding(
                    test=test,
                    title=title,
                    severity=secret_severity,
                    references=secret_references,
                    description=secret_description,
                    file_path=secret_target,
                    static_finding=True,
                    dynamic_finding=False,
                    service=service,
                )
                if secret_rule_id:
                    finding.unsaved_vulnerability_ids = [secret_rule_id]
                findings.append(finding)

        return findings
