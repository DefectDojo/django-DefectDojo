"""
Parser for Aquasecurity trivy-operator (https://github.com/aquasecurity/trivy-operator)
"""

import json
import logging

from dojo.models import Finding

logger = logging.getLogger(__name__)

TRIVY_SEVERITIES = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "UNKNOWN": "Info",
}

DESCRIPTION_TEMPLATE = """{title}
**Fixed version:** {fixed_version}
"""

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
            data = json.loads(str(scan_data, 'utf-8'))
        except:
            data = json.loads(scan_data)

        if data is None:
            return list()
        metadata = data.get('metadata', None)
        if metadata is None:
            return list()
        labels = metadata.get('labels', None)
        if labels is None:
            return list()
        resource_namespace = labels.get('trivy-operator.resource.namespace', '')
        resource_kind = labels.get('trivy-operator.resource.kind', '')
        resource_name = labels.get('trivy-operator.resource.name', '')
        container_name = labels.get('trivy-operator.container.name', '')
        service = '/'.join([resource_namespace, resource_kind, resource_name])
        if container_name != '':
            service = '/'.join([service, container_name])

        report = data.get('report', None)
        if report is None:
            return list()

        findings = list()
        vulnerabilities = report.get('vulnerabilities', None)
        if vulnerabilities is not None:
            for vulnerability in vulnerabilities:
                vuln_id = vulnerability.get('vulnerabilityID', '0')
                severity = TRIVY_SEVERITIES[vulnerability.get('severity')]
                references = vulnerability.get('primaryLink')
                mitigation = vulnerability.get('fixedVersion')
                package_name = vulnerability.get('resource')
                package_version = vulnerability.get('installedVersion')
                cvssv3_score = vulnerability.get('score')
                description = DESCRIPTION_TEMPLATE.format(
                    title=vulnerability.get('title'),
                    fixed_version=mitigation
                )
                title = ' '.join([
                    vuln_id,
                    package_name,
                    package_version,
                ])
                finding = Finding(
                    test=test,
                    title=title,
                    severity=severity,
                    references=references,
                    mitigation=mitigation,
                    component_name=package_name,
                    component_version=package_version,
                    cvssv3_score=cvssv3_score,
                    description=description,
                    static_finding=True,
                    dynamic_finding=False,
                    service=service)
                if vuln_id:
                    finding.unsaved_vulnerability_ids = [vuln_id]
                findings.append(finding)

        checks = report.get('checks', None)
        if checks is not None:
            for check in checks:
                check_title = check.get('title')
                check_severity = TRIVY_SEVERITIES[check.get('severity')]
                check_id = check.get('checkID', '0')
                check_references = ''
                if check_id != 0:
                    check_references = "https://avd.aquasec.com/misconfig/kubernetes/" + check_id.lower()
                check_description = check.get('description', '')
                title = f'{check_id} - {check_title}'
                finding = Finding(
                    test=test,
                    title=title,
                    severity=check_severity,
                    references=check_references,
                    description=check_description,
                    static_finding=True,
                    dynamic_finding=False,
                    service=service)
                if check_id:
                    finding.unsaved_vulnerability_ids = [check_id]
                findings.append(finding)

        secrets = report.get('secrets', None)
        if secrets is not None:
            for secret in secrets:
                secret_title = secret.get('title')
                secret_category = secret.get('category')
                secret_match = secret.get('match', '')
                secret_severity = TRIVY_SEVERITIES[secret.get('severity')]
                secret_rule_id = secret.get('ruleID', '0')
                secret_target = secret.get('target', '')
                secret_references = secret.get('ruleID', '')
                title = f'Secret detected in {secret_target} - {secret_title}'
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
                    service=service)
                if secret_rule_id:
                    finding.unsaved_vulnerability_ids = [secret_rule_id]
                findings.append(finding)

        return findings
