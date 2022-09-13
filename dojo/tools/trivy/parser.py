"""
Parser for Aquasecurity trivy (https://github.com/aquasecurity/trivy) Docker images scaner
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
**Target:** {target}
**Type:** {type}
**Fixed version:** {fixed_version}

{description_text}
"""

MISC_DESCRIPTION_TEMPLATE = """**Target:** {target}
**Type:** {type}

{description}
{message}
"""

SECRET_DESCRIPTION_TEMPLATE = """{title}
**Category:** {category}
**Match:** {match}
"""


class TrivyParser:

    def get_scan_types(self):
        return ["Trivy Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Trivy Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import trivy JSON scan report."

    def get_findings(self, scan_file, test):

        scan_data = scan_file.read()

        try:
            data = json.loads(str(scan_data, 'utf-8'))
        except:
            data = json.loads(scan_data)

        # Legacy format is empty
        if data is None:
            return list()
        # Legacy format with results
        elif isinstance(data, list):
            return self.get_result_items(test, data)
        else:
            schema_version = data.get('SchemaVersion', None)
            cluster_name = data.get('ClusterName')
            if schema_version == 2:
                results = data.get('Results', [])
                return self.get_result_items(test, results)
            elif cluster_name:
                findings = list()
                vulnerabilities = data.get('Vulnerabilities', [])
                for service in vulnerabilities:
                    namespace = service.get('Namespace')
                    kind = service.get('Kind')
                    name = service.get('Name')
                    service_name = ''
                    if namespace:
                        service_name = f'{namespace} / '
                    if kind:
                        service_name += f'{kind} / '
                    if name:
                        service_name += f'{name} / '
                    if len(service_name) >= 3:
                        service_name = service_name[:-3]
                    findings += self.get_result_items(test, service.get('Results', []), service_name)
                misconfigurations = data.get('Misconfigurations', [])
                for service in misconfigurations:
                    namespace = service.get('Namespace')
                    kind = service.get('Kind')
                    name = service.get('Name')
                    service_name = ''
                    if namespace:
                        service_name = f'{namespace} / '
                    if kind:
                        service_name += f'{kind} / '
                    if name:
                        service_name += f'{name} / '
                    if len(service_name) >= 3:
                        service_name = service_name[:-3]
                    findings += self.get_result_items(test, service.get('Results', []), service_name)
                return findings
            else:
                raise ValueError('Schema of Trivy json report is not supported')

    def get_result_items(self, test, results, service_name=None):
        items = list()
        for target_data in results:
            if not isinstance(target_data, dict) or 'Target' not in target_data:
                continue
            target = target_data['Target']

            target_target = target_data.get('Target')
            target_class = target_data.get('Class')
            target_type = target_data.get('Type')

            vulnerabilities = target_data.get('Vulnerabilities', []) or []
            for vuln in vulnerabilities:
                if not isinstance(vuln, dict):
                    continue
                try:
                    vuln_id = vuln.get('VulnerabilityID', '0')
                    package_name = vuln['PkgName']
                    severity = TRIVY_SEVERITIES[vuln['Severity']]
                except KeyError as exc:
                    logger.warning('skip vulnerability due %r', exc)
                    continue
                package_version = vuln.get('InstalledVersion', '')
                references = '\n'.join(vuln.get('References', []))
                mitigation = vuln.get('FixedVersion', '')
                if len(vuln.get('CweIDs', [])) > 0:
                    cwe = int(vuln['CweIDs'][0].split("-")[1])
                else:
                    cwe = 0
                type = target_data.get('Type', '')
                title = ' '.join([
                    vuln_id,
                    package_name,
                    package_version,
                ])
                description = DESCRIPTION_TEMPLATE.format(
                    title=vuln.get('Title', ''),
                    target=target,
                    type=type,
                    fixed_version=mitigation,
                    description_text=vuln.get('Description', ''),
                )
                cvss = vuln.get('CVSS', None)
                cvssv3 = None
                if cvss is not None:
                    nvd = cvss.get('nvd', None)
                    if nvd is not None:
                        cvssv3 = nvd.get('V3Vector', None)
                finding = Finding(
                    test=test,
                    title=title,
                    cwe=cwe,
                    severity=severity,
                    references=references,
                    description=description,
                    mitigation=mitigation,
                    component_name=package_name,
                    component_version=package_version,
                    cvssv3=cvssv3,
                    static_finding=True,
                    dynamic_finding=False,
                    tags=[type, target_class],
                    service=service_name,
                )

                if vuln_id:
                    finding.unsaved_vulnerability_ids = [vuln_id]

                items.append(finding)

            misconfigurations = target_data.get('Misconfigurations', [])
            for misconfiguration in misconfigurations:
                misc_type = misconfiguration.get('Type')
                misc_id = misconfiguration.get('ID')
                misc_title = misconfiguration.get('Title')
                misc_description = misconfiguration.get('Description')
                misc_message = misconfiguration.get('Message')
                misc_resolution = misconfiguration.get('Resolution')
                misc_severity = misconfiguration.get('Severity')
                misc_primary_url = misconfiguration.get('PrimaryURL')
                misc_references = misconfiguration.get('References', [])

                title = f'{misc_id} - {misc_title}'
                description = MISC_DESCRIPTION_TEMPLATE.format(
                    target=target_target,
                    type=misc_type,
                    description=misc_description,
                    message=misc_message,
                )
                severity = TRIVY_SEVERITIES[misc_severity]
                references = None
                if misc_primary_url:
                    references = f'{misc_primary_url}\n'
                if misc_primary_url in misc_references:
                    misc_references.remove(misc_primary_url)
                if references:
                    references += '\n'.join(misc_references)
                else:
                    references = '\n'.join(misc_references)

                finding = Finding(
                    test=test,
                    title=title,
                    severity=severity,
                    references=references,
                    description=description,
                    mitigation=misc_resolution,
                    static_finding=True,
                    dynamic_finding=False,
                    tags=[target_type, target_class],
                    service=service_name,
                )
                items.append(finding)

            secrets = target_data.get('Secrets', [])
            for secret in secrets:
                secret_category = secret.get('Category')
                secret_title = secret.get('Title')
                secret_severity = secret.get('Severity')
                secret_match = secret.get('Match')
                secret_start_line = secret.get('StartLine')

                title = f'Secret detected in {target_target} - {secret_title}'
                description = SECRET_DESCRIPTION_TEMPLATE.format(
                    title=secret_title,
                    category=secret_category,
                    match=secret_match,
                )
                severity = TRIVY_SEVERITIES[secret_severity]

                finding = Finding(
                    test=test,
                    title=title,
                    severity=severity,
                    description=description,
                    file_path=target_target,
                    line=secret_start_line,
                    static_finding=True,
                    dynamic_finding=False,
                    tags=[target_class],
                    service=service_name,
                )
                items.append(finding)

        return items
