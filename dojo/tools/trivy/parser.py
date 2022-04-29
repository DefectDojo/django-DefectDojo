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
Target: {target}
Type: {type}
Fixed version: {fixed_version}

{description_text}
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
            results = data
        else:
            schema_version = data.get('SchemaVersion', None)
            if schema_version == 2:
                results = data.get('Results', None)
            else:
                raise ValueError('Schema of Trivy json report is not supported')

        items = list()
        for target_data in results:
            if not isinstance(target_data, dict) or 'Target' not in target_data:
                continue
            target = target_data['Target']
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
                items.append(
                    Finding(
                        test=test,
                        title=title,
                        cve=vuln_id,
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
                        tags=[type],
                    )
                )
        return items
