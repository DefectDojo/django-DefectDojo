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
Fixed version: {fixed_version}

{description_text}
"""


class TrivyParser:

    def __init__(self, scan_file, test):
        self.items = []

        scan_data = scan_file.read()

        try:
            data = json.loads(str(scan_data, 'utf-8'))
        except:
            data = json.loads(scan_data)

        if not isinstance(data, list):
            return

        for target_data in data:
            if not isinstance(target_data, dict) or 'Target' not in target_data:
                continue
            target = target_data['Target']
            vulnerabilities = target_data.get('Vulnerabilities', []) or []
            for vuln in vulnerabilities:
                if not isinstance(vuln, dict):
                    continue
                try:
                    vuln_id = vuln['VulnerabilityID']
                    package_name = vuln['PkgName']
                    severity = TRIVY_SEVERITIES[vuln['Severity']]
                except KeyError as exc:
                    logger.warning('skip vulnerability due %r', exc)
                    continue
                package_version = vuln.get('InstalledVersion', '')
                references = '\n'.join(vuln.get('References', []))
                mitigation = vuln.get('FixedVersion', '')
                title = ' '.join([
                    vuln_id,
                    package_name,
                    package_version,
                ])
                description = DESCRIPTION_TEMPLATE.format(
                    title=vuln.get('Title', ''),
                    target=target,
                    fixed_version=mitigation,
                    description_text=vuln.get('Description', ''),
                )
                self.items.append(
                    Finding(
                        test=test,
                        title=title,
                        cve=vuln_id,
                        severity=severity,
                        references=references,
                        description=description,
                        mitigation=mitigation,
                    )
                )
