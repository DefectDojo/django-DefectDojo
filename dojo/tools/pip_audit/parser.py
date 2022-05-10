import json

from dojo.models import Finding


class PipAuditParser:

    def get_scan_types(self):
        return ["pip-audit Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "pip-audit Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import pip-audit JSON scan report."

    def requires_file(self, scan_type):
        return True

    def get_findings(self, scan_file, test):

        data = json.load(scan_file)

        findings = list()
        for item in data:
            vulnerabilities = item.get('vulns', [])
            if vulnerabilities:
                component_name = item['name']
                component_version = item.get('version')
                for vulnerability in vulnerabilities:
                    vuln_id = vulnerability.get('id')
                    vuln_fix_versions = vulnerability.get('fix_versions')
                    vuln_description = vulnerability.get('description')

                    title = f'{vuln_id} in {component_name}:{component_version}'

                    description = ''
                    description += vuln_description

                    mitigation = None
                    if vuln_fix_versions:
                        mitigation = 'Upgrade to version:'
                        if len(vuln_fix_versions) == 1:
                            mitigation += f' {vuln_fix_versions[0]}'
                        else:
                            for fix_version in vuln_fix_versions:
                                mitigation += f'\n- {fix_version}'

                    finding = Finding(
                        test=test,
                        title=title,
                        cwe=1352,
                        severity='Medium',
                        description=description,
                        mitigation=mitigation,
                        component_name=component_name,
                        component_version=component_version,
                        vuln_id_from_tool=vuln_id,
                        static_finding=True,
                        dynamic_finding=False,
                    )
                    vulnerability_ids = list()
                    if vuln_id:
                        vulnerability_ids.append(vuln_id)
                    if vulnerability_ids:
                        finding.unsaved_vulnerability_ids = vulnerability_ids

                    findings.append(finding)

        return findings
