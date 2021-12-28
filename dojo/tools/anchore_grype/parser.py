import json
from cvss import parser as cvss_parser
from cvss.cvss3 import CVSS3

from dojo.models import Finding


class AnchoreGrypeParser(object):
    """Anchore Grype JSON report format generated with `-o json` option.

    command: `grype defectdojo/defectdojo-django:1.13.1 -o json > many_vulns.json`
    """

    def get_scan_types(self):
        return ["Anchore Grype"]

    def get_label_for_scan_types(self, scan_type):
        return "Anchore Grype"

    def get_description_for_scan_types(self, scan_type):
        return "A vulnerability scanner for container images and filesystems. JSON report generated with '-o json' format"

    def get_findings(self, file, test):
        data = json.load(file)
        dupes = dict()
        for item in data.get("matches", []):
            vulnerability = item['vulnerability']
            vuln_id = vulnerability["id"]
            vuln_namespace = vulnerability.get('namespace')
            vuln_datasource = vulnerability.get('dataSource')
            vuln_severity = self._convert_severity(vulnerability["severity"])
            vuln_urls = vulnerability.get('urls')
            vuln_description = vulnerability.get('description')
            vuln_fix_versions = None
            if 'fix' in vulnerability:
                vuln_fix_versions = vulnerability['fix'].get('versions')
            vuln_cvss = vulnerability.get('cvss')

            rel_id = None
            rel_datasource = None
            rel_urls = None
            rel_description = None
            rel_cvss = None
            related_vulnerabilities = item.get('relatedVulnerabilities')
            if related_vulnerabilities:
                related_vulnerability = related_vulnerabilities[0]
                rel_id = related_vulnerability.get('id')
                rel_datasource = related_vulnerability.get('dataSource')
                rel_urls = related_vulnerability.get('urls')
                rel_description = related_vulnerability.get('description')
                rel_cvss = related_vulnerability.get('cvss')

            matches = item['matchDetails']

            artifact = item['artifact']
            artifact_name = artifact.get('name')
            artifact_version = artifact.get('version')
            artifact_purl = artifact.get('purl')

            cve = self.get_cve(vuln_id, rel_id)
            finding_title = f'{cve} in {artifact_name}:{artifact_version}'

            finding_tags = None
            finding_description = f'**Vulnerability Id:** {vuln_id}'
            if vuln_namespace:
                finding_description += f'\n**Vulnerability Namespace:** {vuln_namespace}'
            if vuln_description:
                finding_description += f'\n**Vulnerability Description:** {vuln_description}'
            if rel_id and rel_id != vuln_id:
                finding_description += f'\n**Related Vulnerability Id:** {rel_id}'
            if rel_description and rel_description != vuln_description:
                finding_description += f'\n**Related Vulnerability Description:** {rel_description}'
            if matches:
                if type(item["matchDetails"]) is dict:
                    finding_description += f"\n**Matcher:** {matches['matcher']}"
                    finding_tags = [matches['matcher'].replace('-matcher', '')]
                elif len(matches) == 1:
                    finding_description += f"\n**Matcher:** {matches[0]['matcher']}"
                    finding_tags = [matches[0]['matcher'].replace('-matcher', '')]
                else:
                    finding_description += '\n**Matchers:**'
                    finding_tags = []
                    for match in matches:
                        finding_description += f"\n- {match['matcher']}"
                        tag = match['matcher'].replace('-matcher', '')
                        if tag not in finding_tags:
                            finding_tags.append(tag)
            if artifact_purl:
                finding_description += f'\n**Package URL:** {artifact_purl}'

            if cve.startswith('CVE'):
                finding_cve = cve
            else:
                finding_cve = None

            finding_mitigation = None
            if vuln_fix_versions:
                finding_mitigation = 'Upgrade to version:'
                if len(vuln_fix_versions) == 1:
                    finding_mitigation += f' {vuln_fix_versions[0]}'
                else:
                    for fix_version in vuln_fix_versions:
                        finding_mitigation += f'\n- {fix_version}'

            finding_references = ''
            if vuln_datasource:
                finding_references += f'**Vulnerability Datasource:** {vuln_datasource}\n'
            if vuln_urls:
                if len(vuln_urls) == 1:
                    if vuln_urls[0] != vuln_datasource:
                        finding_references += f'**Vulnerability URL:** {vuln_urls[0]}\n'
                else:
                    finding_references += '**Vulnerability URLs:**\n'
                    for url in vuln_urls:
                        if url != vuln_datasource:
                            finding_references += f'- {url}\n'
            if rel_datasource:
                finding_references += f'**Related Vulnerability Datasource:** {rel_datasource}\n'
            if rel_urls:
                if len(rel_urls) == 1:
                    if rel_urls[0] != vuln_datasource:
                        finding_references += f'**Related Vulnerability URL:** {rel_urls[0]}\n'
                else:
                    finding_references += '**Related Vulnerability URLs:**\n'
                    for url in rel_urls:
                        if url != vuln_datasource:
                            finding_references += f'- {url}\n'
            if finding_references and finding_references[-1] == '\n':
                finding_references = finding_references[:-1]

            finding_cvss3 = None
            if vuln_cvss:
                finding_cvss3 = self.get_cvss(vuln_cvss)
            if not finding_cvss3 and rel_cvss:
                finding_cvss3 = self.get_cvss(rel_cvss)

            dupe_key = finding_title
            if dupe_key in dupes:
                finding = dupes[dupe_key]
                finding.nb_occurences += 1
            else:
                dupes[dupe_key] = Finding(
                            title=finding_title,
                            description=finding_description,
                            cve=finding_cve,
                            cwe=1352,
                            cvssv3=finding_cvss3,
                            severity=vuln_severity,
                            mitigation=finding_mitigation,
                            references=finding_references,
                            component_name=artifact_name,
                            component_version=artifact_version,
                            vuln_id_from_tool=vuln_id,
                            tags=finding_tags,
                            static_finding=True,
                            dynamic_finding=False,
                            nb_occurences=1,
                        )

        return list(dupes.values())

    def _convert_severity(self, val):
        if "Unknown" == val:
            return "Info"
        elif "Negligible" == val:
            return "Info"
        else:
            return val.title()

    def get_cve(self, vuln_id, rel_id):
        if vuln_id and vuln_id.startswith('CVE'):
            return vuln_id
        elif rel_id and rel_id.startswith('CVE'):
            return rel_id
        else:
            return vuln_id

    def get_cvss(self, cvss):
        if cvss:
            for cvss_item in cvss:
                vector = cvss_item['vector']
                cvss_objects = cvss_parser.parse_cvss_from_text(vector)
                if len(cvss_objects) > 0 and type(cvss_objects[0]) == CVSS3:
                    return vector
        return None
