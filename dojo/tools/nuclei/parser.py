import json
import hashlib
from cvss import parser as cvss_parser
from dojo.models import Finding, Endpoint


class NucleiParser(object):
    """
    A class that can be used to parse the nuclei (https://github.com/projectdiscovery/nuclei) JSON report file
    """

    def get_scan_types(self):
        return ["Nuclei Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Nuclei Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import JSON output for nuclei scan report."

    def get_findings(self, filename, test):
        data = [json.loads(line) for line in filename]
        if len(data) == 0:
            return []
        else:
            dupes = {}
            for item in data:
                template_id = item.get('templateID')
                if template_id is None:
                    template_id = item.get('template-id')
                info = item.get('info')
                name = info.get('name')
                severity = info.get('severity').title()
                type = item.get('type')
                matched = item.get('matched')
                if matched is None:
                    matched = item.get('matched-at')
                if '://' in matched:
                    endpoint = Endpoint.from_uri(matched)
                else:
                    endpoint = Endpoint.from_uri('//' + matched)

                finding = Finding(
                    title=f"{name}",
                    test=test,
                    severity=severity,
                    nb_occurences=1,
                    vuln_id_from_tool=template_id,
                )
                if info.get('description'):
                    finding.description = info.get('description')
                if info.get('tags'):
                    finding.unsaved_tags = info.get('tags')
                if info.get('reference'):
                    finding.references = info.get('reference')
                finding.unsaved_endpoints.append(endpoint)

                classification = info.get('classification')
                if classification:
                    if 'cve-id' in classification and classification['cve-id']:
                        cve_ids = classification['cve-id']
                        finding.unsaved_vulnerability_ids = list(map(lambda x: x.upper(), cve_ids))
                    if 'cwe-id' in classification and classification['cwe-id'] and len(classification['cwe-id']) > 0:
                        cwe = classification['cwe-id'][0]
                        finding.cwe = int(cwe[4:])
                    if 'cvss-metrics' in classification and classification['cvss-metrics']:
                        cvss_objects = cvss_parser.parse_cvss_from_text(classification['cvss-metrics'])
                        if len(cvss_objects) > 0:
                            finding.cvssv3 = cvss_objects[0].clean_vector()
                    if 'cvss-score' in classification and classification['cvss-score']:
                        finding.cvssv3_score = classification['cvss-score']

                dupe_key = hashlib.sha256(
                    (template_id + type).encode('utf-8')
                ).hexdigest()

                if dupe_key in dupes:
                    finding = dupes[dupe_key]
                    if endpoint not in finding.unsaved_endpoints:
                        finding.unsaved_endpoints.append(endpoint)
                    finding.nb_occurences += 1
                else:
                    dupes[dupe_key] = finding
            return list(dupes.values())
