import json
import hashlib
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
                info = item.get('info')
                name = info.get('name')
                severity = info.get('severity').title()
                type = item.get('type')
                matched = item.get('matched')
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
