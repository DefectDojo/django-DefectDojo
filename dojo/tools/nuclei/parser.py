import json
import hashlib
from dojo.models import Finding, Endpoint


class NucleiParser(object):
    """
    A class that can be used to parse the nuclei (https://github.com/projectdiscovery/nuclei) JSON report file
    """

    # table to match nuclei severity to DefectDojo severity
    SEVERITY = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
    }

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
                if info.get('severity') in self.SEVERITY:
                    severity = self.SEVERITY[info.get('severity')]
                else:
                    severity = "Low"
                type = item.get('type')
                host = item.get('host')
                matched = item.get('matched')
                ip = item.get('ip')

                dupe_key = hashlib.sha256(
                    (template_id + type + host + ip + matched).encode('utf-8')
                ).hexdigest()

                if dupe_key in dupes:
                    finding = dupes[dupe_key]
                    finding.nb_occurences += 1
                else:
                    finding = Finding(
                        title=f"{name}: {matched}",
                        test=test,
                        severity=severity,
                        nb_occurences=1,
                    )
                    if info.get('description'):
                        finding.description = info.get('description')
                    if info.get('tags'):
                        finding.unsaved_tags = info.get('tags')
                    if info.get('reference'):
                        finding.references = info.get('reference')
                    finding.unsaved_endpoints = []
                    if '://' in matched:
                        endpoint = Endpoint.from_uri(matched)
                    else:
                        endpoint = Endpoint.from_uri('//' + matched)
                    finding.unsaved_endpoints.append(endpoint)
                    dupes[dupe_key] = finding
            return list(dupes.values())
