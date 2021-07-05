import json
import hashlib
from dojo.models import Finding


class KICSParser(object):
    """
    A class that can be used to parse the KICS JSON report file
    """

    # table to match KICS severity to DefectDojo severity
    SEVERITY = {
        "HIGH": "High",
        "MEDIUM": "Medium",
        "LOW": "Low",
        "INFO": "Info",
    }

    def get_scan_types(self):
        return ["KICS Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "KICS Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import JSON output for KICS scan report."

    def get_findings(self, filename, test):
        data = json.load(filename)
        dupes = {}
        for query in data['queries']:
            name = query.get('query_name')
            url = query.get('query_url')
            if query.get('severity') in self.SEVERITY:
                severity = self.SEVERITY[query.get('severity')]
            else:
                severity = "Medium"
            platform = query.get('platform')
            category = query.get('category')
            description = f"{query.get('description')}\nMore information: {url}"
            for item in query.get('files'):
                file_name = item.get('file_name')
                line_number = item.get('line')
                issue_type = item.get('issue_type')
                expected_value = item.get('expected_value')

                dupe_key = hashlib.sha256(
                    (platform + category + issue_type + file_name + str(line_number)).encode("utf-8")
                ).hexdigest()

                if dupe_key in dupes:
                    finding = dupes[dupe_key]
                    finding.nb_occurences += 1
                else:
                    finding = Finding(
                        title=f"{category}: {name}",
                        test=test,
                        severity=severity,
                        description=description,
                        active=True,
                        verified=False,
                        mitigation=expected_value,
                        file_path=file_name,
                        line=line_number,
                        component_name=platform,
                        nb_occurences=1,
                    )
                    dupes[dupe_key] = finding
        return list(dupes.values())
