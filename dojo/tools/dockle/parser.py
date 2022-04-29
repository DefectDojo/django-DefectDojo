import json
import hashlib
from dojo.models import Finding


class DockleParser(object):
    """
    A class that can be used to parse the Dockle JSON report files
    """

    # table to match Dockle severity to DefectDojo severity
    SEVERITY = {
        "INFO": "Low",
        "WARN": "Medium",
        "FATAL": "High",
    }

    def get_scan_types(self):
        return ["Dockle Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Dockle Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import JSON output for Dockle scan report."

    def get_findings(self, filename, test):
        data = json.load(filename)
        dupes = {}
        for item in data['details']:
            code = item['code']
            dockle_severity = item['level']
            title = item['title']
            if dockle_severity == "IGNORE":
                continue
            if dockle_severity in self.SEVERITY:
                severity = self.SEVERITY[dockle_severity]
            else:
                severity = "Medium"
            description = item.get('alerts', [])
            description.sort()
            description = "\n".join(description)
            dupe_key = hashlib.sha256(
                (code + title).encode("utf-8")
            ).hexdigest()

            if dupe_key in dupes:
                finding = dupes[dupe_key]
                finding.nb_occurences += 1
            else:
                finding = Finding(
                    title=f"{code}: {title}",
                    test=test,
                    severity=severity,
                    description=description,
                    static_finding=True,
                    dynamic_finding=False,
                    nb_occurences=1,
                    vuln_id_from_tool=code,
                )
                dupes[dupe_key] = finding
        return list(dupes.values())
