import json
import hashlib
from dojo.models import Finding


class TerrascanParser(object):
    """
    A class that can be used to parse the terrascan JSON report file
    """

    # table to match tfsec severity to DefectDojo severity
    SEVERITY = {
        "HIGH": "High",
        "MEDIUM": "Medium",
        "LOW": "Low",
    }

    def get_scan_types(self):
        return ["Terrascan Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Terrascan Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import JSON output for Terrascan scan report."

    def get_findings(self, filename, test):
        data = json.load(filename)
        dupes = {}
        if 'results' not in data and 'violations' not in data.get('results'):
            raise ValueError("missing mandatory attribute 'results'")
        if data.get('results').get('violations') is None:
            return list()
        for item in data.get('results').get('violations'):
            rule_name = item.get('rule_name')
            description = item.get('description')
            if item.get('severity') in self.SEVERITY:
                severity = self.SEVERITY[item.get('severity')]
            else:
                severity = "Info"
            rule_id = item.get('rule_id')
            category = item.get('category')
            resource_name = item.get('resource_name')
            resource_type = item.get('resource_type')
            file = item.get('file')
            line = item.get('line')

            dupe_key = hashlib.sha256(
                (rule_id + rule_name + resource_name + resource_type + file + str(line)).encode('utf-8')
            ).hexdigest()

            if dupe_key in dupes:
                finding = dupes[dupe_key]
                finding.nb_occurences += 1
            else:
                finding = Finding(
                    title=f"{category}: {rule_name}",
                    test=test,
                    severity=severity,
                    description=description,
                    file_path=file,
                    line=line,
                    component_name=f"{resource_type}/{resource_name}",
                    vuln_id_from_tool=rule_id,
                    nb_occurences=1,
                )
                dupes[dupe_key] = finding
        return list(dupes.values())
