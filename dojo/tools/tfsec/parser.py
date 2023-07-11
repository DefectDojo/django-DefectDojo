import json
import hashlib
from dojo.models import Finding


class TFSecParser(object):
    """
    A class that can be used to parse the tfsec JSON report file
    """

    # table to match tfsec severity to DefectDojo severity
    SEVERITY = {
        "CRITICAL": "Critical",
        "HIGH": "High",
        "ERROR": "High",
        "MEDIUM": "Medium",
        "WARNING": "Medium",
        "LOW": "Low",
        "INFO": "Info",
    }

    def get_scan_types(self):
        return ["TFSec Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "TFSec Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import JSON output for TFSec scan report."

    def get_findings(self, filename, test):
        data = json.load(filename)
        dupes = {}
        if 'results' not in data:
            raise ValueError("Incorrect TFSec scan, missing attribute 'results'")
        if data.get('results') is None:
            return list()
        for item in data.get('results'):
            if item.get('passed', None):
                continue
            rule_id = item.get('rule_id')
            rule_description = item.get('rule_description')
            rule_provider = item.get('rule_provider')
            file = item.get('location').get('filename')
            start_line = item.get('location').get('start_line')
            end_line = item.get('location').get('end_line')
            description = '\n'.join(["Rule ID: " + rule_id, item.get('description')])
            impact = item.get('impact')
            resolution = item.get('resolution')
            if item.get('links', None) is not None:
                references = '\n'.join(item.get('links'))
            else:
                references = item.get('link', None)
            if item.get('severity').upper() in self.SEVERITY:
                severity = self.SEVERITY[item.get('severity').upper()]
            else:
                severity = "Low"

            dupe_key = hashlib.sha256(
                (rule_provider + rule_id + file + str(start_line) + str(end_line)).encode('utf-8')
            ).hexdigest()

            if dupe_key in dupes:
                finding = dupes[dupe_key]
                finding.nb_occurences += 1
            else:
                finding = Finding(
                    title=f"{rule_description}",
                    test=test,
                    severity=severity,
                    description=description,
                    mitigation=resolution,
                    references=references,
                    impact=impact,
                    file_path=file,
                    line=start_line,
                    vuln_id_from_tool=rule_id,
                    nb_occurences=1,
                )
                dupes[dupe_key] = finding
        return list(dupes.values())
