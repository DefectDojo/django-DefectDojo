import json
import hashlib
import re
from dojo.models import Finding


class NjsscanParser(object):
    """
    A class that can be used to parse the njsscan (https://github.com/ajinabraham/njsscan) JSON report file.
    """

    SEVERITY = {
        "ERROR": "High",
        "WARNING": "Medium",
        "INFO": "Low",
    }

    def get_scan_types(self):
        return ["Njsscan Scan"]

    def get_label_for_scan_types(self, scan_type):
        return ["Njsscan Scan"]

    def get_description_for_scan_types(self, scan_type):
        return "Import JSON report for njsscan report file."

    def get_finding(self, test, data, dupes):
        for key, item in data.items():
            metadata = item.get('metadata')
            cwe = int(re.match(r'CWE-([0-9]+)', metadata.get('cwe')).group(1))
            owasp = metadata.get('owasp')
            description = "\n".join([
                f"**Description:** `{metadata.get('description')}`",
                f"**OWASP**: `{owasp}`",
            ])
            if metadata.get('severity') in self.SEVERITY:
                severity = self.SEVERITY[metadata.get('severity')]
            else:
                severity = "Info"

            if item.get('files'):
                for file in item.get('files'):
                    finding = Finding(
                        title=f"{key}",
                        test=test,
                        severity=severity,
                        nb_occurences=1,
                        cwe=cwe,
                        description=description,
                    )
                    file_path = file.get('file_path')
                    line = file.get('match_lines')[0]
                    finding.file_path = file_path
                    finding.line = line
                    dupe_key = hashlib.sha256(
                        (key + str(cwe) + owasp + file_path + str(line)).encode('utf-8')
                    ).hexdigest()

                    if dupe_key in dupes:
                        finding = dupes[dupe_key]
                        finding.nb_occurences += 1
                    else:
                        dupes[dupe_key] = finding

    def get_findings(self, filename, test):
        data = json.load(filename)
        if len(data.get('nodejs')) == 0 or len(data.get('templates')) == 0:
            return []
        else:
            dupes = []
            if len(data.get('nodejs')) > 0:
                self.get_finding(test, data.get('nodejs'), dupes)
            if len(data.get('templates')) > 0:
                self.get_finding(test, data.get('templates'), dupes)
        return list(dupes.values())
