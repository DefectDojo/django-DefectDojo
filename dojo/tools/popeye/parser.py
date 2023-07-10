import hashlib
import json
import re
from dojo.models import Finding


class PopeyeParser(object):
    """
    Popeye is a kubernetes cluster resource analyzer.
    """

    def get_scan_types(self):
        return ["Popeye Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Popeye Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Popeye report file can be imported in JSON format (option --json)."

    def get_findings(self, file, test):
        data = json.load(file)

        dupes = dict()
        for sanitizer in data["popeye"]["sanitizers"]:
            issues = sanitizer.get("issues")
            if issues:
                for issue_group, issue_list in issues.items():
                    for issue in issue_list:
                        if issue["level"] != 0:
                            title = (
                                sanitizer["sanitizer"]
                                + " "
                                + issue_group
                                + " "
                                + issue["message"]
                            )
                            severity = self.get_defect_dojo_severity(
                                issue["level"]
                            )
                            description = (
                                "**Sanitizer** : "
                                + sanitizer["sanitizer"]
                                + "\n\n"
                                + "**Resource** : "
                                + issue_group
                                + "\n\n"
                                + "**Group** : "
                                + issue["group"]
                                + "\n\n"
                                + "**Severity** : "
                                + self.get_popeye_level_string(issue["level"])
                                + "\n\n"
                                + "**Message** : "
                                + issue["message"]
                            )
                            vuln_id_from_tool = re.search(
                                r"\[(POP-\d+)\].+", issue["message"]
                            ).group(1)
                            finding = Finding(
                                title=title,
                                test=test,
                                description=description,
                                severity=severity,
                                static_finding=False,
                                dynamic_finding=True,
                                vuln_id_from_tool=vuln_id_from_tool,
                            )
                            # internal de-duplication
                            dupe_key = hashlib.sha256(
                                str(description + title).encode("utf-8")
                            ).hexdigest()
                            if dupe_key not in dupes:
                                dupes[dupe_key] = finding
        return list(dupes.values())

    def get_popeye_level_string(self, level):
        if level == 1:
            return "Info"
        elif level == 2:
            return "Warning"
        else:
            return "Error"

    def get_defect_dojo_severity(self, level):
        if level == 1:
            return "Info"
        elif level == 2:
            return "Low"
        else:
            return "High"
