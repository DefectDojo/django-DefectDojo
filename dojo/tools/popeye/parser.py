import hashlib
import json
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
        for sanitizer in data['popeye']['sanitizers']:
            try:
                for issue_group, issue_list in sanitizer['issues'].items():
                    for issue in issue_list:
                        if issue['level'] != 0:
                            title = sanitizer['sanitizer'] + " " + issue_group + " " + issue['message']
                            severity = self.getDefectDojoSeverity(issue['level'])
                            description = "**Sanitizer** : " + sanitizer['sanitizer'] + "\n\n" + \
                                        "**Resource** : " + issue_group + "\n\n" + \
                                        "**Group** : " + issue['group'] + "\n\n" + \
                                        "**Severity** : " + self.getPopeyeLevelString(issue['level']) + "\n\n" + \
                                        "**Message** : " + issue['message']
                            found_by = "Popeye"

                            finding = Finding(
                                title=title,
                                test=test,
                                description=description,
                                severity=severity,
                                static_finding=False,
                                dynamic_finding=False, 
                            )
                            # internal de-duplication
                            dupe_key = hashlib.sha256(str(description + title).encode('utf-8')).hexdigest()
                            if dupe_key in dupes:
                                find = dupes[dupe_key]
                                if finding.description:
                                    find.description += "\n" + finding.description
                                dupes[dupe_key] = find
                            else:
                                dupes[dupe_key] = finding
                        else:
                            continue
            except KeyError:
                continue
        return list(dupes.values())

    def getPopeyeLevelString (self, level):
        if level is 1 : return "Info"
        elif level is 2 : return "Warning"
        else: return "Error"

    def getDefectDojoSeverity (self, level):
        if level is 1 or 3: return "Info"
        else: return "Low"
