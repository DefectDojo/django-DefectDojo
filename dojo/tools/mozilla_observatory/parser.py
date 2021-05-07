import json

from dojo.models import Finding


class MozillaObservatoryParser(object):
    """Mozilla Observatory

    See: https://observatory.mozilla.org

    See: https://github.com/mozilla/observatory-cli

    See: https://github.com/mozilla/http-observatory
    """

    def get_scan_types(self):
        return ["Mozilla Observatory Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Mozilla Observatory Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import JSON report."

    def get_findings(self, file, test):
        data = json.load(file)
        # format from the CLI
        if "tests" in data:
            nodes = data["tests"]
        else:
            nodes = data

        findings = list()
        for key in nodes:
            node = nodes[key]

            description = "\n".join([
                "**Score Description** : `" + node['score_description'] + "`",
                "**Result** : `" + node['result'] + "`"
                "**expectation** : " + str(node.get('expectation')) + "`",
            ])

            finding = Finding(
                title=node['score_description'],
                test=test,
                active=not node['pass'],
                description=description,
                severity=self.get_severity(int(node['score_modifier'])),
                static_finding=False,
                dynamic_finding=True,
                vuln_id_from_tool=node['name']
            )

            findings.append(finding)
        return findings

    def get_severity(self, num_severity):
        if num_severity >= -10:
            return "Low"
        elif -11 >= num_severity > -26:
            return "Medium"
        elif num_severity <= -26:
            return "High"
        else:
            return "Info"
