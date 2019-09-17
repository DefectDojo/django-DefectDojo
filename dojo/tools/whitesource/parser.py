import hashlib
import json
from dojo.models import Finding

__author__ = 'dr3dd589'


class WhitesourceJSONParser(object):
    def __init__(self, file, test):
        self.dupes = dict()
        self.items = ()
        if file is None:
            return

        data = file.read()
        try:
            content = json.loads(str(data, 'utf-8'))
        except:
            content = json.loads(data)
        if "vulnerabilities" in content:
            tree_node = content['vulnerabilities']
            for node in tree_node:
                title = node['name'] + " | " + node['project']
                severity = node['severity'].lower().capitalize()
                description = "**Description** : " + node.get('description', "") + "\n\n" + \
                            "**Library Name** : " + node['library'].get('name', "") + "\n\n" + \
                            "**Library Filename** : " + node['library'].get('filename', "") + "\n\n" + \
                            "**Library Description** : " + node['library'].get('description', "") + "\n\n" + \
                            "**Library Type** : " + node['library'].get('type', "") + "\n"
                try:
                    mitigation = "**fixResolution** : " + node['topFix']['fixResolution'] + "\n" + \
                                "**Message** : " + node['topFix']['message'] + "\n"
                except:
                    mitigation = "N/A"

                if "CVE" in node['type']:
                    cve = node['name']
                else:
                    cve = None

                dupe_key = hashlib.md5(description.encode('utf-8') + title.encode('utf-8')).hexdigest()

                if dupe_key in self.dupes:
                    finding = self.dupes[dupe_key]
                    if finding.description:
                        finding.description = finding.description
                    self.dupes[dupe_key] = finding
                else:
                    self.dupes[dupe_key] = True

                    finding = Finding(title=title,
                                    test=test,
                                    active=False,
                                    verified=False,
                                    description=description,
                                    severity=severity,
                                    cve=cve,
                                    mitigation=mitigation,
                                    numerical_severity=Finding.get_numerical_severity(
                                        severity),
                                    dynamic_finding=True)
                    self.dupes[dupe_key] = finding

            self.items = self.dupes.values()
