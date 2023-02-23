import json
from dojo.models import Finding


class WazuhParser(object):
    """Wazuh JSON """

    def get_scan_types(self):
        return ["Wazuh"]

    def get_label_for_scan_types(self, scan_type):
        return "Wazuh"

    def get_description_for_scan_types(self, scan_type):
        return "Wazuh"

    def get_findings(self, filename, test):
        tree = filename.read()
        try:
            data = json.loads(str(tree, "utf-8"))
        except:
            data = json.loads(tree)

        # Detect duplications
        dupes = dict()

        try:
            vulnerability = data[next(iter(data.keys()))]["affected_items"]
        except (KeyError, StopIteration):
            return list()

        if vulnerability is None:
            return list()

        for item in vulnerability:
            if item['condition'] != "Package unfixed":
                id = item.get('cve')
                package_name = item.get('name')
                package_version = item.get('version')
                description = item.get('condition')
                severity = item.get('severity')
                links = item.get('external_references')
                title = item.get('title') + " (version: " + package_version + ")"
                severity = transpose_severity(severity)
                if links:
                    references = ''
                    for link in links:
                        references += f'{link}\n'
                else:
                    references = None

                if id and id.startswith('CVE'):
                    vulnerability_id = id
                else:
                    vulnerability_id = None

                dupe_key = title

                if dupe_key in dupes:
                    find = dupes[dupe_key]
                else:
                    dupes[dupe_key] = True

                    find = Finding(
                        title=title,
                        test=test,
                        description=description,
                        severity=severity,
                        mitigation="mitigation",
                        references=references,
                        static_finding=True,
                        component_name=package_name,
                        component_version=package_version,
                    )
                    if vulnerability_id:
                        find.unsaved_vulnerability_ids = [vulnerability_id]
                    dupes[dupe_key] = find
        return list(dupes.values())


def transpose_severity(severity):
    if severity in Finding.SEVERITIES:
        return severity
    else:
        return 'Info'
