import json
from dojo.models import Finding


class WazuhParser(object):
    """
    Use Wazuh Vulnerability API to retrieve the findings
    The vulnerabilities with condition "Package unfixed" are skipped because there is no fix out yet.
    https://github.com/wazuh/wazuh/issues/14560
    """

    def get_scan_types(self):
        return ["Wazuh"]

    def get_label_for_scan_types(self, scan_type):
        return "Wazuh"

    def get_description_for_scan_types(self, scan_type):
        return "Wazuh"

    def get_findings(self, filename, test):
        data = json.load(filename)
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
                severity = transpose_severity(item.get('severity'))
                if item.get('status') == "VALID":
                    active = True
                else:
                    active = False
                links = item.get('external_references')
                title = item.get('title') + " (version: " + package_version + ")"
                severity = item.get('severity', 'info').capitalize()
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
                        active=active,
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
