import json
import hashlib
from dojo.models import Finding


class CargoAuditParser(object):
    """
    A class that can be used to parse the cargo audit JSON report file
    """

    def get_scan_types(self):
        return ["CargoAudit Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "CargoAudit Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import JSON output for cargo audit scan report."

    def get_findings(self, filename, test):
        data = json.load(filename)
        dupes = {}
        if data.get('vulnerabilities'):
            for item in data.get('vulnerabilities').get('list'):
                advisory = item.get('advisory')
                vuln_id = advisory.get('id')
                if "categories" in advisory:
                    categories = f"**Categories:** {', '.join(advisory['categories'])}"
                else:
                    categories = ''
                description = categories + f"\n**Description:** `{advisory.get('description')}`"

                if item["affected"] is not None and "functions" in item["affected"]:
                    affected_func = [f'{func}: {", ".join(versions)}'
                                     for func, versions in item["affected"]["functions"].items()]
                    description += f"\n**Affected functions**: {', '.join(affected_func)}"

                references = f"{advisory.get('url')}\n" + '\n'.join(advisory['references'])
                date = advisory.get('date')

                if len(advisory.get('aliases')) != 0:
                    cve = advisory.get('aliases')[0]
                else:
                    cve = None

                package_name = item.get('package').get('name')
                package_version = item.get('package').get('version')
                title = f"[{package_name} {package_version}] {advisory.get('title')}"
                severity = "High"
                if 'keywords' in advisory:
                    tags = advisory.get('keywords')
                else:
                    tags = []
                try:
                    mitigation = f"**Update {package_name} to** {', '.join(item['versions']['patched'])}"
                except KeyError:
                    mitigation = "No information about patched version"
                dupe_key = hashlib.sha256(
                    (vuln_id + str(cve) + date + package_name + package_version).encode('utf-8')
                ).hexdigest()

                if dupe_key in dupes:
                    finding = dupes[dupe_key]
                    finding.nb_occurences += 1
                else:
                    finding = Finding(
                        title=title,
                        test=test,
                        severity=severity,
                        cve=cve,
                        tags=tags,
                        description=description,
                        component_name=package_name,
                        component_version=package_version,
                        vuln_id_from_tool=vuln_id,
                        publish_date=date,
                        nb_occurences=1,
                        references=references,
                        mitigation=mitigation
                    )
                    dupes[dupe_key] = finding
        return list(dupes.values())
