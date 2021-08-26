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
                title = advisory.get('title')
                description = "\n".join([
                    f"**Description:** `{advisory.get('description')}`",
                    f"\n**Read more:** `{advisory.get('url')}`",
                ])
                date = advisory.get('date')
                cve = advisory.get('aliases')[0]
                package_name = item.get('package').get('name')
                package_version = item.get('package').get('version')
                severity = "High"
                if 'keywords' in advisory:
                    tags = advisory.get('keywords')
                else:
                    tags = []

                dupe_key = hashlib.sha256(
                    (vuln_id + cve + date + package_name + package_version).encode('utf-8')
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
                    )
                    dupes[dupe_key] = finding
        return list(dupes.values())
