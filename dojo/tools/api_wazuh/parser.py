import json
import hashlib
from dojo.models import Finding, Endpoint
from .importer import (
    WazuhApiImporter,
)  # Importing the WazuhApiImporter from importer.py

SCAN_TYPE_ID = "Wazuh API"


class ApiWazuhParser(object):
    """
    Import from Wazuh API
    """

    def get_scan_types(self):
        return [SCAN_TYPE_ID]

    def get_label_for_scan_types(self, scan_type):
        return SCAN_TYPE_ID

    def get_description_for_scan_types(self, scan_type):
        return "Wazuh findings can be directly imported using the Wazuh API."

    def requires_file(self, scan_type):
        return False  # Since we're interacting with the API, no file is required

    def requires_tool_type(self, scan_type):
        return SCAN_TYPE_ID  # This parser is specifically for the Wazuh API

    def api_scan_configuration_hint(self):
        return "Please ensure the correct API endpoint and API key (JWT token) are configured for Wazuh."

    def get_findings(self, file, test):
        # If a file is not provided, fetch data from the Wazuh API
        if file is None:
            data = WazuhApiImporter().get_findings(
                test
            )  # Adapted to use WazuhApiImporter
        else:
            data = json.load(file)

        if not data:
            return []

        # Detect duplications
        dupes = dict()

        # Loop through each element in the list
        for entry in data:
            vulnerabilities = entry.get("data", {}).get("affected_items", [])
            for item in vulnerabilities:
                if (
                    item["condition"] != "Package unfixed"
                    and item["severity"] != "Untriaged"
                ):
                    id = item.get("cve")
                    package_name = item.get("name")
                    package_version = item.get("version")
                    description = item.get("condition")
                    severity = item.get("severity").capitalize()
                    agent_ip = item.get("agent_ip")
                    links = item.get("external_references")
                    cvssv3_score = item.get("cvss3_score")
                    publish_date = item.get("published")

                    if links:
                        references = "\n".join(links)
                    else:
                        references = None

                    title = item.get("title") + " (version: " + package_version + ")"
                    dupe_key = title + id + agent_ip + package_name + package_version
                    dupe_key = hashlib.sha256(dupe_key.encode("utf-8")).hexdigest()

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
                            cvssv3_score=cvssv3_score,
                            publish_date=publish_date,
                            unique_id_from_tool=dupe_key,
                        )
                        if id and id.startswith("CVE"):
                            find.unsaved_vulnerability_ids = [id]
                        if agent_ip:
                            find.unsaved_endpoints = [Endpoint(host=agent_ip)]
                        dupes[dupe_key] = find

        return list(dupes.values())
