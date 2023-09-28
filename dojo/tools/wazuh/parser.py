import json
from dojo.models import Finding, Endpoint

class WazuhParser(object):
    """
    IMPORTANT: Please use the 'wazuh-vulns-extractor.py' script to generate 
    the report for DefectDojo. This script enhances the reporting by:
    1. Handling multiple agents, thus allowing consolidated reporting.
    2. Introducing the 'agent_ip' field, which DefectDojo uses to create distinct endpoints.
    3. Correlating individual vulnerabilities with their respective vulnerable host.
    All these improvements are combined into a single, comprehensive report for streamlined 
    integration with DefectDojo.

    The vulnerabilities with condition "Package unfixed" are skipped because there is no fix out yet.
    https://github.com/wazuh/wazuh/issues/14560
    """

    def get_scan_types(self):
        return ["Wazuh"]

    def get_label_for_scan_types(self, scan_type):
        return "Wazuh"

    def get_description_for_scan_types(self, scan_type):
        return "Wazuh"

    def get_findings(self, file, test):
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
                
                    if links:
                        references = "\n".join(links)
                    else:
                        references = None

                    title = (
                        item.get("title") + " (version: " + package_version + ")"
                    )
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
                        if id and id.startswith("CVE"):
                            find.unsaved_vulnerability_ids = [id]
                        if agent_ip:
                            find.unsaved_endpoints = [Endpoint(host=agent_ip)]
                        dupes[dupe_key] = find

        return list(dupes.values())
