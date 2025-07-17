import json
import hashlib

from datetime import datetime
from dojo.models import Finding, Endpoint


class WazuhIndexerParser:
    def get_scan_types(self):
        return ["Wazuh48v"]

    def get_label_for_scan_types(self, scan_type):
        return "Wazuh 48z"

    def get_description_for_scan_types(self, scan_type):
        return "Wazuh Vulnerability Data >= 4.8 from indexer in JSON format. See the documentation for search a script to obtain a clear output."

    def get_findings(self, file, test):
        data = json.load(file)

        if not data:
            return []

        # Detect duplications
        dupes = {}

        # Loop through each element in the list
        vulnerabilities = data.get("hits", {}).get("hits", [])
        for item_source in vulnerabilities:

            item = item_source.get("_source")

            # Get all vulnerability data
            vuln = item.get("vulnerability")

            description = vuln.get("description")
            cve = vuln.get("id")
            detected_at = datetime.fromisoformat(vuln["detected_at"].replace("Z", "+00:00")).date()
            references = vuln.get("reference")
            severity = vuln.get("severity")
            if vuln.get("score"):
                cvss_score = vuln.get("score").get("base")
                cvss_version = vuln.get("score").get("version")



            # Agent is equal to the endpoint
            agent = item.get("agent")

            agent_id = agent.get("id")
            agent_name = agent.get("name")
            # agent_ip = agent.get("ip")  Maybe... will introduce it in the news versions of Wazuh?
            
            description = (
                f"Agent Name: {agent_name}\n"
                f"Agent ID: {agent_id}\n\n"
                f"{description}"
            )


            # Package in Wazuh is equivalent to "component" in DD
            package = item.get("package")

            package_name = package.get("name")
            package_version = package.get("version")
            package_description = package.get("description")
            # Only get this field on some Windows agents.
            package_path = package.get("path", None)

            # Get information about OS from agent.
            # This will use for
            info_os = item.get("host")
            if info_os and info_os.get("os"):
                name_os = info_os.get("os").get("full")
                kernel_os = info_os.get("os").get("kernel") if info_os.get("os").get("kernel") else "N/A"


            title = f"{cve} Affects {package_name} (Version: {package_version})"
            justify_severation = (
                f"Severity: {severity}"
                f"CVSS Score: {cvss_score}"
                f"CVSS Version: {cvss_version}"
                f"\nOS: {name_os}"
                f"Kernel: {kernel_os}\n"
                f"Package Name: {package_name}"
                f"Package Description: {package_description}"
            )

            dupe_key = cve + severity + description
            dupe_key = hashlib.sha256(dupe_key.encode("utf-8")).hexdigest()

            if dupe_key in dupes:
                find = dupes[dupe_key]
            else:
                dupes[dupe_key] = True

            finding = Finding(
                title=title,
                test=test,
                description=description,
                severity_justification=severity_justification
                severity=severity,
                references=references,
                static_finding=True,
                component_name=package_name,
                component_version=package_version,
                file_path=package_path if package_path else None,
                publish_date=detected_at,
                unique_id_from_tool=dupe_key,
            )

            finding.unsaved_vulnerability_ids = [cve]
            finding.unsaved_endpoints = [Endpoint(host=agent_name)]
            dupes[dupe_key] = finding

        return list(dupes.values())
