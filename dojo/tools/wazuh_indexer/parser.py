import json
from datetime import datetime

from dojo.models import EndPoint, Finding


class WazuhIndexerParser:
    def get_scan_types(self):
        return ["Wazuh >= 4.8 Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Wazuh >= 4.8 Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Wazuh Vulnerability Data >= 4.8 from indexer in JSON format. See the documentation for search a script to obtain a clear output."

    def get_findings(self, file, test):
        data = json.load(file)

        if not data:
            return []

        findings = []

        vulnerabilities = data.get("hits", {}).get("hits", [])
        for item_source in vulnerabilities:

            item = item_source.get("_source")

            # Get all vulnerability data
            vuln = item.get("vulnerability")

            description = vuln.get("description")
            cve = vuln.get("id")
            published_date = datetime.fromisoformat(vuln["published_at"]).date()
            references = vuln.get("reference")
            severity = vuln.get("severity")
            if severity not in {"Critical", "High", "Medium", "Low"}:
                severity = "Info"

            if vuln.get("score"):
                cvss_score = vuln.get("score").get("base")
                cvss_version = vuln.get("score").get("version")
                cvss3 = cvss_version.split(".")[0]

            # Agent is equal to the endpoint
            agent = item.get("agent")

            agent_id = agent.get("id")
            agent_name = agent.get("name")
            # agent_ip = agent.get("ip")  Maybe... will introduce it in the news versions of Wazuh?

            description = (
                f"Agent Name/ID: {agent_name} / {agent_id}\n"
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
            # This will use for severity justification
            info_os = item.get("host")
            if info_os and info_os.get("os"):
                name_os = info_os.get("os").get("full", "N/A")
                kernel_os = info_os.get("os").get("kernel", "N/A")

            title = f"{cve} Affects {package_name} (Version: {package_version})"
            severity_justification = (
                f"Severity: {severity}\n"
                f"CVSS Score: {cvss_score}\n"
                f"CVSS Version: {cvss_version}\n"
                f"\nOS: {name_os}\n"
                f"Kernel: {kernel_os}\n\n"
                f"Package Name: {package_name}\n"
                f"Package Description: {package_description}"
            )

            finding = Finding(
                title=title,
                test=test,
                description=description,
                severity_justification=severity_justification,
                severity=severity,
                references=references,
                dynamic_finding=True,
                static_finding=False,
                component_name=package_name,
                component_version=package_version,
                file_path=package_path or None,
                publish_date=published_date,
                cvssv3_score=cvss3 or None,
            )

            finding.unsaved_vulnerability_ids = [cve]
            finding.unsaved_endpoints = [Endpoint(host=agent_name)]
            findings.append(finding)

        return findings
