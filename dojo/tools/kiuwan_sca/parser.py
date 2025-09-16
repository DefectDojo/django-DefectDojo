import hashlib
import json
import logging

from dojo.models import Finding

logger = logging.getLogger(__name__)

__author__ = "mwager"


class KiuwanSCAParser:
    SEVERITY = {
        "-": "Low",
        "LOW": "Low",
        "MEDIUM": "Medium",
        "HIGH": "High",
        "CRITICAL": "Critical",
        "Low": "Low",
        "Medium": "Medium",
        "High": "High",
        "Critical": "Critical",
    }

    def get_scan_types(self):
        return ["Kiuwan SCA Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Kiuwan Insights Scan in JSON format. Export as JSON using Kiuwan REST API."

    def get_findings(self, filename, test):
        data = json.load(filename)
        dupes = {}

        for row in data:
            # if a finding was "muted" in the Kiuwan UI, we ignore it (e.g. marked as false positive)
            if row["muted"] is True:
                continue

            components = row.get("components", [])
            if not components:
                logger.debug("Insights Finding from Kiuwan does not have a related component - Skipping.")
                continue

            # We want one unique finding in DD for each component affected:
            for component in components:
                finding = Finding(test=test)
                finding.vuln_id_from_tool = str(row["id"])
                finding.cve = row["cve"]
                finding.description = row["description"]
                finding.severity = self.SEVERITY[row["securityRisk"]]

                if "artifact" in component:
                    finding.component_name = component["artifact"]
                if "version" in component:
                    finding.component_version = component["version"]

                if finding.component_name and finding.component_version:
                    finding.title = f"{finding.component_name} v{finding.component_version}"
                else:
                    finding.title = finding.cve or "Unnamed Finding"

                if "cwe" in row and "CWE-" in row["cwe"]:
                    finding.cwe = int(row["cwe"].replace("CWE-", ""))

                if "epss_score" in row:
                    finding.epss_score = row["epss_score"]
                if "epss_percentile" in row:
                    finding.epss_percentile = row["epss_percentile"]

                if "cVSSv3BaseScore" in row:
                    finding.cvssv3_score = float(row["cVSSv3BaseScore"])

                finding.references = "See Kiuwan Web UI"
                finding.mitigation = "See Kiuwan Web UI"
                finding.static_finding = True

                key = hashlib.sha256(
                    (
                        finding.description
                        + "|"
                        + finding.severity
                        + "|"
                        + finding.component_name
                        + "|"
                        + finding.component_version
                        + "|"
                        + str(finding.cwe or "")
                    ).encode("utf-8"),
                ).hexdigest()

                if key not in dupes:
                    dupes[key] = finding

        return list(dupes.values())
