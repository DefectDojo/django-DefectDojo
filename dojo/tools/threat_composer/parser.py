import json
from collections import defaultdict
from os import linesep

from dojo.models import Finding


class ThreatComposerParser:

    """Threat Composer JSON can be imported. See here for more info on this JSON format."""

    PRIORITY_VALUES = ["Low", "Medium", "High"]
    STRIDE_VALUES = {
        "S": "Spoofing",
        "T": "Tampering",
        "R": "Repudiation",
        "I": "Information Disclosure",
        "D": "Denial of Service",
        "E": "Elevation of Privilege",
    }

    def get_scan_types(self):
        return ["ThreatComposer Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "ThreatComposer Scan"

    def get_description_for_scan_types(self, scan_type):
        return "ThreatComposer report file can be imported in JSON format."

    def get_findings(self, file, test):
        data = json.load(file)
        findings = []

        if "threats" not in data:
            msg = "Invalid ThreatComposer data"
            raise ValueError(msg)

        if "assumptionLinks" in data:
            assumptions = {assumption["id"]: assumption for assumption in data["assumptions"]}
            assumption_mitigation_links = defaultdict(list)
            assumption_threat_links = defaultdict(list)
            for link in data["assumptionLinks"]:
                linked_id = link["linkedId"]
                assumption_id = link["assumptionId"]
                assumption_type = link["type"]
                if assumption_id in assumptions:
                    if assumption_type == "Threat":
                        assumption_threat_links[linked_id].append(assumptions[assumption_id])
                    elif assumption_type == "Mitigation":
                        assumption_mitigation_links[linked_id].append(assumptions[assumption_id])

        if "mitigationLinks" in data:
            mitigations = {
                mitigation["id"]: {
                    "mitigation": mitigation,
                    "assumptions": assumption_mitigation_links[mitigation["id"]],
                }
                for mitigation in data["mitigations"]
            }
            mitigation_links = defaultdict(list)
            for link in data["mitigationLinks"]:
                linked_id = link["linkedId"]
                mitigation_id = link["mitigationId"]
                if mitigation_id in mitigations:
                    mitigation_links[linked_id].append(mitigations[mitigation_id])

        for threat in data["threats"]:

            if "threatAction" in threat:
                title = threat["threatAction"]
                severity, impact, comments = self.parse_threat_metadata(threat.get("metadata", []))
                description = self.to_description_text(threat, comments, assumption_threat_links[threat["id"]])
                mitigation = self.to_mitigation_text(mitigation_links[threat["id"]])
                unique_id_from_tool = threat["id"]
                vuln_id_from_tool = threat["numericId"]
                tags = threat.get("tags", [])

                finding = Finding(
                    title=title,
                    description=description,
                    severity=severity,
                    vuln_id_from_tool=vuln_id_from_tool,
                    unique_id_from_tool=unique_id_from_tool,
                    mitigation=mitigation,
                    impact=impact,
                    tags=tags,
                    static_finding=True,
                    dynamic_finding=False,
                )

                match threat.get("status", "threatIdentified"):
                    case "threatResolved":
                        finding.active = False
                        finding.is_mitigated = True
                        finding.false_p = False
                    case "threatResolvedNotUseful":
                        finding.active = False
                        finding.is_mitigated = True
                        finding.false_p = True

                findings.append(finding)

        return findings

    def to_mitigation_text(self, mitigations):
        text = ""
        for i, current in enumerate(mitigations):
            mitigation = current["mitigation"]
            assumption_links = current["assumptions"]
            counti = i + 1
            text += f"**Mitigation {counti} (ID: {mitigation['numericId']}, Status: {mitigation.get('status', 'Not defined')})**: {mitigation['content']}"

            for item in mitigation.get("metadata", []):
                if item["key"] == "Comments":
                    text += f"\n*Comments*: {item['value'].replace(linesep, ' ')} "
                    break

            text += self.to_assumption_text(assumption_links)

            text += "\n"

        return text

    def parse_threat_metadata(self, metadata):
        severity = "Info"
        impact = None
        comments = None

        for item in metadata:
            if item["key"] == "Priority" and item["value"] in self.PRIORITY_VALUES:
                severity = item["value"]
            elif item["key"] == "STRIDE" and all(element in self.STRIDE_VALUES for element in item["value"]):
                impact = ", ".join([self.STRIDE_VALUES[element] for element in item["value"]])
            elif item["key"] == "Comments":
                comments = item["value"]

        return severity, impact, comments

    def to_description_text(self, threat, comments, assumption_links):
        text = f"**Threat**: {threat['statement']}"
        if comments:
            text += f"\n*Comments*: {comments}"

        text += self.to_assumption_text(assumption_links)

        return text

    def to_assumption_text(self, assumption_links):
        text = ""
        for i, assumption in enumerate(assumption_links):
            counti = i + 1
            text += f"\n- *Assumption {counti} (ID: {assumption['numericId']})*: {assumption['content'].replace(linesep, ' ')}"

            for item in assumption.get("metadata", []):
                if item["key"] == "Comments":
                    text += f"\n&nbsp;&nbsp;*Comments*: {item['value'].replace(linesep, ' ')} "
                    break

        return text
