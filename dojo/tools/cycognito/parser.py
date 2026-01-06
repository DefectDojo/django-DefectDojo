import json
from datetime import datetime

from dojo.models import Endpoint, Finding


class CycognitoParser:
    def get_scan_types(self):
        return ["Cycognito Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Cycognito Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Support Cycognito issues from returned JSON over API."

    def get_findings(self, file, test):
        data = json.load(file)
        findings = []
        for vulnerability in data:
            description = ""
            mitigation = ""
            impact = ""
            confidence = vulnerability.get("confidence", None)
            affected_asset = vulnerability.get("affected_asset", None)
            package = vulnerability.get("package", None)
            exploitation_availability = vulnerability.get("exploitation_availability", None)
            tools = vulnerability.get("tools", None)
            continent = vulnerability.get("continent", None)
            references = vulnerability.get("references", None)
            tech_owners = vulnerability.get("tech_owners", None)
            teams = vulnerability.get("teams", None)
            potential_threat = vulnerability.get("potential_threat", None)
            attacker_interest = vulnerability.get("attacker_interest", None)
            tags = vulnerability.get("tags", None)
            base_severity_score = vulnerability.get("base_severity_score", None)
            vulnid = vulnerability.get("id", None)
            remediation_method = vulnerability.get("remediation_method", None)
            issue_id = vulnerability.get("issue_id", None)
            first_detected = vulnerability.get("first_detected", None)
            summary = vulnerability.get("summary", None)
            exploitation_complexity = vulnerability.get("exploitation_complexity", None)
            underground_activity = vulnerability.get("underground_activity", None)
            resolved_at = vulnerability.get("resolved_at", None)
            snooze_expiration = vulnerability.get("snooze_expiration", None)
            attractiveness_label = vulnerability.get("attractiveness_label", None)
            affected_ptr_domains = vulnerability.get("affected_ptr_domains", None)
            affected_asset_tags = vulnerability.get("affected_asset_tags", None)
            advisories = vulnerability.get("advisories", None)
            environments = vulnerability.get("environments", None)
            locations = vulnerability.get("locations", None)
            region = vulnerability.get("region", None)
            detection_complexity = vulnerability.get("detection_complexity", None)
            port = vulnerability.get("port", None)
            remediation_effort = vulnerability.get("remediation_effort", None)
            exploitation_method = vulnerability.get("exploitation_method", None)
            attractiveness = vulnerability.get("attractiveness", None)
            title = vulnerability.get("title", None)
            platforms = vulnerability.get("platforms", None)
            exploitation_score = vulnerability.get("exploitation_score", None)
            base_severity = vulnerability.get("base_severity", None)
            issue_type = vulnerability.get("issue_type", None)
            organizations = vulnerability.get("organizations", None)
            business_units = vulnerability.get("business_units", None)
            cve_ids = vulnerability.get("cve_ids", None)
            comment = vulnerability.get("comment", None)
            evidence = vulnerability.get("evidence", None)
            remediation_steps = vulnerability.get("remediation_steps", None)
            potential_impact = vulnerability.get("potential_impact", None)
            if confidence is not None:
                description += "**confidence:** " + str(confidence) + "\n"
            if affected_asset is not None:
                description += "**affected_asset:** " + str(affected_asset) + "\n"
            if package is not None:
                description += "**package:** " + str(package) + "\n"
            if exploitation_availability is not None and not "None":
                description += "**exploitation_availability:** " + str(exploitation_availability) + "\n"
            if tools and tools is not None:
                description += "**tools:** " + str(tools) + "\n"
            if continent and continent is not None:
                description += "**continent:** " + str(", ".join(continent)) + "\n"
            if tech_owners and tech_owners is not None:
                description += "**tech_owners:** " + str(tech_owners) + "\n"
            if teams and teams is not None:
                description += "**teams:** " + str(teams) + "\n"
            if potential_threat and potential_threat is not None:
                description += "**potential_threat:** " + str(potential_threat) + "\n"
            if attacker_interest is not None and not "None":
                description += "**attacker_interest:** " + str(attacker_interest) + "\n"
            if tags and tags is not None:
                description += "**tags:** " + str(tags) + "\n"
            if base_severity_score is not None:
                description += "**base_severity_score:** " + str(base_severity_score) + "\n"
            if vulnid is not None:
                description += "**id:** " + str(vulnid) + "\n"
            if remediation_method is not None:
                mitigation += "**remediation_method:** " + str(remediation_method) + "\n"
            if issue_id is not None:
                description += "**issue_id:** " + str(issue_id) + "\n"
            if summary is not None:
                description += "**summary:** " + str(summary) + "\n"
            if exploitation_complexity is not None and exploitation_complexity != "unknown":
                description += "**exploitation_complexity:** " + str(exploitation_complexity) + "\n"
            if underground_activity is not None:
                description += "**underground_activity:** " + str(underground_activity) + "\n"
            if resolved_at is not None:
                description += "**resolved_at:** " + str(resolved_at) + "\n"
            if snooze_expiration is not None:
                description += "**snooze_expiration:** " + str(snooze_expiration) + "\n"
            if attractiveness_label is not None:
                description += "**attractiveness_label:** " + str(attractiveness_label) + "\n"
            if affected_ptr_domains and affected_ptr_domains is not None:
                description += "**affected_ptr_domains:** " + str(", ".join(affected_ptr_domains)) + "\n"
            if affected_asset_tags and affected_asset_tags is not None:
                description += "**affected_asset_tags:** " + "" + "\n"
            if advisories and advisories is not None:
                description += "**advisories:** " + str(advisories) + "\n"
            if environments and environments is not None:
                description += "**environments:** " + str(", ".join(environments)) + "\n"
            if locations and locations is not None:
                description += "**locations:** " + str(", ".join(locations)) + "\n"
            if region and region is not None:
                description += "**region:** " + str(", ".join(region)) + "\n"
            if detection_complexity is not None:
                description += "**detection_complexity:** " + str(detection_complexity) + "\n"
            if port is not None:
                description += "**port:** " + str(port) + "\n"
            if remediation_effort is not None:
                mitigation += "**remediation_effort:** " + str(remediation_effort) + "\n"
            if exploitation_method is not None and exploitation_method != "unknown":
                description += "**exploitation_method:** " + str(exploitation_method) + "\n"
            if attractiveness is not None:
                description += "**attractiveness:** " + str(attractiveness) + "\n"
            if platforms is not None:
                description += "**platforms:** " + str(", ".join(platforms)) + "\n"
            if exploitation_score is not None:
                description += "**exploitation_score:** " + str(exploitation_score) + "\n"
            if issue_type is not None:
                description += "**issue_type:** " + str(issue_type) + "\n"
            if organizations is not None:
                description += "**organizations:** " + str(", ".join(organizations)) + "\n"
            if business_units is not None:
                description += "**business_units:** " + str(", ".join(business_units)) + "\n"
            if comment is not None:
                description += "**comment:** " + str(comment) + "\n"
            if evidence is not None:
                description += "**evidence:** " + str(evidence) + "\n"
            if remediation_steps is not None:
                mitigation += "**remediation_steps:** " + str("\n ".join(remediation_steps)) + "\n"
            if potential_impact and potential_impact is not None:
                impact = "**potential_impact:** " + str(", ".join(potential_impact)) + "\n"
            finding = Finding(
                title=title,
                test=test,
                description=description,
                severity=base_severity.capitalize(),
                references=str("\n".join(references)),
                date=datetime.strptime(first_detected, "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%Y-%m-%d"),
                dynamic_finding=True,
                mitigation=mitigation,
                impact=impact,
            )
            if cve_ids and cve_ids is not None:
                finding.unsaved_vulnerability_ids = []
                for cve_id in cve_ids:
                    finding.unsaved_vulnerability_ids.append(cve_id)
            finding.unsaved_endpoints = []
            finding.unsaved_endpoints.append(Endpoint(host=affected_asset.replace("ip/", "").replace("webapp/", "").replace("cert/", "").replace("domain/", "")))
            findings.append(finding)
        return findings
