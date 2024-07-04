import json
import re

from cvss import CVSS3

from dojo.models import Finding


class JFrogXrayOnDemandBinaryScanParser:
    """jfrog_xray_scan JSON reports"""

    def get_scan_types(self):
        return ["JFrog Xray On Demand Binary Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Xray findings in JSON format."

    def get_findings(self, json_output, test):
        tree = json.load(json_output)
        return self.get_items(tree)

    def get_items(self, tree):
        items = {}
        for data in tree:
            if "vulnerabilities" in data:
                vulnerability_tree = data["vulnerabilities"]

                for node in vulnerability_tree:
                    item_set = get_item_set(node)

                    for item in item_set:
                        unique_key = item.title + item.component_name + item.component_version
                        items[unique_key] = item

        return list(items.values())


def get_component_name_version(name):
    match = re.match(r"([a-z]+://[a-z\d\.:]+):([a-z\d\.\-]+)", name, re.IGNORECASE)
    if match is None:
        return name, ""
    return match[1], match[2]


def get_severity(vulnerability):
    if "severity" in vulnerability:
        if vulnerability["severity"] == "Unknown":
            severity = "Info"
        else:
            severity = vulnerability["severity"].title()
    else:
        severity = "Info"
    return severity


def get_references(vulnerability):
    if "references" in vulnerability:
        ref = ""
        references = vulnerability["references"]
        for reference in references:
            if reference[:2] == "- ":
                ref += reference + "\n"
            else:
                ref += "- " + reference + "\n"
        return ref
    return None


def get_remediation(extended_information):
    remediation = ""
    if "remediation" in extended_information:
        remediation = "\n\n**Remediation**\n"
        remediation += extended_information["remediation"] + "\n"
    return remediation


def get_severity_justification(vulnerability):
    severity_desc = ""
    remediation = ""
    extended_information = vulnerability.get("extended_information")
    if extended_information:
        remediation += get_remediation(extended_information)
        if "short_description" in extended_information:
            severity_desc += "**Short description**\n"
            severity_desc += extended_information["short_description"] + "\n"
        if "full_description" in extended_information:
            severity_desc += "**Full description**\n"
            severity_desc += extended_information["full_description"] + "\n"
        if "jfrog_research_severity" in extended_information:
            severity_desc += "**JFrog research severity**\n"
            severity_desc += extended_information["jfrog_research_severity"] + "\n"
        if "jfrog_research_severity_reasons" in extended_information:
            severity_desc += "**JFrog research severity reasons**\n"
            for item in extended_information["jfrog_research_severity_reasons"]:
                severity_desc += item["name"] + "\n" if item.get("name") else ""
                severity_desc += item["description"] + "\n" if item.get("description") else ""
                severity_desc += "_Is positive:_ " + str(item["is_positive"]).lower() + "\n" if item.get("is_positive") else ""
    return severity_desc, remediation


def process_component(component):
    mitigation = ""
    impact = "**Impact paths**\n\n- "
    fixed_versions = component.get("fixed_versions")
    if fixed_versions:
        mitigation = "**Versions containing a fix:**\n\n- "
        mitigation = mitigation + "\n- ".join(fixed_versions)
    if "impact_paths" in component:
        refs = []
        impact_paths_l1 = component["impact_paths"]
        for impact_paths_l2 in impact_paths_l1:
            for item in impact_paths_l2:
                if "component_id" in item:
                    refs.append(item["component_id"])
                if "full_path" in item:
                    refs.append(item["full_path"])
        if refs:
            impact += "\n- ".join(sorted(set(refs)))  # deduplication
    return mitigation, impact


def get_cve(vulnerability):
    if "cves" in vulnerability:
        return vulnerability["cves"]
    return []


def get_vuln_id_from_tool(vulnerability):
    if "issue_id" in vulnerability:
        return vulnerability["issue_id"]
    return None


def clean_title(title):
    if title.startswith("Issue summary: "):
        title = title[len("Issue summary: "):]
    if "\n" in title:
        title = title[:title.index("\n")]
    return title


def get_item_set(vulnerability):
    item_set = []
    severity_justification, remediation = get_severity_justification(vulnerability)
    severity = get_severity(vulnerability)
    references = get_references(vulnerability)
    vuln_id_from_tool = get_vuln_id_from_tool(vulnerability)
    vulnerability_ids = []
    cvssv3 = None
    cvss_v3 = "No CVSS v3 score."
    # Some entries have no CVE entries, despite they exist. Example CVE-2017-1000502.
    cves = get_cve(vulnerability)
    if len(cves) > 0:
        vulnerability_ids = [item.get("cve") for item in cves if item.get("cve")]
        if "cvss_v3_vector" in cves[0]:
            cvss_v3 = cves[0]["cvss_v3_vector"]
            cvssv3 = CVSS3(cvss_v3).clean_vector()

    for component_name, component in vulnerability.get("components", {}).items():
        component_name, component_version = get_component_name_version(component_name)
        mitigation, impact = process_component(component)

        title = clean_title(vulnerability["summary"])
        # create the finding object
        finding = Finding(
            title=title,
            severity_justification=severity_justification or None,
            severity=severity,
            description=(vulnerability["summary"]).strip(),
            mitigation=(mitigation + remediation) or None,
            component_name=component_name,
            component_version=component_version,
            impact=impact or None,
            references=references or None,
            static_finding=True,
            dynamic_finding=False,
            cvssv3=cvssv3,
            vuln_id_from_tool=vuln_id_from_tool,
        )
        if vulnerability_ids:
            finding.unsaved_vulnerability_ids = vulnerability_ids
        item_set.append(finding)
    return item_set
