import json
import re

from cvss import CVSS3

from dojo.models import Finding


class JfrogXrayOnDemandBinaryScanParser(object):
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
                        title_cve = "No CVE"
                        if "cves" in node:
                            if "cve" in node["cves"][0]:
                                title_cve = node["cves"][0]["cve"]

                        unique_key = item.title + node.get("issue_id", "") + node.get("summary", "") + title_cve
                        items[unique_key] = item

        return list(items.values())


def decode_cwe_number(value):
    match = re.match(r"CWE-\d+", value, re.IGNORECASE)
    if match is None:
        return 0
    return int(match[0].rsplit("-")[1])


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
    else:
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
            impact += "\n- ".join(sorted(set(refs)))
    return mitigation, impact


def get_version_vulnerability(vulnerability):
    if "vulnerable_versions" in vulnerability["component_versions"]:
        extra_desc = "\n**Versions that are vulnerable:**\n\n- "
        extra_desc += "\n- ".join(vulnerability["component_versions"]["vulnerable_versions"])
        return extra_desc
    return "None"


def get_provider(vulnerability):
    if "component_versions" in vulnerability:
        provider = vulnerability.get("component_versions").get("more_details").get("provider")
        if provider:
            provider += f"\n**Provider:** {provider}"
            return provider
    return ""


def get_ext(vulnerability):
    if "EXT" in vulnerability:
        return vulnerability["EXT"]
    return ""


def get_cve(vulnerability):
    if "cves" in vulnerability:
        cves = vulnerability["cves"]
        return cves
    return []

def get_vuln_id_from_tool(vulnerability):
    if "issue_id" in vulnerability:
        return vulnerability["issue_id"]
    return None


def get_item_set(vulnerability):
    item_set = []

    severity_justification, remediation = get_severity_justification(vulnerability)
    severity = get_severity(vulnerability)
    references = get_references(vulnerability)
    vuln_id_from_tool = get_vuln_id_from_tool(vulnerability)
    vulnerability_ids = list()
    cwe = None
    cvssv3 = None
    cvss_v3 = "No CVSS v3 score."
    extra_desc = ""
    # Some entries have no CVE entries, despite they exist. Example CVE-2017-1000502.
    cves = get_cve(vulnerability)
    if len(cves) > 0:
        for item in cves:
            if item.get("cve"):
                vulnerability_ids.append(item.get("cve"))
        # take only the first one for now, limitation of DD model.
        if len(cves[0].get("cwe", [])) > 0:
            cwe = decode_cwe_number(cves[0].get("cwe", [])[0])
        if "cvss_v3_vector" in cves[0]:
            cvss_v3 = cves[0]["cvss_v3_vector"]
            # this dedicated package will clean the vector
            cvssv3 = CVSS3(cvss_v3).clean_vector()

    extra_desc += get_provider(vulnerability)
    for component_name, component in vulnerability.get("components", {}).items():
        mitigation, impact = process_component(component)
        component_version = get_ext(vulnerability)

        # The 'id' field is empty? (at least in my sample file)
        if vulnerability_ids:
            if vulnerability.get("id"):
                title = (
                    vulnerability["id"]
                    + " - "
                    + str(vulnerability_ids[0])
                    + " - "
                    + component_name
                    + ":"
                    + component_version
                )
            else:
                title = str(vulnerability_ids[0]) + " - " + component_name + ":" + component_version
        else:
            if vulnerability.get("id"):
                title = vulnerability["id"] + " - " + component_name + ":" + component_version
            else:
                title = "No CVE - " + component_name + ":" + component_version

        # create the finding object
        finding = Finding(
            title=title,
            cwe=cwe,
            severity_justification=severity_justification,
            severity=severity,
            description=(vulnerability["summary"] + extra_desc).strip(),
            mitigation=mitigation + remediation,
            component_name=component_name,
            component_version=component_version,
            impact=impact,
            references=references,
            file_path=vulnerability.get("source_comp_id"),
            static_finding=True,
            dynamic_finding=False,
            cvssv3=cvssv3,
            vuln_id_from_tool=vuln_id_from_tool,
        )
        if vulnerability_ids:
            finding.unsaved_vulnerability_ids = vulnerability_ids
        item_set.append(finding)
    return item_set
