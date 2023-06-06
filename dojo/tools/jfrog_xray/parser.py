import json
import re

from cvss import CVSS3

from dojo.models import Finding


class JFrogXrayParser(object):
    """jfrog_xray_scan JSON reports"""

    def get_scan_types(self):
        return ["JFrog Xray"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Xray findings in JSON format."

    def get_findings(self, json_output, test):
        tree = json.load(json_output)
        return self.get_items(tree, test)
        

    def get_items(self, tree, test):
        items = {}
        data = tree[0]
        if 'vulnerabilities' in data:
            vulnerability_tree = data['vulnerabilities']

            for node in vulnerability_tree:

                item = get_item(node, test)

                title_cve = "No CVE"
                if 'cves' in data:
                    if 'cve' in data["cves"][0]:
                        title_cve = data["cve"]

                unique_key = node.get("issue_id", "") + node.get("summary", "") + \
                    title_cve
                items[unique_key] = item

        return list(items.values())


def decode_cwe_number(value):
    match = re.match(r"CWE-\d+", value, re.IGNORECASE)
    if match is None:
        return 0
    return int(match[0].rsplit('-')[1])


def get_servery(vulnerability):
    if 'severity' in vulnerability:
        if vulnerability['severity'] == 'Unknown':
            severity = "Info"
        else:
            severity = vulnerability['severity'].title()
    else:
        severity = "Info"
    return severity


def get_references(vulnerability):
    ref = ""
    if "references" in vulnerability:
        references = vulnerability["references"]
        for reference in references:
            ref += reference + "\n"
    return ref


def get_remediation(extended_information):
    remediation = ""
    if "remediation" in extended_information:
        remediation = "\n**Remediation**\n"
        remediation += extended_information["remediation"] + "\n"
    return remediation
       
        
def get_severity_justification(vulnerability):
    severity_desc = ""
    remediation = ""
    extended_information = vulnerability.get("extended_information")
    if extended_information:
        remediation += get_remediation(extended_information)
        if "short_description" in extended_information:
            severity_desc = "**short description**\n"
            severity_desc += extended_information["short_description"] + "\n"
            severity_desc = "**full description**\n"
            severity_desc += extended_information["full_description"] + "\n"
            severity_desc = "**jfrog research severity**\n"
            severity_desc += extended_information["jfrog_research_severity"] + "\n"
            if "jfrog_research_severity_reasons" in extended_information:
                severity_desc = "**jfrog research severity reasons**\n"
                for item in extended_information["jfrog_research_severity_reasons"]:
                    severity_desc += item["name"] + "\n" if item.get("name") else ""
                    severity_desc += item["description"] + "\n" if item.get("description") else ""
    return severity_desc, remediation 

def get_component(vulnerability):
    mitigation = ""
    gav = ""
    impact = "**Impact paths**\n"
    if "components" in vulnerability:
        components = vulnerability["components"]
        gav = next(iter(components))
        print("***key***", gav)
        component = components[gav]
        fixed_versions = component.get("fixed_versions")
        if fixed_versions:
            mitigation = "**Versions containing a fix:**\n"
            mitigation = mitigation + "\n".join(fixed_versions)
        if "impact_paths" in component:
            impact_paths = component["impact_paths"][0]
            for item in impact_paths:
                if "component_id" in item:
                    component_id = item["component_id"]
                    impact = impact + "\n" + component_id
                if "full_path" in item:
                    full_path = item["full_path"]
                    impact = impact + "\n" + full_path
        return gav, mitigation, impact


def get_version_vulnerability(vulnerability):
    if 'vulnerable_versions' in vulnerability['component_versions']:
        extra_desc = "\n**Versions that are vulnerable:**\n"
        extra_desc += "\n".join(vulnerability['component_versions']['vulnerable_versions'])
        return extra_desc
    return "None"
 

def get_provider(vulnerabiity):
    if "component_versions" in vulnerabiity:
        provider = vulnerabiity.get('component_versions').get('more_details').get('provider')
        if provider:
            provider += f"\n**Provider:** {provider}"
            return provider
    return ""


def get_etx(vulnerability):
    if "EXT" in vulnerability:
        return vulnerability["EXT"]
    return ""


def get_cve(vulnerability):
    if "cves" in vulnerability:
        cves = vulnerability["cves"]
        return cves
    return []


def get_item(vulnerability, test):
    severity_justification, remediation = get_severity_justification(vulnerability)
    severity = get_servery(vulnerability)
    references = get_references(vulnerability)
    vulnerability_ids = list()
    cwe = None
    cvssv3 = None
    cvss_v3 = "No CVSS v3 score."
    extra_desc = ""
    # Some entries have no CVE entries, despite they exist. Example CVE-2017-1000502.
    cves = get_cve(vulnerability)
    if len(cves) > 0:
        for item in cves:
            if item.get('cve'):
                vulnerability_ids.append(item.get('cve'))
        # take only the first one for now, limitation of DD model.
        if len(cves[0].get('cwe', [])) > 0:
            cwe = decode_cwe_number(cves[0].get('cwe', [])[0])
        if 'cvss_v3' in cves[0]:
            cvss_v3 = cves[0]['cvss_v3']
            # this dedicated package will clean the vector
            cvssv3 = CVSS3.from_rh_vector(cvss_v3).clean_vector()

    extra_desc += get_provider(vulnerability)
    component_name, mitigation, impact = get_component(vulnerability)
    component_version = get_etx(vulnerability)

    # The 'id' field is empty? (at least in my sample file)
    if vulnerability_ids:
        if vulnerability.get("id"):
            title = vulnerability['id'] + " - " + str(vulnerability_ids[0]) + " - " + component_name + ":" + component_version
        else:
            title = str(vulnerability_ids[0]) + " - " + component_name + ":" + component_version
    else:
        if vulnerability.get("id"):
            title = vulnerability['id'] + " - " + component_name + ":" + component_version
        else:
            title = "No CVE - " + component_name + ":" + component_version

    # create the finding object
    finding = Finding(
        title=title,
        cwe=cwe,
        test=test,
        severity_justification=severity_justification,
        severity=severity,
        description=(vulnerability['summary'] + extra_desc).strip(),
        mitigation=mitigation + remediation,
        component_name=component_name,
        component_version=component_version,
        impact=impact,
        references=references,
        file_path=vulnerability.get('source_comp_id'),
        static_finding=True,
        dynamic_finding=False,
        cvssv3=cvssv3)
    if vulnerability_ids:
        finding.unsaved_vulnerability_ids = vulnerability_ids
    return finding
