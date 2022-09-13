import json
import re

from cvss import CVSS3

from dojo.models import Finding


class JFrogXrayApiSummaryArtifactParser(object):

    # This function return a list of all the scan_type supported by your parser. This identifiers are used internally. Your parser can support more than one scan_type
    # For example some parsers use different identifier to modify the behavior of the parser (aggregate, filter, etc…)
    def get_scan_types(self):
        return ["JFrog Xray API Summary Artifact Scan"]

    # This function return a string used to provide some text in the UI (short label)
    def get_label_for_scan_types(self, scan_type):
        return scan_type

    # This function return a string used to provide some text in the UI (long description)
    def get_description_for_scan_types(self, scan_type):
        return "Import Xray findings in JSON format from the JFrog Xray API Summary/Artifact JSON response"

    # This function return a list of findings
    def get_findings(self, json_output, test):
        tree = json.load(json_output)
        return self.get_items(tree, test)

    def get_items(self, tree, test):
        items = []
        if 'artifacts' in tree:
            artifact_tree = tree['artifacts']
            for artifactNode in artifact_tree:
                artifact_general = artifactNode['general']
                artifact_issues = artifactNode['issues']
                for node in artifact_issues:
                    service = decode_service(artifact_general['name'])
                    item = get_item(node, str(service), test)
                    items.append(item)

        return items


# Retrieve the findings
def get_item(vulnerability, service, test):
    cve = None
    cwe = None
    cvssv3 = None
    cvssv3_score = 0.0
    unique_id_from_tool = None
    impact_paths = None
    impact_path = ImpactPath("", "", "")

    if 'severity' in vulnerability:
        if vulnerability['severity'] == 'Unknown':
            severity = "Informational"
        else:
            severity = vulnerability['severity'].title()
    else:
        severity = "Informational"

    # Some entries have no CVE entries, despite they exist. Example CVE-2017-1000502.
    cves = vulnerability.get('cves', [])
    vulnerability_ids = list()
    if cves:
        for item in cves:
            if 'cve' in item:
                vulnerability_ids.append(item['cve'])
        if len(cves[0].get('cwe', [])) > 0:
            cwe = decode_cwe_number(cves[0].get('cwe', [])[0])
        if 'cvss_v3' in cves[0]:
            cvss_v3 = cves[0]['cvss_v3']
            cvssv3 = CVSS3.from_rh_vector(cvss_v3).clean_vector()

    impact_paths = vulnerability.get('impact_path', [])
    if len(impact_paths) > 0:
        impact_path = decode_impact_path(impact_paths[0])

    # The unique_id_from_tool is set only when a given component (SHA) has a specific unique Finding (XRAY or CVE)
    if 'issue_id' in vulnerability:
        title = vulnerability['issue_id'] + " - " + impact_path.name + ":" + impact_path.version
        unique_id_from_tool = vulnerability['issue_id'] + " " + impact_path.sha
    elif vulnerability_ids:
        title = str(vulnerability_ids[0]) + " - " + impact_path.name + ":" + impact_path.version
        unique_id_from_tool = str(vulnerability_ids[0]) + " " + impact_path.sha
    else:
        title = impact_path.name + ":" + impact_path.version
        unique_id_from_tool = None

    finding = Finding(
        service=service,
        title=title,
        cwe=cwe,
        cvssv3=cvssv3,
        severity=severity,
        description=vulnerability['description'],
        test=test,
        file_path=impact_paths[0],
        component_name=impact_path.name,
        component_version=impact_path.version,
        static_finding=True,
        dynamic_finding=False,
        unique_id_from_tool=unique_id_from_tool
    )
    if vulnerability_ids:
        finding.unsaved_vulnerability_ids = vulnerability_ids

    return finding


# Regex helpers

def decode_service(name):
    match = re.match(r".*/(.*):", name, re.IGNORECASE)
    if match is None:
        return ''
    return match[1]


def decode_cwe_number(value):
    match = re.match(r"CWE-\d+", value, re.IGNORECASE)
    if match is None:
        return 0
    return int(match[0].rsplit('-')[1])


def decode_impact_path(path):
    impactPath = ImpactPath("", "", "")

    match = re.match(r".*\/(.*)$", str(path), re.IGNORECASE)
    if match is None:
        return impactPath
    fullname = match[1]

    match = re.match(r".*sha256__(.*).tar", path, re.IGNORECASE)
    if match:
        impactPath.sha = (match[1][:64]) if len(match[1]) > 64 else match[1]

    if fullname.__contains__(".jar"):
        match = re.match(r"(.*)-", fullname, re.IGNORECASE)
        if match:
            impactPath.name = match[1]
        match = re.match(r".*-(.*).jar", fullname, re.IGNORECASE)
        if match:
            impactPath.version = match[1]
    elif fullname.__contains__(":"):
        match = re.match(r"(.*):", fullname, re.IGNORECASE)
        if match:
            impactPath.name = match[1]
        match = re.match(r".*:(.*)", fullname, re.IGNORECASE)
        if match:
            impactPath.version = match[1]
    elif fullname.__contains__(".js"):
        match = re.match(r"(.*)-", fullname, re.IGNORECASE)
        if match:
            impactPath.name = match[1]
        match = re.match(r".*-(.*).js", fullname, re.IGNORECASE)
        if match:
            impactPath.version = match[1]
    else:
        impactPath.name = fullname

    return impactPath


class ImpactPath:
    def __init__(self, sha, name, version):
        self.sha = sha
        self.name = name
        self.version = version
