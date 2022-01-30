import json
import re

from cvss import CVSS3

from dojo.models import Finding

class JFrogXrayApiSummaryArtifactParser(object):
    
    # This function return a list of all the scan_type supported by your parser. This identifiers are used internally. Your parser can support more than one scan_type. 
    # For example some parsers use different identifier to modify the behavior of the parser (aggregate, filter, etc…)
    def get_scan_types(self):
        return ["JFrog Xray API Summary Artifact Scan"]

    # This function return a string used to provide some text in the UI (short label)
    def get_label_for_scan_types(self, scan_type):
        return scan_type

    # This function return a string used to provide some text in the UI (long description)
    def get_description_for_scan_types(self, scan_type):
        return "Import Xray findings in JSON format. The file structure is in accordance to the responce from the JFrog Xray API Summary/Artifact JSON report (https://www.jfrog.com/confluence/display/JFROG/Xray+REST+API#XrayRESTAPI-ArtifactSummary)"

    # This function return a list of findings
    def get_findings(self, json_output, test):
        tree = json.load(json_output)
        return self.get_items(tree, test)

    def get_items(self, tree, test):
        items = {}
        if 'artifacts' in tree:
            artifactTree = tree['artifacts']

            for artifactNode in artifactTree:

                artifactGeneral = artifactNode['general']
                artifactIssues = artifactNode['issues']               

                for node in artifactIssues:

                    service=decode_service(artifactGeneral['name'])
                    
                    # Get the findings of the current artifact
                    item = get_item(node, service, test) 

                    unique_key = node.get('impact_path')
                    items[unique_key] = item

        return list(items.values())


# Retreive the findings 
def get_item(vulnerability, service, test):
    
    cve = None
    cwe = None
    cvssv3 = None
    cvss_v3 = "No CVSS v3 score."
    unique_id_from_tool = None
    impact_paths = None
    impact_path = None
    component_name = None
    component_version = None
    
    if 'severity' in vulnerability:
        if vulnerability['severity'] == 'Unknown':
            severity = "Informational"
        else:
            severity = vulnerability['severity'].title()
    else:
        severity = "Informational"

    # Some entries have no CVE entries, despite they exist. Example CVE-2017-1000502.
    cves = vulnerability.get('cves', [])
    if len(cves) > 0:
        if 'cve' in cves[0]:
            cve = cves[0]['cve']
        # take only the first one for now, limitation of DD model.
        if len(cves[0].get('cwe', [])) > 0:
            cwe = decode_cwe_number(cves[0].get('cwe', [])[0])
        if 'cvss_v3' in cves[0]:
            cvss_v3 = cves[0]['cvss_v3']
            # this dedicated package will clean the vector
            cvssv3 = CVSS3.from_rh_vector(cvss_v3).clean_vector()
            cvssv3_score = decode_cvssv3_score(cvss_v3)

    impact_paths = vulnerability.get('impact_path', [])
    if len(impact_paths) > 0:
        impact_path  = impact_paths[0]
        component_name = decode_component_name(impact_path)
        component_version = decode_component_version(impact_path)
    
    if vulnerability['issue_id']:
        title = vulnerability['issue_id'] + " - " + str(cve) + " - " + component_name + component_version
    elif cve:
        title = str(cve) + " - " + component_name + ":" + component_version
    else:
        title = "No CVE - " + component_name + ":" + component_version

    unique_id_from_tool = title
    hash_code = decode_hash_code(impact_path)
  
    finding = Finding (
        service = service,
        title = title,
        cwe = cwe,
        cve = cve,
        cvssv3 = cvssv3,
        cvssv3_score = cvssv3_score,
        severity = severity,
        description = vulnerability['description'],
        verified = False,
        test = test,
        hash_code = hash_code,
        file_path = impact_path,
        component_name = component_name,
        component_version = component_version,
        static_finding = True,
        dynamic_finding = False,
        unique_id_from_tool = unique_id_from_tool
        )

    return finding


# Regex helpers

def decode_service(name):
    match = re.match(r"/.*/(.*):", name, re.IGNORECASE)
    if match is None:
        return ''
    return match[0]

def decode_cwe_number(value):
    match = re.match(r"CWE-\d+", value, re.IGNORECASE)
    if match is None:
        return 0
    return int(match[0].rsplit('-')[1])

def decode_component_name(impact_path):
    match = re.match(r"[^/]*(?=[.][a-zA-Z]+$)", impact_path, re.IGNORECASE)
    if match is None:
        return ''
    return match[0].rsplit('-')[0]

def decode_component_version(impact_path):
    match = re.match(r"[^/]*(?=[.][a-zA-Z]+$)", impact_path, re.IGNORECASE)
    if match is None:
        return ''
    return match[0].rsplit('-')[1]

def decode_cvssv3_score(cvss_v3):
    match = re.match(r"^.+?(?=\/)", cvss_v3, re.IGNORECASE)
    if match is None:
        return 0
    return float(match[0])

def decode_hash_code(impact_path):
    match = re.match(r"(?<=sha256__)(.*)(?=cae)", impact_path, re.IGNORECASE)
    if match is None:
        return ''
    return match[0]