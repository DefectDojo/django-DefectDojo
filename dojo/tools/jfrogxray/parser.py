import json
import re

from cvss import CVSS3

from dojo.models import Finding


class JFrogXrayParser(object):
    """JFrog Xray JSON reports"""

    def get_scan_types(self):
        return ["JFrog Xray Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Xray findings in JSON format."

    def get_findings(self, json_output, test):
        tree = json.load(json_output)
        return self.get_items(tree, test)

    def get_items(self, tree, test):
        items = {}
        if 'data' in tree:
            vulnerabilityTree = tree['data']

            for node in vulnerabilityTree:

                item = get_item(node, test)

                title_cve = "No CVE"
                more_details = node.get('component_versions').get('more_details')
                if 'cves' in more_details:
                    if 'cve' in more_details.get('cves')[0]:
                        title_cve = node.get('component_versions').get('more_details').get('cves')[0].get('cve')

                unique_key = node.get('id') + node.get('summary') + node.get('provider') + node.get('source_comp_id') + \
                    title_cve
                items[unique_key] = item

        return list(items.values())


def decode_cwe_number(value):
    match = re.match(r"CWE-\d+", value, re.IGNORECASE)
    if match is None:
        return 0
    return int(match[0].rsplit('-')[1])


def get_item(vulnerability, test):
    # Following the CVSS Scoring per https://nvd.nist.gov/vuln-metrics/cvss
    if 'severity' in vulnerability:
        if vulnerability['severity'] == 'Unknown':
            severity = "Info"
        else:
            severity = vulnerability['severity'].title()
    # TODO: Needs UNKNOWN new status in the model.
    else:
        severity = "Info"

    cve = None
    cwe = None
    cvssv3 = None
    cvss_v3 = "No CVSS v3 score."
    mitigation = None
    extra_desc = ""
    # Some entries have no CVE entries, despite they exist. Example CVE-2017-1000502.
    cves = vulnerability['component_versions']['more_details'].get('cves', [])
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

    if 'fixed_versions' in vulnerability['component_versions']:
        mitigation = "**Versions containing a fix:**\n"
        mitigation = mitigation + "\n".join(vulnerability['component_versions']['fixed_versions'])

    if 'vulnerable_versions' in vulnerability['component_versions']:
        extra_desc = "\n**Versions that are vulnerable:**\n"
        extra_desc += "\n".join(vulnerability['component_versions']['vulnerable_versions'])

    provider = vulnerability.get('component_versions').get('more_details').get('provider')
    if provider:
        extra_desc += f"\n**Provider:** {provider}"

    component_name = vulnerability.get('component')
    component_version = vulnerability.get('source_comp_id')[len(vulnerability.get('source_id', '')) + 1:]

    # The 'id' field is empty? (at least in my sample file)
    if vulnerability['id']:
        title = vulnerability['id'] + " - " + str(cve) + " - " + component_name + component_version
    elif cve:
        title = str(cve) + " - " + component_name + ":" + component_version
    else:
        title = "No CVE - " + component_name + ":" + component_version

    # create the finding object
    finding = Finding(
        title=title,
        cve=cve,
        cwe=cwe,
        test=test,
        severity=severity,
        description=(vulnerability['summary'] + extra_desc).strip(),
        mitigation=mitigation,
        component_name=component_name,
        component_version=component_version,
        file_path=vulnerability.get('source_comp_id'),
        static_finding=True,
        dynamic_finding=False,
        cvssv3=cvssv3)

    return finding
