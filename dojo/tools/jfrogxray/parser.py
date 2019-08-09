import json
from dojo.models import Finding


class XrayJSONParser(object):
    def __init__(self, json_output, test):

        tree = self.parse_json(json_output)

        if tree:
            self.items = [data for data in self.get_items(tree, test)]
        else:
            self.items = []

    def parse_json(self, json_output):
        try:
            data = json_output.read()
            try:
                tree = json.loads(str(data, 'utf-8'))
            except:
                tree = json.loads(data)
        except:
            raise Exception("Invalid format")

        return tree

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

    cve = "No CVE on file"
    cwe = 0
    cvss_v3 = "No CVSS v3 score."
    cvss_v2 = "No CVSS v2 score."
    mitigation = "N/A"
    extra_desc = ""
    # Some entries have no CVE entries, despite they exist. Example CVE-2017-1000502.
    if 'cves' in vulnerability['component_versions']['more_details']:
        if 'cve' in vulnerability['component_versions']['more_details']['cves'][0]:
            cve = vulnerability['component_versions']['more_details']['cves'][0]['cve']

        if 'cwe' in vulnerability['component_versions']['more_details']['cves'][0]:
            # take only the first one for now, limitation of DD model.
            cwe = vulnerability['component_versions']['more_details']['cves'][0]['cwe'][0].split('-')[1]

            # some can be "NVD-CWE-noinfo"
            if not type(cwe) is int:
                cwe = 0

        if 'cvss_v3' in vulnerability['component_versions']['more_details']['cves'][0]:
            cvss_v3 = vulnerability['component_versions']['more_details']['cves'][0]['cvss_v3']

        if 'cvss_v2' in vulnerability['component_versions']['more_details']['cves'][0]:
            cvss_v2 = vulnerability['component_versions']['more_details']['cves'][0]['cvss_v2']

    if 'fixed_versions' in vulnerability['component_versions']:
        mitigation = "Versions containing a fix:\n"
        mitigation = mitigation + "</br>".join(vulnerability['component_versions']['fixed_versions'])

    if 'vulnerable_versions' in vulnerability['component_versions']:
        extra_desc = "Versions that are vulnerable:\n\n"
        extra_desc = extra_desc + "</br>".join(vulnerability['component_versions']['vulnerable_versions'])

    # The 'id' field is empty? (at least in my sample file)
    if vulnerability['id']:
        title = vulnerability['id'] + " - " + str(cve) + " - " + vulnerability['component']
    else:
        title = str(cve) + " - " + vulnerability['component']

    # create the finding object
    finding = Finding(
        title=title,
        cve=cve,
        cwe=cwe,
        test=test,
        severity=severity,
        description=(vulnerability['summary'] + "\n\n" + extra_desc).strip(),
        mitigation=mitigation,
        file_path=vulnerability.get('source_comp_id'),
        severity_justification="CVSS v3 base score: {}\nCVSS v2 base score: {}".format(cvss_v3, cvss_v2),
        static_finding=True,
        dynamic_finding=False,
        references=vulnerability.get('component_versions').get('more_details').get('provider'),
        impact=severity)

    return finding
