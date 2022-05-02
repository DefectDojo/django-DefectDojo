import json

from dojo.models import Finding


class AquaParser(object):

    def get_scan_types(self):
        return ["Aqua Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Aqua Scan"

    def get_description_for_scan_types(self, scan_type):
        return ""

    def get_findings(self, json_output, test):
        tree = json.load(json_output)
        return self.get_items(tree, test)

    def get_items(self, tree, test):
        items = {}
        if 'resources' in tree:
            vulnerabilityTree = tree['resources']

            for node in vulnerabilityTree:
                resource = node.get('resource')
                vulnerabilities = node.get('vulnerabilities')

                for vuln in vulnerabilities:
                    item = get_item(resource, vuln, test)
                    unique_key = resource.get('cpe') + vuln.get('name', 'None')
                    items[unique_key] = item
        elif 'cves' in tree:
            for cve in tree['cves']:
                unique_key = cve.get('file') + cve.get('name')
                items[unique_key] = get_item_v2(cve, test)

        return list(items.values())


def get_item(resource, vuln, test):
    resource_name = resource.get('name', resource.get('path'))
    resource_version = resource.get('version', 'No version')
    vulnerability_id = vuln.get('name', 'No CVE')
    fix_version = vuln.get('fix_version', 'None')
    description = vuln.get('description', 'No description.')
    cvssv3 = None

    url = ""
    if 'nvd_url' in vuln:
        url += "\n{}".format(vuln.get('nvd_url'))
    if 'vendor_url' in vuln:
        url += "\n{}".format(vuln.get('vendor_url'))

    # Take in order of preference (most prio at the bottom of ifs), and put everything in severity justification anyways.
    score = 0
    severity_justification = ""
    used_for_classification = ""
    if 'aqua_severity' in vuln:
        score = vuln.get('aqua_severity')
        severity = aqua_severity_of(score)
        used_for_classification = "Aqua security score ({}) used for classification.\n".format(score)
        severity_justification = vuln.get('aqua_severity_classification')
        if 'nvd_score_v3' in vuln:
            cvssv3 = vuln.get('nvd_vectors_v3')
    else:
        if 'aqua_score' in vuln:
            score = vuln.get('aqua_score')
            used_for_classification = "Aqua score ({}) used for classification.\n".format(score)
        elif 'vendor_score' in vuln:
            score = vuln.get('vendor_score')
            used_for_classification = "Vendor score ({}) used for classification.\n".format(score)
        elif 'nvd_score_v3' in vuln:
            score = vuln.get('nvd_score_v3')
            used_for_classification = "NVD score v3 ({}) used for classification.\n".format(score)
            severity_justification += "\nNVD v3 vectors: {}".format(vuln.get('nvd_vectors_v3'))
            # Add the CVSS3 to Finding
            cvssv3 = vuln.get('nvd_vectors_v3')
        elif 'nvd_score' in vuln:
            score = vuln.get('nvd_score')
            used_for_classification = "NVD score v2 ({}) used for classification.\n".format(score)
            severity_justification += "\nNVD v2 vectors: {}".format(vuln.get('nvd_vectors'))
        severity = severity_of(score)
        severity_justification += "\n{}".format(used_for_classification)

    finding = Finding(
        title=vulnerability_id + " - " + resource_name + " (" + resource_version + ") ",
        test=test,
        severity=severity,
        severity_justification=severity_justification,
        cwe=0,
        cvssv3=cvssv3,
        description=description.strip(),
        mitigation=fix_version,
        references=url,
        component_name=resource.get('name'),
        component_version=resource.get('version'),
        impact=severity)
    if vulnerability_id != 'No CVE':
        finding.unsaved_vulnerability_ids = [vulnerability_id]

    return finding


def get_item_v2(item, test):
    vulnerability_id = item['name']
    file_path = item['file']
    url = item.get('url')
    severity = severity_of(float(item['score']))
    description = item.get('description')
    solution = item.get('solution')
    fix_version = item.get('fix_version')
    if solution:
        mitigation = solution
    elif fix_version:
        mitigation = ('Upgrade to ' + str(fix_version))
    else:
        mitigation = 'No known mitigation'

    finding = Finding(title=str(vulnerability_id) + ': ' + str(file_path),
                   description=description,
                   url=url,
                   cwe=0,
                   test=test,
                   severity=severity,
                   impact=severity,
                   mitigation=mitigation)
    finding.unsaved_vulnerability_ids = [vulnerability_id]

    return finding


def aqua_severity_of(score):
    if score == 'high':
        return "High"
    if score == 'medium':
        return "Medium"
    elif score == 'low':
        return "Low"
    elif score == "negligible":
        return "Info"
    else:
        return "Critical"


def severity_of(score):
    if score == 0:
        return "Info"
    elif score < 4:
        return "Low"
    elif 4.0 < score < 7.0:
        return "Medium"
    elif 7.0 < score < 9.0:
        return "High"
    else:
        return "Critical"
